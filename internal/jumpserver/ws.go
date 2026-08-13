package jumpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// koko WebSocket 端点（v3 实测，见设计文档附录 D V3）。
const wsTerminalPath = "/koko/ws/terminal/"

// ErrMalformed 表示收到无法解析的 JSON 文本帧；调用方可选择 debug 打印后跳过
// （设计文档：非法消息跳过不 panic，与参考实现直接 panic 的区别）。
var ErrMalformed = errors.New("malformed ws message")

// readDeadline 是单次读消息的超时兜底：正常链路每 30s 有应用层 PING，
// 超过该时长无任何消息视为断线（防止对端半开时永久阻塞）。
const readDeadline = 5 * time.Minute

// writeDeadline 是单次写消息的超时。
const writeDeadline = 30 * time.Second

// EventKind 区分 WebSocket 事件类型（v3 纯透传协议，附录 D V3）。
type EventKind int

const (
	// EventControl 是 Text 帧（opcode=1）的 JSON 控制消息：CONNECT / TERMINAL_SESSION 等。
	EventControl EventKind = iota
	// EventData 是 Binary 帧（opcode=2）的裸终端字节流：shell 输出原样下发，非 JSON 包裹。
	EventData
)

// Event 是 ReadEvent 的返回值：控制消息或终端字节，二者互斥。
type Event struct {
	Kind EventKind
	Msg  *Message // Kind == EventControl 时有效
	Data []byte   // Kind == EventData 时有效
}

// Conn 封装一条 koko WebSocket 连接。gorilla 的 *websocket.Conn 不支持并发写，
// 所有写操作经内部互斥锁串行化（session 中心跳 goroutine 与透传写并发）。
type Conn struct {
	ws  *websocket.Conn
	wmu sync.Mutex
}

// wsURL 将 https(s)://host[/path] 转换为 koko 终端 WebSocket 地址。
// v3 实测（附录 D V3）：建连用 ?token={connection-token 的 id} 认证，
// 不再使用 target_id + type + system_user_id 参数（旧参数会收到
// ERROR "connect token is nil"）。生产 host 为 https:// → wss://；
// 测试场景 http:// → ws://。
func wsURL(host, tokenID string) (string, error) {
	hu, err := url.Parse(host)
	if err != nil {
		return "", fmt.Errorf("解析 JumpServer 地址失败：%w", err)
	}
	if hu.Host == "" {
		// 裸主机名（如 your-jumpserver.example.com）补全 scheme
		hu, err = url.Parse("https://" + host)
		if err != nil {
			return "", fmt.Errorf("解析 JumpServer 地址失败：%w", err)
		}
	}
	path := wsTerminalPath
	if p := strings.TrimSuffix(hu.Path, "/"); p != "" {
		// host 带 path 前缀（如 https://host/jms/）时保持前缀
		path = p + wsTerminalPath
	}
	scheme := "wss"
	if hu.Scheme == "http" {
		scheme = "ws"
	}
	q := url.Values{}
	q.Set("token", tokenID)
	u := url.URL{Scheme: scheme, Host: hu.Host, Path: path, RawQuery: q.Encode()}
	return u.String(), nil
}

// Connect 建立到 koko 的 WebSocket 连接。
//
// tokenID 来自 CreateConnectToken（v3 实测流程：先建 token 再以 ?token={id}
// 握手）；握手 Header 携带浏览器会话 Cookie（设计文档 6.1.2）；TLS 证书校验
// 保持开启。握手失败按状态码归类：302/401/403 视为会话失效（跳转登录页），
// 404 提示路径问题，网络错误原样返回——均不 panic。
func Connect(ctx context.Context, host, cookie, tokenID string) (*Conn, error) {
	u, err := wsURL(host, tokenID)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set("Cookie", cookie)

	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	conn, resp, err := dialer.DialContext(ctx, u, h)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusFound, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
				// 握手阶段即可判定的会话失效 / 路径问题
				return nil, classifyError(resp.StatusCode)
			}
		}
		return nil, fmt.Errorf("WebSocket 连接失败（网络不可达或服务异常）：%w", err)
	}
	return &Conn{ws: conn}, nil
}

// ReadEvent 读取下一事件（v3 纯透传协议，附录 D V3）：
//   - Text 帧（opcode=1）：JSON 控制消息 → EventControl（CONNECT / TERMINAL_SESSION 等）
//   - Binary 帧（opcode=2）：裸终端字节流 → EventData（shell 输出原样返回，非 JSON 包裹）
//
// 无法解析的 Text 帧返回 ErrMalformed；控制帧（Ping/Pong/Close）由 gorilla
// 自动处理，此处仅兜底跳过其他意外帧类型。
func (c *Conn) ReadEvent(ctx context.Context) (*Event, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		_ = c.ws.SetReadDeadline(time.Now().Add(readDeadline))
		typ, raw, err := c.ws.ReadMessage()
		if err != nil {
			return nil, err
		}
		switch typ {
		case websocket.TextMessage:
			m, err := ParseMessage(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrMalformed, truncate(raw))
			}
			return &Event{Kind: EventControl, Msg: m}, nil
		case websocket.BinaryMessage:
			// 裸字节：拷贝一份，避免依赖 gorilla 的复用缓冲
			data := make([]byte, len(raw))
			copy(data, raw)
			return &Event{Kind: EventData, Data: data}, nil
		default:
			continue // 其他帧类型（正常不会出现）：跳过
		}
	}
}

// WriteControl 发送 Text JSON 控制帧（上行控制消息：TERMINAL_INIT /
// TERMINAL_RESIZE / PING 等）。实测 Text JSON 控制帧有效。
func (c *Conn) WriteControl(m *Message) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeDeadline))
	return c.ws.WriteJSON(m)
}

// WriteData 发送 Binary 裸字节数据帧（本地终端输入 → 远端）。
// v3 实测：上行数据必须用裸字节 Binary 帧，Text JSON 的 hex 编码不生效。
func (c *Conn) WriteData(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeDeadline))
	return c.ws.WriteMessage(websocket.BinaryMessage, b)
}

// Close 优雅关闭：先发关闭帧再关闭底层连接，唤醒阻塞中的读。
func (c *Conn) Close() error {
	c.wmu.Lock()
	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(2*time.Second))
	c.wmu.Unlock()
	return c.ws.Close()
}

// truncate 截断原文便于 debug 输出，避免超长消息刷屏。
func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
