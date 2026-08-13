package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"reedferry/internal/config"
	"reedferry/internal/jumpserver"
)

// ---------- fake 终端 ----------

// fakeTerm 注入式终端：生产为 *terminal.PTY（需真实 TTY），测试用其替代。
type fakeTerm struct {
	mu       sync.Mutex
	size     [2]int
	onResize func(cols, rows int)
	watchSet chan struct{}
}

func newFakeTerm(cols, rows int) *fakeTerm {
	return &fakeTerm{size: [2]int{cols, rows}, watchSet: make(chan struct{})}
}

func (f *fakeTerm) Size() (int, int) { return f.size[0], f.size[1] }
func (f *fakeTerm) Restore()         {}
func (f *fakeTerm) WatchSize(fn func(int, int)) {
	f.mu.Lock()
	f.onResize = fn
	f.mu.Unlock()
	close(f.watchSet)
}

func (f *fakeTerm) triggerResize(cols, rows int) {
	f.mu.Lock()
	fn := f.onResize
	f.mu.Unlock()
	if fn != nil {
		fn(cols, rows)
	}
}

// gatedReader 等待 gate 关闭后才返回 data（用于模拟对端 RST 后的上行写）。
type gatedReader struct {
	gate <-chan struct{}
	data []byte
}

func (r *gatedReader) Read(p []byte) (int, error) {
	<-r.gate
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// ---------- fake koko ----------

// wsMsg 与 jumpserver.Message 同构，便于 handler 内解构断言。
type wsMsg struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Data string `json:"data"`
}

// readFrame 从 fake koko 侧读取一帧，返回帧类型与原始内容。
func readFrame(t *testing.T, conn *websocket.Conn) (int, []byte) {
	t.Helper()
	typ, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("fake koko read: %v", err)
	}
	return typ, raw
}

// readWS 从 fake koko 侧读取并解构一条 Text JSON 控制帧。
func readWS(t *testing.T, conn *websocket.Conn) wsMsg {
	t.Helper()
	typ, raw := readFrame(t, conn)
	if typ != websocket.TextMessage {
		t.Fatalf("expected Text control frame, got typ=%d raw=%q", typ, raw)
	}
	var m wsMsg
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("fake koko unmarshal %s: %v", raw, err)
	}
	return m
}

// sendConnect 从 fake koko 侧下发 Text JSON 控制帧（CONNECT）。
func sendConnect(t *testing.T, conn *websocket.Conn, id string) {
	t.Helper()
	_ = conn.WriteMessage(websocket.TextMessage,
		[]byte(fmt.Sprintf(`{"type":"CONNECT","id":%q,"data":""}`, id)))
}

// newFakeKoko 构造同时提供资产 API（resolveTarget/建连 token 使用）与 WebSocket 端点的
// fake 服务端：资产树/账号/token 端点返回 JSON，/koko/ 路径升级 WebSocket。
func newFakeKoko(t *testing.T, assets, users string, wsHandler func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/koko/") {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "connection-token"):
				// 建连 token 端点（v3 实测）：校验 CSRF 头（jms_csrftoken）与 Referer 头
				if r.Header.Get("X-CSRFToken") != "jmscsrf" {
					t.Errorf("X-CSRFToken: got %q, want jmscsrf", r.Header.Get("X-CSRFToken"))
				}
				if got := r.Header.Get("Referer"); got != "http://"+r.Host+"/" {
					t.Errorf("Referer: got %q, want http://%s/", got, r.Host)
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"tok-1","value":"tok-val"}`))
			case strings.Contains(r.URL.Path, "children-with-assets"):
				// 资产树端点（v3 实测）：返回 TreeNode 数组
				_, _ = w.Write([]byte(assets))
			case strings.Contains(r.URL.Path, "self/assets/"):
				// 单资产详情端点：permed_accounts
				_, _ = w.Write([]byte(users))
			default:
				_, _ = w.Write([]byte(`[]`))
			}
			return
		}
		// WS 握手：v3 用 ?token={id} 认证（不再用 target_id/system_user_id）
		if got := r.URL.Query().Get("token"); got != "tok-1" {
			t.Errorf("ws token param: got %q, want tok-1", got)
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		wsHandler(conn)
	}))
}

// testCfg 构造指向 fake 服务端的配置，资产含主机 t1，Cookie 含 jms_csrftoken。
func testCfg(host string) *config.Config {
	return &config.Config{Host: host, Cookie: "sessionid=abc; jms_csrftoken=jmscsrf"}
}

const (
	// 资产树根节点返回：资产叶子 t1（v3 结构：meta.type=asset，name=主机名，title=IP）
	fakeAssets = `[{"id":"a1","name":"t1","title":"203.0.113.1","pId":"","meta":{"type":"asset","data":{"address":"203.0.113.1"}}}]`
	fakeUsers  = `{"permed_accounts":[{"id":"u1","name":"root-acc","username":"root"}]}`
)

// U4: 握手后回 CONNECT（Text 控制帧）→ 客户端应回 TERMINAL_INIT（Text JSON）且尺寸正确；
// U5: 上行输入为 Binary 裸字节、回显经 Binary 裸字节下发 → 本地 Output 收到原文
func TestRunInitAndEcho(t *testing.T) {
	var gotInit wsMsg
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "sess-9")
		gotInit = readWS(t, conn) // TERMINAL_INIT（Text JSON）
		// 客户端上行输入 "hi" → Binary 裸字节帧（v3 纯透传）
		typ, raw := readFrame(t, conn)
		if typ != websocket.BinaryMessage || string(raw) != "hi" {
			t.Errorf("uplink: typ=%d raw=%q, want Binary \"hi\"", typ, raw)
		}
		// 回显：Binary 裸字节（v3：终端输出原样下发）
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("hi"))
		// 远端退出
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	})
	defer srv.Close()

	var out bytes.Buffer
	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{
		Input:  strings.NewReader("hi"),
		Output: &out,
		Term:   newFakeTerm(80, 24),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotInit.Type != jumpserver.MsgTerminalInit {
		t.Errorf("INIT type: got %q", gotInit.Type)
	}
	if gotInit.ID != "sess-9" {
		t.Errorf("INIT id: got %q want sess-9", gotInit.ID)
	}
	if gotInit.Data != `{"cols":80,"rows":24}` {
		t.Errorf("INIT data: got %q", gotInit.Data)
	}
	if out.String() != "hi" {
		t.Errorf("echo: got %q want %q", out.String(), "hi")
	}
}

// U6: 窗口尺寸变化 → TERMINAL_RESIZE（Text JSON）且 cols/rows 正确
func TestRunResize(t *testing.T) {
	var gotResize wsMsg
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn)             // TERMINAL_INIT
		gotResize = readWS(t, conn) // TERMINAL_RESIZE
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	})
	defer srv.Close()

	ft := newFakeTerm(80, 24)
	go func() {
		<-ft.watchSet // 等 Run 注册 WatchSize
		ft.triggerResize(200, 50)
	}()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{
		Input: strings.NewReader(""),
		Term:  ft,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotResize.Type != jumpserver.MsgTerminalResize {
		t.Errorf("resize type: got %q", gotResize.Type)
	}
	if gotResize.Data != `{"cols":200,"rows":50}` {
		t.Errorf("resize data: got %q", gotResize.Data)
	}
}

// U7: 心跳——静默期间每 interval 收到应用层 PING（Text JSON 控制帧，测试缩短间隔）
func TestRunHeartbeat(t *testing.T) {
	pingCount := make(chan int, 1)
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn) // INIT
		n := 0
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			typ, raw, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if typ != websocket.TextMessage {
				continue
			}
			var m wsMsg
			_ = json.Unmarshal(raw, &m)
			if m.Type == jumpserver.MsgPing && m.Data == "" {
				n++
				if n >= 2 {
					pingCount <- n
					_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
					break
				}
			}
		}
	})
	defer srv.Close()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{
		Input:             strings.NewReader(""),
		Term:              newFakeTerm(80, 24),
		HeartbeatInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := <-pingCount; n < 2 {
		t.Errorf("ping count: got %d want >=2", n)
	}
}

// U8: 远端退出（WebSocket 关闭帧）→ Run 正常返回 nil
func TestRunRemoteExit(t *testing.T) {
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn) // INIT
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	})
	defer srv.Close()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{Input: strings.NewReader(""), Term: newFakeTerm(80, 24)})
	if err != nil {
		t.Fatalf("remote exit: want nil, got %v", err)
	}
}

// 远端退出（v3 实测：exit 后 koko 发 Text JSON CLOSE 消息而非 WebSocket 关闭帧）→ Run 正常返回 nil
func TestRunRemoteCloseMessage(t *testing.T) {
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn) // INIT
		// Text JSON CLOSE 控制消息（会话结束信号）
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"id":"s-1","type":"CLOSE","data":"","msg":"logout"}`))
	})
	defer srv.Close()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{Input: strings.NewReader(""), Term: newFakeTerm(80, 24)})
	if err != nil {
		t.Fatalf("remote close message: want nil, got %v", err)
	}
}

// TERMINAL_SESSION 控制消息（CONNECT 后收到）应被忽略，会话继续直到正常退出
func TestRunTerminalSessionIgnored(t *testing.T) {
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn) // INIT
		// TERMINAL_SESSION 会话信息消息（忽略，不影响会话）
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"id":"s-1","type":"TERMINAL_SESSION","data":""}`))
		// 随后正常关闭
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	})
	defer srv.Close()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{Input: strings.NewReader(""), Term: newFakeTerm(80, 24)})
	if err != nil {
		t.Fatalf("TERMINAL_SESSION should be ignored, got %v", err)
	}
}

// U9: 异常断开（对端直接断开 TCP）→ Run 返回非 nil 错误
func TestRunUnexpectedClose(t *testing.T) {
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn)  // INIT
		_ = conn.Close() // 直接断开，无关闭帧
	})
	defer srv.Close()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{Input: strings.NewReader(""), Term: newFakeTerm(80, 24)})
	if err == nil {
		t.Fatal("unexpected close: want error, got nil")
	}
}

// 上行写失败（对端 RST）：Run 应快速返回错误，而非阻塞等下行超时（问题 3 回归）
func TestRunUplinkFailure(t *testing.T) {
	rstDone := make(chan struct{})
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn) // INIT
		// 强制 RST 断开底层 TCP，使客户端后续写必然失败
		if tcp, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
			_ = tcp.Close()
		}
		close(rstDone)
	})
	defer srv.Close()

	// 等 RST 生效后才返回输入字节，保证上行写发生在连接已死之后
	input := &gatedReader{gate: rstDone, data: []byte("hi")}
	start := time.Now()
	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{Input: input, Term: newFakeTerm(80, 24)})
	if err == nil {
		t.Fatal("uplink failure: want error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("uplink failure should terminate promptly, took %v", elapsed)
	}
}

// 下行非法 JSON 消息：debug 打印后跳过，会话继续（不 panic）
func TestRunSkipMalformed(t *testing.T) {
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn) // INIT
		// 非法 JSON 文本帧
		_ = conn.WriteMessage(websocket.TextMessage, []byte("not json{"))
		// 正常关闭帧
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	})
	defer srv.Close()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{Input: strings.NewReader(""), Term: newFakeTerm(80, 24)})
	if err != nil {
		t.Fatalf("malformed message should be skipped, got %v", err)
	}
}

// blockReader 模拟阻塞的本地输入：Read 返回 "hi" 后等待 gate 关闭再返回；
// 记录 Read 调用次数，用于验证会话结束后上行 goroutine 是否仍在读输入。
type blockReader struct {
	mu    sync.Mutex
	reads int
	gate  chan struct{} // 关闭后 Read 立即返回数据
}

func (r *blockReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	r.reads++
	r.mu.Unlock()
	<-r.gate
	n := copy(p, []byte("hi"))
	return n, nil
}

func (r *blockReader) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads
}

// 回归（CLOSE 后回 REPL 首次输入被吞的 bug）：会话结束后上行 goroutine
// 必须退出（连接已关闭 → WriteData 失败），不再继续读本地输入。
// 修复前：conn 未关闭，WriteData 成功 → goroutine 无限循环 Read；
// 修复后：WriteData 失败退出，Read 次数停在 1。
func TestRunCloseStopsUplink(t *testing.T) {
	in := &blockReader{gate: make(chan struct{})}
	srv := newFakeKoko(t, fakeAssets, fakeUsers, func(conn *websocket.Conn) {
		sendConnect(t, conn, "s-1")
		readWS(t, conn) // INIT
		// Text JSON CLOSE（非 WebSocket 关闭帧）
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"id":"s-1","type":"CLOSE","data":"","msg":"logout"}`))
	})
	defer srv.Close()

	err := Run(context.Background(), testCfg(srv.URL), "t1", Options{Input: in, Term: newFakeTerm(80, 24)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 放行输入：若上行 goroutine 仍在运行，会持续 Read 并 WriteData
	time.Sleep(50 * time.Millisecond)
	close(in.gate)
	time.Sleep(150 * time.Millisecond)
	if n := in.count(); n > 1 {
		t.Errorf("uplink goroutine kept reading stdin after close: %d reads (want 1)", n)
	}
}

// ---------- resolveTarget ----------

// fakeAPI 同时提供资产树与账号两个端点（v3 实测路径）。
func fakeAPI(t *testing.T, assets string, users string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "self/assets/") {
			_, _ = w.Write([]byte(users))
			return
		}
		_, _ = w.Write([]byte(assets))
	}))
}

func TestResolveTargetHostname(t *testing.T) {
	srv := fakeAPI(t,
		`[{"id":"a1","name":"web-01","title":"203.0.113.1","meta":{"type":"asset","data":{}}},{"id":"a2","name":"db-01","title":"203.0.113.2","meta":{"type":"asset","data":{}}}]`,
		`{"permed_accounts":[{"id":"u1","username":"root"}]}`)
	defer srv.Close()
	cfg := &config.Config{Host: srv.URL, Cookie: "c"}

	tid, uid, err := resolveTarget(context.Background(), cfg, "db-01", "")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	if tid != "a2" || uid != "u1" {
		t.Errorf("got tid=%q uid=%q, want a2/u1", tid, uid)
	}
}

// connect 目标按 IP（Address）匹配
func TestResolveTargetByIP(t *testing.T) {
	srv := fakeAPI(t,
		`[{"id":"a1","name":"web-01","title":"203.0.113.1","meta":{"type":"asset","data":{}}},{"id":"a2","name":"db-01","title":"203.0.113.2","meta":{"type":"asset","data":{}}}]`,
		`{"permed_accounts":[{"id":"u1","username":"root"}]}`)
	defer srv.Close()
	cfg := &config.Config{Host: srv.URL, Cookie: "c"}

	tid, uid, err := resolveTarget(context.Background(), cfg, "203.0.113.2", "")
	if err != nil {
		t.Fatalf("resolveTarget by IP: %v", err)
	}
	if tid != "a2" || uid != "u1" {
		t.Errorf("got tid=%q uid=%q, want a2/u1", tid, uid)
	}
}

// 多个资产同名（或同 IP）：取首个（容错）
func TestResolveTargetDuplicateTakesFirst(t *testing.T) {
	srv := fakeAPI(t,
		`[{"id":"a1","name":"dup","title":"203.0.113.1","meta":{"type":"asset","data":{}}},{"id":"a2","name":"dup","title":"203.0.113.2","meta":{"type":"asset","data":{}}}]`,
		`{"permed_accounts":[{"id":"u1","username":"root"}]}`)
	defer srv.Close()
	cfg := &config.Config{Host: srv.URL, Cookie: "c"}

	tid, _, err := resolveTarget(context.Background(), cfg, "dup", "")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	if tid != "a1" {
		t.Errorf("got tid=%q, want a1 (first match)", tid)
	}
}

func TestResolveTargetUUID(t *testing.T) {
	// UUID 直接作为 target_id，不请求资产列表；系统用户显式指定则完全无 API 调用
	cfg := &config.Config{Host: "http://127.0.0.1:1", Cookie: "c"}
	tid, uid, err := resolveTarget(context.Background(), cfg, "11111111-2222-3333-4444-555555555555", "su-9")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	if tid != "11111111-2222-3333-4444-555555555555" || uid != "su-9" {
		t.Errorf("got tid=%q uid=%q", tid, uid)
	}
}

func TestResolveTargetNotFound(t *testing.T) {
	srv := fakeAPI(t, `[]`, `{"permed_accounts":[]}`)
	defer srv.Close()
	cfg := &config.Config{Host: srv.URL, Cookie: "c"}
	_, _, err := resolveTarget(context.Background(), cfg, "ghost", "")
	if err == nil || !strings.Contains(err.Error(), "未找到主机") {
		t.Fatalf("want not-found error, got %v", err)
	}
}

func TestResolveTargetNoSystemUser(t *testing.T) {
	srv := fakeAPI(t, `[{"id":"a1","name":"web-01","meta":{"type":"asset","data":{}}}]`, `{"permed_accounts":[]}`)
	defer srv.Close()
	cfg := &config.Config{Host: srv.URL, Cookie: "c"}
	_, _, err := resolveTarget(context.Background(), cfg, "web-01", "")
	if err == nil || !strings.Contains(err.Error(), "没有可用系统用户") {
		t.Fatalf("want no-system-user error, got %v", err)
	}
}
