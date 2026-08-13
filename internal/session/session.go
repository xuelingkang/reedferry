// Package session 编排 terminal 与 jumpserver 两条数据通路：建立 WebSocket、
// 本地终端 raw mode、双向透传、30s 心跳、SIGWINCH resize 与退出/断线收敛。
//
// 与参考实现 karin0/jumpserver-proxy 的本质区别（设计文档 5.2.4）：Reedferry
// 为纯终端透传——不执行远端程序、不做 smux、不过滤任何字符，所有字节原样
// 双向搬运，由本地终端负责渲染。
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"reedferry/internal/config"
	"reedferry/internal/jumpserver"
	"reedferry/internal/terminal"
)

const (
	// defaultHeartbeatInterval 应用层 PING 间隔（防 nginx 空闲断连，设计文档 6.1.2）。
	defaultHeartbeatInterval = 30 * time.Second
)

// uuidRe 匹配 JumpServer 资产 UUID（8-4-4-4-12）。connect 参数为 UUID 时
// 直接作为 target_id，否则按 hostname 精确匹配。
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Terminal 是 session 依赖的终端抽象，生产实现为 *terminal.PTY，测试注入 fake。
// 本地终端只承担 raw mode 与尺寸来源，不参与数据透传（见 terminal 包注释）。
type Terminal interface {
	Size() (cols, rows int)
	Restore()
	WatchSize(fn func(cols, rows int))
}

// Options 连接选项。
type Options struct {
	Debug             bool          // 打印收发消息（stderr）
	SystemUser        string        // 指定系统用户 ID；空则取资产首个可用系统用户
	Shell             string        // 终端 shell（预留，纯透传模式不启动本地 shell）
	Input             io.Reader     // 本地输入；默认 os.Stdin
	Output            io.Writer     // 本地输出；默认 os.Stdout
	Term              Terminal      // 终端抽象；默认 terminal.Open
	HeartbeatInterval time.Duration // 心跳间隔；<=0 用默认 30s（测试可调短）
}

// Run 建立一次终端会话，阻塞至远端退出、本地退出或异常断开。
//
// 返回 nil 表示正常退出（远端 shell 退出或本地中断）；非 nil 表示异常断开
// （Cookie 过期/网络抖动等），由 CLI 层给出退出码与提示。
func Run(ctx context.Context, cfg *config.Config, target string, opts Options) error {
	// 解析目标（hostname 或 UUID）与系统用户
	targetID, sysUserID, err := resolveTarget(ctx, cfg, target, opts.SystemUser)
	if err != nil {
		return err
	}

	// 本地终端：raw mode（非交互场景下由注入的 Input/Output 接管）
	t := opts.Term
	if t == nil {
		p, err := terminal.Open(opts.Shell)
		if err != nil {
			return err
		}
		defer p.Restore()
		t = p
	}
	input := opts.Input
	if input == nil {
		input = os.Stdin
	}
	output := opts.Output
	if output == nil {
		output = os.Stdout
	}

	// 创建建连 token（v3 实测流程：先 POST connection-token 拿 token，
	// 再以 ?token={id} 建立 WebSocket，见附录 D V3）
	tok, err := jumpserver.CreateConnectToken(ctx, cfg.Host, cfg.Cookie, cfg.CSRF(), targetID, sysUserID)
	if err != nil {
		return err
	}

	// 建立 WebSocket（握手携带 Cookie 与 token，设计文档 6.1.2）
	conn, err := jumpserver.Connect(ctx, cfg.Host, cfg.Cookie, tok.ID)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 等待下行 CONNECT 控制消息（Text JSON 帧），取得会话 id。
	// 循环跳过可能先到的其他控制消息（如 TERMINAL_SESSION）。
	var wsID string
	for {
		ev, err := conn.ReadEvent(ctx)
		if err != nil {
			return fmt.Errorf("等待 CONNECT 失败：%w", err)
		}
		if ev.Kind == jumpserver.EventControl && ev.Msg.Type == jumpserver.MsgConnect {
			wsID = ev.Msg.ID
			break
		}
	}

	// 发送 TERMINAL_INIT（Text JSON 控制帧，v3 实测有效）
	cols, rows := t.Size()
	if err := conn.WriteControl(jumpserver.NewMessage(jumpserver.MsgTerminalInit, wsID, jumpserver.SizeData(cols, rows))); err != nil {
		return fmt.Errorf("发送 TERMINAL_INIT 失败：%w", err)
	}

	// 本地中断（Ctrl-C/SIGTERM）→ 正常退出。注意 raw mode 下 Ctrl-C 会作为
	// 字节上行由远端处理；此处兜底外部 kill 场景。
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx = sigCtx

	// 心跳：每 30s 发应用层 PING（JSON 消息，与协议层 ping/pong 控制帧无关）。
	// 使用独立 hbCtx 以便主循环退出时主动停掉心跳 goroutine（避免依赖外层 ctx）。
	interval := opts.HeartbeatInterval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				if err := conn.WriteControl(jumpserver.NewMessage(jumpserver.MsgPing, wsID, "")); err != nil {
					debugf(opts.Debug, "PING 发送失败：%v", err)
				}
			}
		}
	}()

	// 窗口尺寸变化 → TERMINAL_RESIZE（Text JSON 控制帧）
	t.WatchSize(func(c, r int) {
		if err := conn.WriteControl(jumpserver.NewMessage(jumpserver.MsgTerminalResize, wsID, jumpserver.SizeData(c, r))); err != nil {
			debugf(opts.Debug, "TERMINAL_RESIZE 发送失败：%v", err)
		}
	})

	// 上行通路：本地输入字节 → Binary 裸字节帧（v3 纯透传，不再 hex 编码）。
	// EOF（Ctrl-D）时仅关闭 channel（远端可能仍在输出，会话不结束）；
	// 写失败时上报错误终止会话。
	// done 在 Run 返回（defer）时关闭：上行 goroutine 若阻塞在 input.Read，
	// 下次读返回后立即放弃处理并退出，不再进入下一轮读——避免泄漏的
	// goroutine 继续抢读本地输入（回 REPL 后首次输入被吞的实测 bug 收敛）。
	upDone := make(chan struct{})
	defer close(upDone)
	upErr := make(chan error, 1)
	go func() {
		defer close(upErr)
		buf := make([]byte, 4096)
		for {
			n, err := input.Read(buf)
			select {
			case <-upDone:
				return // 会话已结束：放弃本次读到的内容
			default:
			}
			if n > 0 {
				if werr := conn.WriteData(buf[:n]); werr != nil {
					upErr <- fmt.Errorf("上行发送失败：%w", werr)
					return
				}
			}
			if err != nil {
				return // EOF / 读错误：终止上行，会话是否结束由主循环与下行决定
			}
		}
	}()

	// 下行通路 goroutine：ReadEvent 阻塞调用无法直接 select，包一层结果 channel。
	// 事件（控制消息/终端字节）与读错误都经 readCh 通知主循环。
	type wsRead struct {
		ev  *jumpserver.Event
		err error
	}
	readCh := make(chan wsRead, 1)
	go func() {
		defer close(readCh)
		for {
			ev, err := conn.ReadEvent(ctx)
			if err != nil {
				readCh <- wsRead{nil, err}
				if !errors.Is(err, jumpserver.ErrMalformed) {
					return // 致命读错误：退出读 goroutine
				}
				continue // 非法消息：跳过继续读（由主循环 debug 打印）
			}
			readCh <- wsRead{ev, nil}
		}
	}()

	// 主循环：下行 → 终端输出；同时监听上行失败与本地中断，避免
	// 上行断掉后仍阻塞等待下行（原实现 upErr 无人读取，异常场景下
	// 会等到 readDeadline 5min 才退出）。
	//
	// 退出收敛：所有 return 路径统一先 conn.Close()——上行 goroutine 阻塞在
	// input.Read（本地输入）上，连接关闭后其下一次 WriteData 立即失败退出，
	// 避免泄漏的 goroutine 继续读 stdin 抢走 REPL 的输入（CLOSE 后回 REPL
	// 首次输入被吞的实测 bug）。
	for {
		select {
		case r, ok := <-readCh:
			if !ok {
				// 读 goroutine 意外退出（理论上仅通道关闭时）
				hbCancel()
				<-hbDone
				_ = conn.Close()
				return fmt.Errorf("连接已断开（可能 Cookie 过期或网络抖动）：读取通道关闭")
			}
			if r.err != nil {
				switch {
				case errors.Is(r.err, jumpserver.ErrMalformed):
					// 非法消息：debug 打印原文后跳过，不 panic（设计文档异常处理）
					debugf(opts.Debug, "跳过无法解析的消息：%v", r.err)
					continue
				case ctx.Err() != nil:
					// 本地退出（外部中断）
					hbCancel()
					<-hbDone
					_ = conn.Close()
					return nil
				case isNormalClose(r.err):
					// 远端退出（WebSocket 关闭帧）
					hbCancel()
					<-hbDone
					_ = conn.Close()
					return nil
				default:
					hbCancel()
					<-hbDone
					_ = conn.Close()
					return fmt.Errorf("连接已断开（可能 Cookie 过期或网络抖动）：%w", r.err)
				}
			}
			// 事件分流：Binary 裸字节 → 终端输出；Text 控制消息 → 分类处理
			switch r.ev.Kind {
			case jumpserver.EventData:
				if _, werr := output.Write(r.ev.Data); werr != nil {
					hbCancel()
					<-hbDone
					_ = conn.Close()
					return fmt.Errorf("写入终端失败：%w", werr)
				}
			case jumpserver.EventControl:
				if r.ev.Msg.Type == jumpserver.MsgClose {
					// 会话结束信号（实测：exit 后 koko 发 Text JSON CLOSE 消息而非
					// WebSocket 关闭帧，见附录 D V3）：走正常退出路径，并关闭连接
					// 打断上行 goroutine（其不再抢读本地输入，见函数注释）
					hbCancel()
					<-hbDone
					_ = conn.Close()
					return nil
				}
				// 其他控制消息（TERMINAL_SESSION 等）：忽略。注意 TERMINAL_SESSION
				// 只是会话信息展示，与 CONNECT 的会话 id 无关，无需处理。
			}
		case err, ok := <-upErr:
			if !ok {
				// 上行 EOF（正常）：忽略，等待下行；置 nil 使该 case 不再触发
				upErr = nil
				break
			}
			// 上行写失败：立即终止会话，不等下行超时
			hbCancel()
			<-hbDone
			_ = conn.Close()
			return err
		case <-ctx.Done():
			// 本地退出：主动关闭连接以打断读 goroutine
			hbCancel()
			<-hbDone
			_ = conn.Close()
			return nil
		}
	}
}

// resolveTarget 将 connect 参数解析为 target_id 与 system_user_id：
// UUID 直接使用，否则按 hostname 匹配资产；系统用户未指定时取资产首个。
func resolveTarget(ctx context.Context, cfg *config.Config, target, sysUserFlag string) (targetID, sysUserID string, err error) {
	if uuidRe.MatchString(target) {
		targetID = target
	} else {
		targetID, err = findAssetID(ctx, cfg, target)
		if err != nil {
			return "", "", err
		}
	}
	if sysUserFlag != "" {
		return targetID, sysUserFlag, nil
	}
	users, err := jumpserver.ListSystemUsers(ctx, cfg.Host, cfg.Cookie, targetID)
	if err != nil {
		return "", "", err
	}
	if len(users) == 0 {
		return "", "", fmt.Errorf("资产 %s 没有可用系统用户", targetID)
	}
	return targetID, users[0].ID, nil
}

// findAssetID 展开资产树得到扁平资产列表，按 hostname 或 IP（Address）精确匹配
// 返回资产 ID（二选一命中即可）；多个资产同名/IP 时取首个并提示（容错，实际不会发生）。
func findAssetID(ctx context.Context, cfg *config.Config, target string) (string, error) {
	assets, err := jumpserver.ListAssets(ctx, cfg.Host, cfg.Cookie)
	if err != nil {
		return "", err
	}
	firstID := ""
	match := 0
	for _, a := range assets {
		if a.Hostname == target || a.Address == target {
			match++
			if firstID == "" {
				firstID = a.ID
			}
		}
	}
	if firstID == "" {
		return "", fmt.Errorf("未找到主机 %s（可用 `reedferry list` 查看资产）", target)
	}
	if match > 1 {
		fmt.Fprintf(os.Stderr, "提示：%s 匹配到 %d 个资产，已取首个（%s）\n", target, match, firstID)
	}
	return firstID, nil
}

// isNormalClose 判断读错误是否为远端正常关闭（关闭帧/无关闭码直接断开）。
func isNormalClose(err error) bool {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived:
			return true
		}
		return false
	}
	return false
}

// debugf 仅 debug 模式输出到 stderr（不污染终端数据流，设计文档 3.2）。
func debugf(debug bool, format string, args ...any) {
	if debug {
		log.Printf(format, args...)
	}
}
