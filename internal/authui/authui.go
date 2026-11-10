// Package authui 提供交互式登录的用户界面：微信扫码二维码渲染、扫码等待、
// 2FA 验证码终端输入与登录结果提示。
//
// 输入模型：登录输入不直接读 os.Stdin，而是经 REPL 的 stdin 分发通道
// （HiddenReader，与会话模式同一通道语义）读取，避免与命令循环/会话模式
// 竞争抢读（见 repl.loop 输入模型）。回显控制基于 termios ioctl
// （golang.org/x/sys/unix，机制与 golang.org/x/term.ReadPassword 相同）：
// 2FA 验证码字段关闭回显，输入内容仅存于本次调用栈，不打印、不写日志、
// 不落盘（设计文档 7.1）。
package authui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"rsc.io/qr"

	"reedferry/internal/jumpserver"
)

// HiddenReader 从 stdin 分发通道（REPL 登录模式的输入通道，见 repl.loop
// 输入模型）逐字节读取登录输入。ECHO 开关需要真实 TTY fd——登录输入
// 由 REPL 分发通道提供，但隐藏回显只能在交互终端完成；fd 非 TTY 或
// termios 操作失败时 SetEcho 返回 ErrNotTTY（调用方按不可交互登录处理）。
type HiddenReader struct {
	ch  <-chan []byte
	buf []byte
	fd  int
}

// NewHiddenReader 构造 HiddenReader：ch 为 REPL 登录分发通道，fd 为真实终端
// 文件描述符（用于 ECHO 开关）。fd 传 -1 时（测试/无 TTY 场景）SetEcho
// 直接返回 ErrNotTTY，但通道读取照常工作。
func NewHiddenReader(ch <-chan []byte, fd int) *HiddenReader {
	return &HiddenReader{ch: ch, fd: fd}
}

// Read 实现 io.Reader：从通道消费字节块（与 repl.chanReader 相同语义，
// 供 readLineRaw 逐字节按行消费）。
func (r *HiddenReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		b, ok := <-r.ch
		if !ok {
			return 0, io.EOF
		}
		r.buf = b
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// SetEcho 打开（on=true）/关闭（on=false）终端 ECHO 位。fd<0 或 fd 非 TTY
// （ioctl 失败）时返回 ErrNotTTY（无法隐藏回显，登录降级为取消提示）。
func (r *HiddenReader) SetEcho(on bool) error {
	if r.fd < 0 {
		return ErrNotTTY
	}
	t, err := unix.IoctlGetTermios(r.fd, ioctlReadTermios)
	if err != nil {
		return ErrNotTTY
	}
	if on {
		t.Lflag |= unix.ECHO
	} else {
		t.Lflag &^= unix.ECHO
	}
	if err := unix.IoctlSetTermios(r.fd, ioctlWriteTermios, t); err != nil {
		return ErrNotTTY
	}
	return nil
}

// prompt 显示提示后从登录通道读取一行；secret=true 时关闭回显（验证码），
// 否则保持回显。读取后恢复回显，避免影响 REPL 后续输入。
// Ctrl-D（EOF）经 readLineRaw 返回 io.EOF，由调用方按取消处理。
func (r *HiddenReader) prompt(out io.Writer, text string, secret bool) (string, error) {
	if err := r.SetEcho(!secret); err != nil && !errors.Is(err, ErrNotTTY) {
		return "", err
	}
	defer func() {
		// 恢复回显；失败忽略（终端已不可用，错误已在上层处理）
		_ = r.SetEcho(true)
	}()
	fmt.Fprint(out, text)
	line, err := readLineRaw(r)
	if secret {
		fmt.Fprintln(out) // 隐藏回显：补齐换行（回显时终端已输出换行）
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// RenderQR 把 content 渲染为终端二维码（半块字符 + 强制黑底白面的 ANSI
// 配色，避免深色终端把二维码反色导致识别不到）。非交互输出（非字符设备）
// 只打印内容 URL，供用户自行在二维码生成器中使用。
func RenderQR(w io.Writer, content string) error {
	if !isCharDevice(w) {
		fmt.Fprintf(w, "登录二维码内容：%s\n", content)
		return nil
	}
	art, err := renderQRCode(content)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, art)
	return err
}

// renderQRCode 生成终端二维码文本（半块字符 + ANSI 黑白配色）。
func renderQRCode(content string) (string, error) {
	code, err := qr.Encode(content, qr.M)
	if err != nil {
		return "", fmt.Errorf("生成二维码失败：%w", err)
	}
	const quiet = 2 // 静区：二维码四周留白，缺了扫不出来
	size := code.Size + quiet*2
	black := func(x, y int) bool {
		return code.Black(x-quiet, y-quiet)
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		b.WriteString("\x1b[30;47m") // 前景黑、背景白
		for x := 0; x < size; x++ {
			top := black(x, y)
			bottom := false
			if y+1 < size {
				bottom = black(x, y+1)
			}
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String(), nil
}

// ScanFlow 是扫码登录流程的最小接口（*jumpserver.LoginFlow 实现），
// 便于将等待逻辑与网络流程分开测试。
type ScanFlow interface {
	QR() *jumpserver.QRCode
	RefreshQR(ctx context.Context) error
	PollScan(ctx context.Context) (jumpserver.ScanStatus, *jumpserver.LoginOutcome, error)
}

// WaitScan 渲染二维码并等待扫码完成：轮询扫码状态、提示进度、支持
// 「r 刷新二维码」「q 取消」。二维码过期时自动刷新（最多 qrRefreshLimit 次）。
// 扫码成功后可能仍返回 NeedMFA（业务侧 2FA），由调用方继续处理。
func WaitScan(ctx context.Context, flow ScanFlow, input <-chan []byte, out io.Writer) (*jumpserver.LoginOutcome, error) {
	const qrRefreshLimit = 3
	qr := flow.QR()
	if qr == nil {
		return nil, errors.New("登录流程未提供二维码")
	}
	if err := RenderQR(out, qr.Content); err != nil {
		return nil, err
	}
	fmt.Fprintln(out, "请用微信扫描上方二维码完成登录（r 刷新二维码，q 取消）")

	lineCh, stop := splitLines(input)
	defer stop()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	scanned := false
	refreshes := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case line, ok := <-lineCh:
			if !ok {
				return nil, ErrCancelled
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "q", "quit", "exit":
				return nil, ErrCancelled
			case "r", "refresh":
				if err := refreshQR(ctx, flow, out); err != nil {
					return nil, err
				}
				scanned = false
			default:
				fmt.Fprintln(out, "等待扫码中：r 刷新二维码，q 取消")
			}
		case <-ticker.C:
			status, outcome, err := flow.PollScan(ctx)
			if err != nil {
				var le *jumpserver.LoginError
				if errors.As(err, &le) && le.Kind == jumpserver.LoginErrQRExpired {
					if refreshes >= qrRefreshLimit {
						return nil, errors.New("二维码多次过期，已取消登录")
					}
					refreshes++
					fmt.Fprintln(out, "二维码已过期，正在刷新…")
					if err := refreshQR(ctx, flow, out); err != nil {
						return nil, err
					}
					scanned = false
					continue
				}
				return nil, err
			}
			if outcome != nil {
				return outcome, nil
			}
			if status == jumpserver.ScanScanned && !scanned {
				scanned = true
				fmt.Fprintln(out, "已扫码，请在微信中确认授权…")
			}
		}
	}
}

// refreshQR 重新拉取二维码内容并重绘。
func refreshQR(ctx context.Context, flow ScanFlow, out io.Writer) error {
	if err := flow.RefreshQR(ctx); err != nil {
		return err
	}
	qr := flow.QR()
	if qr == nil {
		return errors.New("刷新二维码后内容为空")
	}
	if err := RenderQR(out, qr.Content); err != nil {
		return err
	}
	fmt.Fprintln(out, "二维码已刷新，请用微信扫描（r 刷新二维码，q 取消）")
	return nil
}

// pollInterval 扫码状态轮询间隔（与 SSO 前端一致；包级变量便于测试调小）。
var pollInterval = 1500 * time.Millisecond

// splitLines 把 stdin 分发通道的字节块按行拆开，返回行通道与停止函数。
// 停止后读取 goroutine 立即退出，不残留阻塞在通道上的协程。
func splitLines(input <-chan []byte) (<-chan string, func()) {
	lines := make(chan string, 4)
	done := make(chan struct{})
	go func() {
		defer close(lines)
		var sb strings.Builder
		for {
			select {
			case <-done:
				return
			case b, ok := <-input:
				if !ok {
					// 通道关闭：把残留内容当最后一行
					if sb.Len() > 0 {
						select {
						case lines <- sb.String():
						case <-done:
						}
					}
					return
				}
				for _, c := range b {
					if c == '\n' {
						select {
						case lines <- sb.String():
						case <-done:
							return
						}
						sb.Reset()
						continue
					}
					if c != '\r' {
						sb.WriteByte(c)
					}
				}
			}
		}
	}()
	var once bool
	return lines, func() {
		if once {
			return
		}
		once = true
		close(done)
	}
}

// RunMFA 提示用户输入 JumpServer 2FA 动态验证码并提交；验证码错误时提示
// 重新输入（最多 mfaRetry 次），返回登录结果。验证码输入隐藏回显
// （in 必须为 *HiddenReader）。Ctrl-D（EOF）取消登录。
func RunMFA(ctx context.Context, flow *jumpserver.LoginFlow, prompt *jumpserver.MFAPrompt, in io.Reader, out io.Writer) (*jumpserver.LoginOutcome, error) {
	const mfaRetry = 3
	hr, ok := in.(*HiddenReader)
	if !ok {
		return nil, ErrNotTTY
	}
	desc := prompt.Describe()
	for attempt := 0; attempt < mfaRetry; attempt++ {
		if attempt > 0 {
			fmt.Fprintln(out, "验证码错误，请重新输入")
		}
		mfaType := prompt.DefaultType()
		hint := fmt.Sprintf("请输入 JumpServer 2FA 动态验证码（%s）: ", desc)
		code, err := hr.prompt(out, hint, true)
		if err != nil {
			return nil, err
		}
		if code == "" {
			return nil, errors.New("2FA 验证码为空，已取消登录")
		}
		outcome, err := flow.SubmitMFA(ctx, code, mfaType)
		if err == nil {
			return outcome, nil
		}
		var le *jumpserver.LoginError
		if errors.As(err, &le) && le.Kind == jumpserver.LoginErrBadMFA {
			continue // 验证码错误：重新输入
		}
		return nil, err
	}
	return nil, errors.New("2FA 验证码错误次数过多，已取消登录（账号未被锁定，可稍后重试）")
}

// ErrCancelled 表示用户主动取消登录（输入 q 或关闭输入）。
var ErrCancelled = errors.New("已取消登录")

// ErrNotTTY 表示 stdin 不是交互式终端，无法进行隐藏回显输入。
var ErrNotTTY = errors.New("登录需要交互式终端（stdin 不是 TTY）；可在终端中运行 reedferry，或改用浏览器登录后复制 Cookie 到配置文件")

// readLineRaw 读取一行（含 EOF/Ctrl-D 处理：返回 io.EOF 由调用方按取消处理）。
func readLineRaw(in io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			c := buf[0]
			if c == '\n' {
				return sb.String(), nil
			}
			if c == '\r' {
				continue // CR 忽略（LF 终止）
			}
			sb.WriteByte(c)
		}
		if err != nil {
			if err == io.EOF {
				return sb.String(), io.EOF
			}
			return sb.String(), err
		}
	}
}

// isCharDevice 判断输出是否为字符设备（终端）：非终端不写 ANSI 转义序列。
func isCharDevice(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
