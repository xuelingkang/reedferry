// Package authui 提供交互式登录的用户界面：账号/密码/2FA 验证码的终端输入
// 与登录结果提示。
//
// 输入模型：登录输入不直接读 os.Stdin，而是经 REPL 的 stdin 分发通道
// （HiddenReader，与会话模式同一通道语义）读取，避免与命令循环/会话模式
// 竞争抢读（见 repl.loop 输入模型）。回显控制基于 termios ioctl
// （golang.org/x/sys/unix，机制与 golang.org/x/term.ReadPassword 相同）：
// 账号字段开启回显，密码/2FA 验证码字段关闭回显。输入内容仅存于本次调用栈，
// 不打印、不写日志；密码可由用户选择存入配置（0600），2FA 动态验证码任何
// 情况下不落盘（设计文档 7.1）。
package authui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/sys/unix"

	"reedferry/internal/jumpserver"
)

// Credentials 登录凭据（可选预填）：配置了 username/password 时跳过对应
// 交互输入。2FA 动态验证码不在此列（任何情况下不落盘）。
type Credentials struct {
	Username string
	Password string
}

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

// prompt 显示提示后从登录通道读取一行；secret=true 时关闭回显（密码/验证码），
// 否则保持回显（账号）。读取后恢复回显，避免影响 REPL 后续输入。
// Ctrl-D（EOF）经 readLineRaw 返回 io.EOF，由调用方按取消处理。
//
// 回显开关通过 termios ioctl 操作绑定终端 fd（NewHiddenReader 的 fd 参数）。
// fd 非 TTY 时 SetEcho 返回 ErrNotTTY（非交互场景，读取照常进行但回显不受控）；
// 只有非 ErrNotTTY 的回显开关错误（真实终端异常）才终止读取。
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

// ReadCredentials 交互式读取 JumpServer 账号与密码（in 必须为 *HiddenReader，
// 经 REPL 登录分发通道读取）。preset 提供预填凭据（来自配置 username/password）：
// 非空字段跳过对应交互输入（配置凭据失败后重试回退交互输入，见
// repl.interactiveLogin）。非交互终端（fd 非 TTY）返回 ErrNotTTY；
// Ctrl-D（EOF）取消登录。
func ReadCredentials(in io.Reader, out io.Writer, preset Credentials) (username, password string, err error) {
	hr, ok := in.(*HiddenReader)
	if !ok {
		return "", "", ErrNotTTY
	}
	if preset.Username != "" && preset.Password != "" {
		fmt.Fprintln(out, "开始 JumpServer 登录（账号密码已从配置文件读取，仅用于本次换取会话 Cookie；2FA 动态验证码不会保存）")
	} else {
		fmt.Fprintln(out, "开始 JumpServer 登录（账号密码仅用于本次换取会话 Cookie，不会保存）")
	}
	username = preset.Username
	if username == "" {
		username, err = hr.prompt(out, "JumpServer 账号: ", false)
		if err != nil {
			return "", "", err
		}
	}
	if username == "" {
		return "", "", errors.New("账号不能为空")
	}
	password = preset.Password
	if password == "" {
		password, err = hr.prompt(out, "JumpServer 密码: ", true)
		if err != nil {
			return "", "", err
		}
	}
	if password == "" {
		return "", "", errors.New("密码不能为空")
	}
	return username, password, nil
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
