// Package authui 提供交互式登录的用户界面：账号/密码/2FA 验证码的终端输入
// 与登录结果提示。密码与验证码输入关闭回显（golang.org/x/term.ReadPassword），
// 输入内容仅存于本次调用栈，不打印、不写日志、不落盘（设计文档 7.1）。
package authui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"reedferry/internal/jumpserver"
)

// ReadCredentials 交互式读取 JumpServer 账号与密码（密码隐藏回显）。
// 非交互终端（stdin 非 TTY）时返回 ErrNotTTY；Ctrl-D（EOF）取消登录。
func ReadCredentials(in io.Reader, out io.Writer) (username, password string, err error) {
	if !isTerminal(in) {
		return "", "", ErrNotTTY
	}
	fmt.Fprintln(out, "开始 JumpServer 登录（账号密码仅用于本次换取会话 Cookie，不会保存）")
	username, err = readLine(in, out, "JumpServer 账号: ")
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(username) == "" {
		return "", "", errors.New("账号不能为空")
	}
	password, err = readPassword(in, out, "JumpServer 密码: ")
	if err != nil {
		return "", "", err
	}
	if password == "" {
		return "", "", errors.New("密码不能为空")
	}
	return username, password, nil
}

// RunMFA 提示用户输入 JumpServer 2FA 动态验证码并提交；验证码错误时提示
// 重新输入（最多 mfaRetry 次），返回登录结果。验证码输入隐藏回显。
func RunMFA(ctx context.Context, flow *jumpserver.LoginFlow, prompt *jumpserver.MFAPrompt, in io.Reader, out io.Writer) (*jumpserver.LoginOutcome, error) {
	const mfaRetry = 3
	desc := prompt.Describe()
	for attempt := 0; attempt < mfaRetry; attempt++ {
		if !isTerminal(in) {
			return nil, ErrNotTTY
		}
		if attempt > 0 {
			fmt.Fprintln(out, "验证码错误，请重新输入")
		}
		// 明确提示是 JumpServer 2FA 动态验证码；可选方式一并列出
		mfaType := prompt.DefaultType()
		hint := fmt.Sprintf("请输入 JumpServer 2FA 动态验证码（%s）: ", desc)
		code, err := readPassword(in, out, hint)
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

// isTerminal 判断输入是否来自交互式终端。
func isTerminal(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// readLine 显示提示后读取一行（回显）。
func readLine(in io.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	line, err := readLineRaw(in)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readPassword 显示提示后读取一行（隐藏回显；换行后的回车符不回显）。
func readPassword(in io.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	f, ok := in.(*os.File)
	if !ok {
		return "", ErrNotTTY
	}
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(out) // 补齐换行（ReadPassword 不输出）
	if err != nil {
		return "", err
	}
	return string(b), nil
}

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
