// Package terminal 管理本地终端：raw mode、尺寸读取、SIGWINCH 尺寸变化监听。
//
// 设计要点（见设计文档 5.2.3/5.2.4）：Reedferry 为纯终端透传，不启动本地
// shell 进程参与数据流（否则本地 shell 的渲染/回显会混入上行字节）；本地
// 终端仅提供 raw mode 与尺寸来源，字节流由 session 在 终端 ↔ WebSocket 间
// 原样双向搬运。
package terminal

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// ErrNotTTY 表示 stdin 不是交互式终端（如管道重定向），无法建立终端会话。
var ErrNotTTY = errors.New("connect 需要交互式终端（stdin 不是 TTY）")

// PTY 封装本地终端句柄。
type PTY struct {
	F        *os.File // 终端文件句柄（交互场景为 os.Stdin）
	cols     int      // 当前终端列数
	rows     int      // 当前终端行数
	oldState *term.State
}

// Open 使本地终端进入 raw mode 并读取当前尺寸。
//
// shell 参数保留设计文档接口签名；因采用纯透传，交互场景不会启动本地
// shell 进程（见包注释）。stdin 非 TTY 时返回 ErrNotTTY。
func Open(shell string) (*PTY, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, ErrNotTTY
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("进入 raw mode 失败：%w", err)
	}
	w, h, err := term.GetSize(fd)
	if err != nil {
		_ = term.Restore(fd, oldState)
		return nil, fmt.Errorf("读取终端尺寸失败：%w", err)
	}
	return &PTY{F: os.Stdin, cols: w, rows: h, oldState: oldState}, nil
}

// Size 返回当前终端尺寸。
func (p *PTY) Size() (cols, rows int) {
	return p.cols, p.rows
}

// WatchSize 监听 SIGWINCH（窗口尺寸变化），变化时读取新尺寸并回调 fn。
// 尺寸变化直接由上层（session）发 TERMINAL_RESIZE 同步远端，本地无需调整。
func (p *PTY) WatchSize(fn func(cols, rows int)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if w, h, err := term.GetSize(int(p.F.Fd())); err == nil {
				p.cols, p.rows = w, h
				fn(w, h)
			}
		}
	}()
}

// Restore 恢复终端 raw mode 前的状态（defer 保证会话结束时调用）。
func (p *PTY) Restore() {
	if p.oldState != nil {
		_ = term.Restore(int(p.F.Fd()), p.oldState)
		p.oldState = nil
	}
}
