//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package authui

import "golang.org/x/sys/unix"

// termios ioctl 请求常量：BSD 系平台（含 macOS/darwin）的导出名为
// TIOCGETA/TIOCSETA，与 golang.org/x/term 的 term_unix_bsd.go 一致；
// Linux/Solaris 等平台见 ioctl_other.go。
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
