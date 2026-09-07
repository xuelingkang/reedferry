//go:build aix || linux || solaris || zos

package authui

import "golang.org/x/sys/unix"

// termios ioctl 请求常量：Linux/Solaris 等平台的导出名为 TCGETS/TCSETS，
// 与 golang.org/x/term 的 term_unix_other.go 一致；BSD 系（含 macOS）见
// ioctl_bsd.go。
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)
