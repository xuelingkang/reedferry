// Command reedferry 是本地终端经 JumpServer koko Web 通道连接资产的交互式工具。
//
// 直接运行 `reedferry`（无参数）进入 REPL，提供资产列表分页、关键字过滤、
// 编号/主机名直连、配置自动初始化等交互命令（见 internal/repl）。
// 设计文档 docs/design/2026-08-13-reedferry-design.md 第 13 章。
package main

import (
	"fmt"
	"os"

	"reedferry/internal/repl"
)

func main() {
	if err := repl.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "reedferry:", err)
		os.Exit(1)
	}
}
