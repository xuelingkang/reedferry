// Package repl 实现 reedferry 交互式 REPL：资产列表分页、关键字过滤、
// 编号直连、直接输入主机名/IP 连接与连接编排（调用 session.Run）。
//
// 启动流程：确保配置存在（不存在时自动创建示例模板）→ Cookie 为空提示编辑 →
// 有 Cookie 则拉取资产（失败提示可重试）→ 提示符循环。
// REPL 使用正常行输入模式（非 raw mode）；只有连接进入会话时才由 session 切 raw mode。
package repl

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"reedferry/internal/config"
	"reedferry/internal/jumpserver"
	"reedferry/internal/session"
)

// pageSize 资产列表每页条数（v2 交互版）。
const pageSize = 10

// errQuit 是 REPL 内部退出信号（exit/quit 命令触发）。
var errQuit = errors.New("quit")

// REPL 保存交互会话状态：配置、资产列表、过滤关键字与分页位置。
type REPL struct {
	cfg      *config.Config
	assets   []jumpserver.Asset
	filter   string // 当前过滤关键字（空 = 不过滤）
	page     int    // 当前页（0 起）
	pageSize int

	// 输入通道：唯一 stdin 读取 goroutine 按模式分发（命令模式 → cmdCh；
	// 会话模式 → sessCh），避免会话结束后泄漏的上行 goroutine 与 REPL 竞争抢读。
	cmdCh  chan []byte
	sessMu sync.Mutex
	sessCh chan []byte // 非 nil 表示当前处于终端会话

	// connect 连接指定资产；默认调用 session.Run，测试可注入 mock。
	connect func(a jumpserver.Asset) error
}

// Run 启动交互式 REPL：确保配置 → 显示欢迎与 help → 命令循环。
// 资产列表不做自动拉取：首次 list 时惰性拉取（KISS）。
func Run() error {
	r := &REPL{pageSize: pageSize}
	if err := r.loadConfig(); err != nil {
		return err
	}
	r.printBanner()
	return r.loop()
}

// printBanner 输出简短欢迎与命令帮助。
func (r *REPL) printBanner() {
	if r.cfg.Host != "" {
		fmt.Printf("Reedferry — 借道 JumpServer Web 终端连接资产（%s）\n\n", r.cfg.Host)
	} else {
		fmt.Println("Reedferry — 借道 JumpServer Web 终端连接资产")
	}
	r.cmdHelp()
}

// loadConfig 确保配置存在（缺失时自动创建示例模板）；Cookie 为空时提示编辑。
func (r *REPL) loadConfig() error {
	cfg, err := config.EnsureConfig()
	if err != nil {
		return err
	}
	r.cfg = cfg
	if cfg.Cookie == "" {
		fmt.Printf("配置文件 %s 中 Cookie 为空：请编辑该文件填入 Cookie（浏览器登录后 F12 → Network → 任选请求 → 复制 Cookie 请求头），然后输入 reload 或重启生效。\n", config.Path())
	}
	return nil
}

// fetchAssets 拉取资产列表（API 全量，本地过滤/分页）。
func (r *REPL) fetchAssets() error {
	assets, err := jumpserver.ListAssets(context.Background(), r.cfg.Host, r.cfg.Cookie)
	if err != nil {
		return err
	}
	r.assets = assets
	r.filter = ""
	r.page = 0
	return nil
}

// filtered 返回按 filter 过滤后的资产列表（主机名/IP 模糊匹配，大小写不敏感）。
func (r *REPL) filtered() []jumpserver.Asset {
	if r.filter == "" {
		return r.assets
	}
	kw := strings.ToLower(r.filter)
	var out []jumpserver.Asset
	for _, a := range r.assets {
		if strings.Contains(strings.ToLower(a.Hostname), kw) || strings.Contains(strings.ToLower(a.Address), kw) {
			out = append(out, a)
		}
	}
	return out
}

// chanReader 实现 io.Reader：从 channel 读取字节块（供 stdin 分发与会话输入使用）。
// 与 bufio.Reader 组合即可按行消费，channel 关闭时返回 io.EOF。
type chanReader struct {
	ch  <-chan []byte
	buf []byte
}

func (r *chanReader) Read(p []byte) (int, error) {
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

// loop 命令主循环（正常行输入模式；Ctrl-D 行首 = EOF 退出）。
//
// 输入模型（修复回 REPL 后首次输入被吞的 bug）：唯一 stdin 读取 goroutine 把
// 字节投递到 rawCh；分发 goroutine 按当前模式转发——命令模式发 cmdCh（REPL
// 消费），会话模式发 sessCh（session 消费）。会话结束后分发不再发 sessCh，
// 泄漏的上行 goroutine 阻塞在 channel 接收而非 fd 读取，不再与 REPL 竞争 stdin。
func (r *REPL) loop() error {
	rawCh := make(chan []byte, 64)
	r.cmdCh = make(chan []byte, 64)

	go func() { // 唯一读取 os.Stdin 的 goroutine
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				rawCh <- cp
			}
			if err != nil {
				close(rawCh)
				return
			}
		}
	}()
	go func() { // 模式分发
		for data := range rawCh {
			r.sessMu.Lock()
			ch := r.sessCh
			r.sessMu.Unlock()
			if ch != nil {
				ch <- data
			} else {
				r.cmdCh <- data
			}
		}
		close(r.cmdCh)
	}()

	reader := bufio.NewReader(&chanReader{ch: r.cmdCh})
	for {
		fmt.Print("reedferry> ")
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil {
			if err == io.EOF {
				// Ctrl-D 行首（EOF）→ 退出
				fmt.Println()
				return nil
			}
			if line == "" {
				return err
			}
		}
		if line == "" {
			continue
		}
		if err := r.runCommand(line); err != nil {
			if errors.Is(err, errQuit) {
				return nil
			}
			fmt.Fprintln(os.Stderr, "reedferry:", err)
		}
	}
}

// runCommand 解析并执行一条命令；errQuit 表示退出 REPL。
// 非命令内容（非纯数字）视为目标名：先按主机名/IP 精确匹配，匹配到即连接，
// 否则报"未知命令或未找到资产"。
func (r *REPL) runCommand(line string) error {
	switch {
	case line == "list" || line == "l":
		r.cmdList()
		return nil
	case line == "next" || line == "n":
		r.page++
		r.cmdList()
		return nil
	case line == "prev" || line == "p":
		if r.page > 0 {
			r.page--
		}
		r.cmdList()
		return nil
	case strings.HasPrefix(line, "/"):
		r.filter = strings.TrimSpace(strings.TrimPrefix(line, "/"))
		r.page = 0
		r.cmdList()
		return nil
	case line == "reload" || line == "r":
		return r.cmdReload()
	case line == "help" || line == "?":
		r.cmdHelp()
		return nil
	case line == "exit" || line == "quit":
		return errQuit
	default:
		// 纯数字：编号直连；否则视为目标名（主机名/IP）
		if n, err := strconv.Atoi(line); err == nil {
			return r.cmdConnectByIndex(n)
		}
		return r.cmdConnectTarget(line)
	}
}

// cmdList 显示当前页资产（全局编号 + 主机名 + IP）。
// 未拉取过（assets 为空）时先惰性拉取；Cookie 为空时提示先编辑配置。
func (r *REPL) cmdList() {
	if len(r.assets) == 0 {
		if err := r.fetchAssets(); err != nil {
			if r.cfg != nil && r.cfg.Cookie == "" {
				fmt.Printf("请先编辑 %s 填入 Cookie 后重试\n", config.Path())
			} else {
				fmt.Printf("资产拉取失败：%v（可输入 reload 重试）\n", err)
			}
			return
		}
	}
	list := r.filtered()
	total := len(list)
	if total == 0 {
		if r.filter != "" {
			fmt.Printf("没有匹配 %q 的资产（输入 / 清除过滤）\n", r.filter)
		} else {
			fmt.Println("没有可用的资产（输入 reload 重新拉取）")
		}
		return
	}
	start := r.page * r.pageSize
	if start >= total {
		r.page = 0
		start = 0
	}
	end := start + r.pageSize
	if end > total {
		end = total
	}
	for i, a := range list[start:end] {
		fmt.Printf("%2d  %-24s %-16s\n", start+i+1, a.Hostname, a.Address)
	}
	pages := (total + r.pageSize - 1) / r.pageSize
	fmt.Printf("第 %d/%d 页，共 %d 条（输入编号或主机名/IP 连接；/关键字 过滤；n/p 翻页）\n", r.page+1, pages, total)
}

// cmdConnectByIndex 按列表编号连接（编号为过滤后列表的全局序号，从 1 起）。
func (r *REPL) cmdConnectByIndex(idx int) error {
	list := r.filtered()
	if idx < 1 || idx > len(list) {
		return fmt.Errorf("编号 %d 超出范围（当前 %d 条，输入 list 查看）", idx, len(list))
	}
	return r.connectAsset(list[idx-1])
}

// cmdConnectTarget 直接以主机名/IP 精确匹配连接（无 conn 前缀）；
// 未拉取过资产时先惰性拉取（与 list 一致）；匹配失败视为未知命令/未找到资产。
func (r *REPL) cmdConnectTarget(target string) error {
	if target == "" {
		return errors.New("输入为空（输入 help 查看命令）")
	}
	if len(r.assets) == 0 {
		// 惰性拉取后再匹配
		if err := r.fetchAssets(); err != nil {
			return fmt.Errorf("资产拉取失败：%v（可先输入 list 或 reload）", err)
		}
	}
	for _, a := range r.assets {
		if a.Hostname == target || a.Address == target {
			return r.connectAsset(a)
		}
	}
	return fmt.Errorf("未知命令或未找到资产 %q（输入 help 查看命令）", target)
}

// cmdReload 重新拉取资产（编辑配置文件后生效）。
func (r *REPL) cmdReload() error {
	if err := r.fetchAssets(); err != nil {
		return fmt.Errorf("资产拉取失败：%v", err)
	}
	r.cmdList()
	return nil
}

// connectAsset 建立终端会话；会话结束后回到 REPL。
// 会话期间把 stdin 分发切换到会话 channel（sessCh），结束后切回命令模式。
func (r *REPL) connectAsset(a jumpserver.Asset) error {
	if r.connect != nil {
		return r.connect(a)
	}
	fmt.Printf("正在连接 %s（%s）...\n", a.Hostname, a.Address)

	sessCh := make(chan []byte, 256)
	r.sessMu.Lock()
	r.sessCh = sessCh
	r.sessMu.Unlock()
	defer func() {
		r.sessMu.Lock()
		r.sessCh = nil
		r.sessMu.Unlock()
	}()

	err := session.Run(context.Background(), r.cfg, a.ID, session.Options{Input: &chanReader{ch: sessCh}})
	if err != nil {
		fmt.Printf("连接已断开：%v\n", err)
	} else {
		fmt.Printf("已断开 %s\n", a.Hostname)
	}
	return nil
}

// cmdHelp 打印全部命令帮助。
func (r *REPL) cmdHelp() {
	fmt.Print(`命令：
  list / l         显示资产列表（分页，每页 10 条）
  next / n         下一页
  prev / p         上一页
  /关键字           按主机名/IP 本地过滤（输入 / 清除过滤）
  <编号>           直接连接列表中的资产
  <主机名或IP>      直接输入名称连接
  reload / r       重新拉取资产（编辑配置文件后生效）
  help / ?         显示本帮助
  exit / quit      退出（Ctrl-D 同样可退出）
`)
}
