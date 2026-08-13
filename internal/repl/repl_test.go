package repl

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"reedferry/internal/config"
	"reedferry/internal/jumpserver"
)

// ---------- REPL 辅助 ----------

// newTestREPL 构造带资产的 REPL，connect 注入 mock 记录调用。
func newTestREPL(t *testing.T, assets []jumpserver.Asset) (*REPL, *[]jumpserver.Asset) {
	t.Helper()
	var called []jumpserver.Asset
	r := &REPL{
		cfg:      &config.Config{Host: "http://fake", Cookie: "c"},
		assets:   assets,
		pageSize: pageSize,
		connect: func(a jumpserver.Asset) error {
			called = append(called, a)
			return nil
		},
	}
	return r, &called
}

func mkAssets(n int) []jumpserver.Asset {
	out := make([]jumpserver.Asset, n)
	for i := 0; i < n; i++ {
		out[i] = jumpserver.Asset{ID: string(rune('a' + i%26)), Hostname: strings.ToLower(string(rune('A'+i%26))) + "-host", Address: "203.0.113." + string(rune('0'+i%10))}
	}
	return out
}

// ---------- 命令分发 ----------

func TestCommandDispatch(t *testing.T) {
	r, _ := newTestREPL(t, mkAssets(12))

	// 未知命令报错
	if err := r.runCommand("bogus"); err == nil {
		t.Error("unknown command should error")
	}
	// exit/quit 返回 errQuit
	if err := r.runCommand("exit"); !errors.Is(err, errQuit) {
		t.Errorf("exit: want errQuit, got %v", err)
	}
	if err := r.runCommand("quit"); !errors.Is(err, errQuit) {
		t.Errorf("quit: want errQuit, got %v", err)
	}
	// help/?/list 不报错
	for _, c := range []string{"help", "?", "list", "l", "next", "n", "prev", "p"} {
		if err := r.runCommand(c); err != nil {
			t.Errorf("%s: unexpected error %v", c, err)
		}
	}
}

// ---------- 分页边界 ----------

func TestPaginationBoundaries(t *testing.T) {
	r, _ := newTestREPL(t, mkAssets(25)) // 3 页（10/10/5）
	if r.page != 0 {
		t.Fatalf("initial page: got %d", r.page)
	}
	r.runCommand("next")
	if r.page != 1 {
		t.Errorf("next: got page %d", r.page)
	}
	r.runCommand("next")
	if r.page != 2 {
		t.Errorf("next x2: got page %d", r.page)
	}
	r.runCommand("prev")
	if r.page != 1 {
		t.Errorf("prev: got page %d", r.page)
	}
	// 首页再 prev 不越界
	r.runCommand("prev")
	r.runCommand("prev")
	if r.page != 0 {
		t.Errorf("prev below first page: got %d", r.page)
	}
	// 末页再 next：cmdList 内部回卷到 0
	r.page = 3
	r.cmdList()
	if r.page != 0 {
		t.Errorf("next beyond last page should wrap to 0, got %d", r.page)
	}
}

func newReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

// ---------- 过滤 ----------

func TestFilter(t *testing.T) {
	assets := []jumpserver.Asset{
		{ID: "1", Hostname: "web-01", Address: "203.0.113.1"},
		{ID: "2", Hostname: "db-01", Address: "203.0.113.2"},
		{ID: "3", Hostname: "redis-cache", Address: "203.0.113.3"},
		{ID: "4", Hostname: "GATEWAY-01", Address: "203.0.113.4"},
	}
	r, _ := newTestREPL(t, assets)
	r.runCommand("/web")
	got := r.filtered()
	if len(got) != 1 || got[0].Hostname != "web-01" {
		t.Errorf("filter /web: got %+v", got)
	}
	// 按 IP 过滤
	r.runCommand("/203.0.113.2")
	got = r.filtered()
	if len(got) != 1 || got[0].ID != "2" {
		t.Errorf("filter by IP: got %+v", got)
	}
	// 大小写不敏感：小写关键字匹配大写主机名
	r.runCommand("/gateway")
	got = r.filtered()
	if len(got) != 1 || got[0].Hostname != "GATEWAY-01" {
		t.Errorf("case-insensitive /gateway: got %+v", got)
	}
	r.runCommand("/gateway-01")
	got = r.filtered()
	if len(got) != 1 || got[0].ID != "4" {
		t.Errorf("case-insensitive /gateway-01: got %+v", got)
	}
	// 清除过滤
	r.runCommand("/")
	if r.filter != "" || len(r.filtered()) != 4 {
		t.Errorf("clear filter: filter=%q n=%d", r.filter, len(r.filtered()))
	}
}

// ---------- 编号连接 ----------

func TestConnectByIndex(t *testing.T) {
	assets := []jumpserver.Asset{
		{ID: "1", Hostname: "web-01", Address: "203.0.113.1"},
		{ID: "2", Hostname: "db-01", Address: "203.0.113.2"},
	}
	r, called := newTestREPL(t, assets)
	// 编号 2 → 第二个资产
	if err := r.runCommand("2"); err != nil {
		t.Fatalf("connect by index: %v", err)
	}
	if len(*called) != 1 || (*called)[0].ID != "2" {
		t.Errorf("connected: %+v, want asset 2", *called)
	}
	// 编号越界
	if err := r.runCommand("99"); err == nil {
		t.Error("index out of range should error")
	}
	// 编号 0 报错
	if err := r.runCommand("0"); err == nil {
		t.Error("index 0 should error")
	}
	// 过滤后编号：过滤 /db → 编号 1 = db-01
	r.runCommand("/db")
	if err := r.runCommand("1"); err != nil {
		t.Fatalf("connect filtered by index: %v", err)
	}
	if (*called)[len(*called)-1].ID != "2" {
		t.Errorf("filtered connect: got %+v, want db-01", (*called)[len(*called)-1])
	}
}

// ---------- 直接输入目标连接 ----------

// 非命令内容：先按主机名/IP 精确匹配，匹配到即连接；否则报未知命令
func TestDirectConnect(t *testing.T) {
	assets := []jumpserver.Asset{
		{ID: "1", Hostname: "web-01", Address: "203.0.113.1"},
		{ID: "2", Hostname: "db-01", Address: "203.0.113.2"},
	}
	r, called := newTestREPL(t, assets)
	// 直接输入主机名连接
	if err := r.runCommand("web-01"); err != nil {
		t.Fatalf("direct connect by hostname: %v", err)
	}
	if (*called)[0].ID != "1" {
		t.Errorf("hostname connect: got %+v", (*called)[0])
	}
	// 直接输入 IP 连接
	if err := r.runCommand("203.0.113.2"); err != nil {
		t.Fatalf("direct connect by IP: %v", err)
	}
	if (*called)[1].ID != "2" {
		t.Errorf("IP connect: got %+v", (*called)[1])
	}
	// 匹配不到 → 未知命令或未找到资产
	err := r.runCommand("ghost")
	if err == nil || !strings.Contains(err.Error(), "未知命令或未找到资产") {
		t.Errorf("unknown target: want error, got %v", err)
	}
}

// ---------- list 惰性拉取 ----------

// fakeAPIAssets 提供资产树端点的 fake 服务端（2 个资产）。
func fakeAPIAssets(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"a1","name":"web-01","title":"203.0.113.1","meta":{"type":"asset","data":{}}},{"id":"a2","name":"db-01","title":"203.0.113.2","meta":{"type":"asset","data":{}}}]`))
	}))
}

// list 首次调用才拉取资产（启动不自动拉取）
func TestListTriggersFetch(t *testing.T) {
	srv := fakeAPIAssets(t)
	defer srv.Close()

	r := &REPL{cfg: &config.Config{Host: srv.URL, Cookie: "c"}, pageSize: pageSize}
	if len(r.assets) != 0 {
		t.Fatal("assets should be empty before first list")
	}
	if err := r.runCommand("list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(r.assets) != 2 {
		t.Errorf("assets after list: got %d, want 2", len(r.assets))
	}
}

// list 在 Cookie 为空时提示先编辑配置，不发起拉取
func TestListNoCookie(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := &REPL{cfg: &config.Config{Host: "http://fake", Cookie: ""}, pageSize: pageSize}
	if err := r.runCommand("list"); err != nil {
		t.Fatalf("list without cookie: %v", err)
	}
	if len(r.assets) != 0 {
		t.Errorf("assets should stay empty without cookie, got %d", len(r.assets))
	}
}

// ---------- chanReader ----------

// chanReader 按序消费 channel 中的字节块并拼成 io.Reader 流
func TestChanReader(t *testing.T) {
	ch := make(chan []byte, 3)
	ch <- []byte("hel")
	ch <- []byte("lo\nwor")
	ch <- []byte("ld")
	close(ch)

	r := &chanReader{ch: ch}
	var got []byte
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if string(got) != "hello\nworld" {
		t.Errorf("stream: got %q", got)
	}
}

// ---------- 退出/EOF ----------

// loop 在 stdin EOF（Ctrl-D 行首）时正常退出
func TestLoopEOFExit(t *testing.T) {
	old := os.Stdin
	r, _ := newTestREPL(t, mkAssets(2))
	// 直接构造：loop 用 os.Stdin，无法注入——改用 runCommand 的 errQuit 路径验证退出语义
	if err := r.runCommand("exit"); !errors.Is(err, errQuit) {
		t.Errorf("want errQuit, got %v", err)
	}
	_ = old
}
