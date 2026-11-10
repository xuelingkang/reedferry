package authui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"reedferry/internal/jumpserver"
)

// HiddenReader：按序消费通道字节块拼成 io.Reader 流；通道关闭返回 io.EOF
func TestHiddenReaderStream(t *testing.T) {
	ch := make(chan []byte, 3)
	ch <- []byte("abc")
	ch <- []byte("de\nfgh")
	close(ch)

	hr := NewHiddenReader(ch, -1)
	var got []byte
	buf := make([]byte, 64)
	for {
		n, err := hr.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if string(got) != "abcde\nfgh" {
		t.Errorf("stream: got %q", got)
	}
}

// HiddenReader 通道无数据时 Read 阻塞（验证分发通道语义：消费方不抢 fd 读）
func TestHiddenReaderBlocksOnEmptyChannel(t *testing.T) {
	ch := make(chan []byte)
	hr := NewHiddenReader(ch, -1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4)
		_, _ = hr.Read(buf)
	}()
	select {
	case <-done:
		t.Fatal("Read returned on empty channel; 必须阻塞等通道数据（不抢读 fd）")
	default:
	}
	ch <- []byte("x")
	<-done
}

// HiddenReader：fd 非 TTY 时 SetEcho 返回 ErrNotTTY（隐藏回显不可用）
func TestHiddenReaderSetEchoNotTTY(t *testing.T) {
	ch := make(chan []byte)
	hr := NewHiddenReader(ch, -1)
	if err := hr.SetEcho(false); !errors.Is(err, ErrNotTTY) {
		t.Errorf("SetEcho on non-TTY fd: got %v, want ErrNotTTY", err)
	}
}

// readLineRaw 行为：按行读取，CR 忽略、LF 终止、EOF 返回已读内容 + io.EOF
func TestReadLineRaw(t *testing.T) {
	src := strings.NewReader("abc\r\ndef\n")
	line, err := readLineRaw(src)
	if err != nil || line != "abc" {
		t.Errorf("first line: %q err %v", line, err)
	}
	line, err = readLineRaw(src)
	if err != nil || line != "def" {
		t.Errorf("second line: %q err %v", line, err)
	}
	// EOF：返回已读内容 + io.EOF
	line, err = readLineRaw(src)
	if err != io.EOF || line != "" {
		t.Errorf("EOF line: %q err %v", line, err)
	}
}

// readLineRaw：流中无换行直接 EOF → io.EOF
func TestReadLineRawPartialThenEOF(t *testing.T) {
	src := strings.NewReader("tail")
	line, err := readLineRaw(src)
	if err != io.EOF || line != "tail" {
		t.Errorf("partial then EOF: %q err %v", line, err)
	}
}

// readLineRaw：空输入（EOF）返回 io.EOF
func TestReadLineRawEOF(t *testing.T) {
	if _, err := readLineRaw(strings.NewReader("")); !errors.Is(err, io.EOF) {
		t.Errorf("want EOF, got %v", err)
	}
}

// renderQRCode：输出含配色转义与半块字符，且图像按两行并一行字符缩写。
func TestRenderQRCode(t *testing.T) {
	art, err := renderQRCode("https://sso.example.com/login?key=abc&type=qrcode-login")
	if err != nil {
		t.Fatalf("renderQRCode: %v", err)
	}
	if !strings.Contains(art, "\x1b[30;47m") || !strings.Contains(art, "\x1b[0m") {
		t.Error("missing ANSI color codes (dark terminal would invert the code)")
	}
	if !strings.ContainsAny(art, "█▀▄") {
		t.Error("no block characters rendered")
	}
	if strings.Count(art, "\n") < 10 {
		t.Errorf("suspiciously few rows: %d", strings.Count(art, "\n"))
	}
}

// RenderQR 非终端输出：不写转义序列，改打印二维码内容 URL。
func TestRenderQRFallbackNonTTY(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderQR(&buf, "https://sso.example.com/login?key=abc"); err != nil {
		t.Fatalf("RenderQR: %v", err)
	}
	if !strings.Contains(buf.String(), "二维码内容：https://sso.example.com/login?key=abc") {
		t.Errorf("fallback output: %q", buf.String())
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Error("ANSI escapes written to non-terminal output")
	}
}

// splitLines：按行拆分字节块，处理跨块行与 CR。
func TestSplitLines(t *testing.T) {
	ch := make(chan []byte, 3)
	ch <- []byte("a")
	ch <- []byte("b\r\nc\n")
	ch <- []byte("d")
	close(ch)
	lines, stop := splitLines(ch)
	defer stop()
	var got []string
	for line := range lines {
		got = append(got, line)
	}
	want := []string{"ab", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("lines: %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

// stubFlow 模拟扫码流程：按队列返回轮询结果。
type stubFlow struct {
	qr        *jumpserver.QRCode
	results   []stubResult
	refresh   int
	refreshed chan struct{}
}

type stubResult struct {
	status  jumpserver.ScanStatus
	outcome *jumpserver.LoginOutcome
	err     error
}

func (s *stubFlow) QR() *jumpserver.QRCode { return s.qr }

func (s *stubFlow) RefreshQR(context.Context) error {
	s.refresh++
	if s.refreshed != nil {
		s.refreshed <- struct{}{}
	}
	return nil
}

func (s *stubFlow) PollScan(context.Context) (jumpserver.ScanStatus, *jumpserver.LoginOutcome, error) {
	if len(s.results) == 0 {
		return jumpserver.ScanWaiting, nil, nil
	}
	r := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return r.status, r.outcome, r.err
}

func newStub(results ...stubResult) *stubFlow {
	return &stubFlow{qr: &jumpserver.QRCode{Content: "https://sso.example.com/login?key=k", Token: "tok", Version: 1}, results: results}
}

// WaitScan：轮询到已扫码并完成，中间提示扫码状态。
func TestWaitScanScannedThenDone(t *testing.T) {
	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	final := &jumpserver.LoginOutcome{Cookie: "jms_sessionid=x"}
	flow := newStub(
		stubResult{status: jumpserver.ScanScanned},
		stubResult{status: jumpserver.ScanScanned, outcome: final},
	)
	var out bytes.Buffer
	got, err := WaitScan(context.Background(), flow, make(chan []byte), &out)
	if err != nil {
		t.Fatalf("WaitScan: %v", err)
	}
	if got == nil || got.Cookie != "jms_sessionid=x" {
		t.Errorf("outcome: %+v", got)
	}
	if !strings.Contains(out.String(), "已扫码") {
		t.Errorf("missing scanned hint: %q", out.String())
	}
}

// WaitScan：输入 q 取消登录（返回 ErrCancelled）。
func TestWaitScanCancel(t *testing.T) {
	ch := make(chan []byte, 1)
	ch <- []byte("q\n")
	if _, err := WaitScan(context.Background(), newStub(), ch, io.Discard); !errors.Is(err, ErrCancelled) {
		t.Errorf("want ErrCancelled, got %v", err)
	}
}

// WaitScan：二维码过期时自动刷新并继续等待。
func TestWaitScanRefreshesOnExpired(t *testing.T) {
	old := pollInterval
	pollInterval = 5 * time.Millisecond
	defer func() { pollInterval = old }()

	final := &jumpserver.LoginOutcome{Cookie: "jms_sessionid=x"}
	flow := newStub(
		stubResult{err: &jumpserver.LoginError{Kind: jumpserver.LoginErrQRExpired, Msg: "二维码已过期"}},
		stubResult{outcome: final},
	)
	var out bytes.Buffer
	got, err := WaitScan(context.Background(), flow, make(chan []byte), &out)
	if err != nil {
		t.Fatalf("WaitScan: %v", err)
	}
	if got != final {
		t.Errorf("outcome: %+v", got)
	}
	if flow.refresh != 1 {
		t.Errorf("refresh calls: %d", flow.refresh)
	}
	if !strings.Contains(out.String(), "已过期") {
		t.Errorf("missing expired hint: %q", out.String())
	}
}
