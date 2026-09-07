package authui

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
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

// ReadCredentials：配置预填凭据时跳过账号/密码交互输入（不再消费通道）
func TestReadCredentialsPresetSkipsInput(t *testing.T) {
	ch := make(chan []byte, 1)
	ch <- []byte("typo\n") // 若有任何交互读取，这里会读到该字节
	hr := NewHiddenReader(ch, -1)
	username, password, err := ReadCredentials(hr, io.Discard, Credentials{Username: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatalf("ReadCredentials: %v", err)
	}
	if username != "alice" || password != "s3cret" {
		t.Errorf("preset credentials: got %q/%q", username, password)
	}
}

// ReadCredentials：预填只给账号时，密码仍需交互输入；账号空报错
func TestReadCredentialsPartialPreset(t *testing.T) {
	ch := make(chan []byte, 1)
	ch <- []byte("pwd1\n")
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hr := NewHiddenReader(ch, int(f.Fd()))
	username, password, err := ReadCredentials(hr, io.Discard, Credentials{Username: "alice"})
	if err != nil {
		t.Fatalf("ReadCredentials: %v", err)
	}
	if username != "alice" || password != "pwd1" {
		t.Errorf("partial preset: got %q/%q", username, password)
	}

	ch2 := make(chan []byte)
	close(ch2) // EOF：账号输入被取消
	hr2 := NewHiddenReader(ch2, -1)
	if _, _, err := ReadCredentials(hr2, io.Discard, Credentials{}); !errors.Is(err, io.EOF) {
		t.Errorf("EOF on username: got %v, want io.EOF", err)
	}
}
