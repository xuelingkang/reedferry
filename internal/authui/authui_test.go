package authui

import (
	"errors"
	"io"
	"strings"
	"testing"
)

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
