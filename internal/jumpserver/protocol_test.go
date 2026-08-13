package jumpserver

import (
	"bytes"
	"math/rand"
	"testing"
)

// U1: hex 编解码往返——随机字节 → Encode → Decode → 与原文一致
func TestHexRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{},
		{0x00, 0x01, 0x0a, 0x0d, 0x1b, 0x7f, 0xff},
		[]byte("hello world\r\n"),
	}
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		b := make([]byte, r.Intn(256))
		_, _ = r.Read(b)
		payloads = append(payloads, b)
	}
	for _, p := range payloads {
		enc := EncodeHex(p)
		dec, err := DecodeHex(enc)
		if err != nil {
			t.Fatalf("DecodeHex(%q): unexpected error: %v", enc, err)
		}
		if !bytes.Equal(dec, p) {
			t.Fatalf("round trip mismatch: got %x want %x", dec, p)
		}
	}
}

// U1 变体: 非法 hex 输入必须报错而非 panic
func TestDecodeHexInvalid(t *testing.T) {
	for _, s := range []string{"zz", "abc", "0x1", "A", "1b?"} {
		if _, err := DecodeHex(s); err == nil {
			t.Errorf("DecodeHex(%q): want error, got nil", s)
		}
	}
}

// U3: 解析 CONNECT 下行消息（含 id）
func TestParseConnect(t *testing.T) {
	m, err := ParseMessage([]byte(`{"type":"CONNECT","id":"sess-123","data":""}`))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.Type != MsgConnect {
		t.Errorf("Type: got %q want %q", m.Type, MsgConnect)
	}
	if m.ID != "sess-123" {
		t.Errorf("ID: got %q want %q", m.ID, "sess-123")
	}
}

// U3: TERMINAL_DATA 的 data 为 hex，解码后还原字节
func TestParseTerminalDataHex(t *testing.T) {
	m, err := ParseMessage([]byte(`{"type":"TERMINAL_DATA","id":"sess-1","data":"68656c6c6f"}`))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.Type != MsgTerminalData {
		t.Errorf("Type: got %q want %q", m.Type, MsgTerminalData)
	}
	got, err := m.DataBytes()
	if err != nil {
		t.Fatalf("DataBytes: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("DataBytes: got %q want %q", got, "hello")
	}
}

// U3: 非法 JSON 返回错误，不 panic
func TestParseInvalidJSON(t *testing.T) {
	for _, raw := range []string{"", "not json{", `{"type":`, `{"type":1,"data":{}}`} {
		if _, err := ParseMessage([]byte(raw)); err == nil {
			t.Errorf("ParseMessage(%q): want error, got nil", raw)
		}
	}
}

// U3 变体: data 为 JSON 对象（v3 可能差异）时容错：不报错、Data 字符串化，解码失败由上层跳过
func TestParseDataObjectTolerant(t *testing.T) {
	m, err := ParseMessage([]byte(`{"type":"TERMINAL_DATA","id":"x","data":{"cols":80,"rows":24}}`))
	if err != nil {
		t.Fatalf("ParseMessage with object data: %v", err)
	}
	if _, err := m.DataBytes(); err == nil {
		t.Errorf("DataBytes on object data: want decode error (non-hex), got nil")
	}
}

// 上行消息编码：携带 id，data 原样字符串
func TestMessageJSON(t *testing.T) {
	m := &Message{Type: MsgTerminalData, ID: "sess-1", Data: "68656c6c6f"}
	got, err := m.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	want := `{"id":"sess-1","type":"TERMINAL_DATA","data":"68656c6c6f"}`
	if string(got) != want {
		t.Errorf("MarshalJSON: got %s want %s", got, want)
	}
}

// TERMINAL_INIT/RESIZE 的 data 为字符串化的 {"cols":N,"rows":N}
func TestSizeData(t *testing.T) {
	got := SizeData(120, 40)
	want := `{"cols":120,"rows":40}`
	if got != want {
		t.Errorf("SizeData: got %s want %s", got, want)
	}
}
