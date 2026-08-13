package jumpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// 握手 + 双通道：Text 帧 = JSON 控制消息，Binary 帧 = 裸字节（v3 纯透传，附录 D V3）
func TestConnHandshakeAndExchange(t *testing.T) {
	up := websocket.Upgrader{}
	gotReq := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 握手 Header 携带 Cookie（设计文档 5.2.2）
		if r.Header.Get("Cookie") != testCookie {
			t.Errorf("ws handshake Cookie: got %q", r.Header.Get("Cookie"))
		}
		// 端点 query 参数（token 认证）
		if r.URL.Query().Get("token") != "tok-1" {
			t.Errorf("ws query: %v", r.URL.Query())
		}
		close(gotReq)
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		// 下行 Text 控制帧 CONNECT
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"CONNECT","id":"sess-1","data":""}`))
		// 等客户端上行 Binary 裸字节（"hi"）
		typ, raw, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("read from client: %v", err)
			return
		}
		if typ != websocket.BinaryMessage || string(raw) != "hi" {
			t.Errorf("client data: typ=%d raw=%q, want Binary \"hi\"", typ, raw)
		}
		// 等客户端上行 Text 控制帧（PING）
		typ, raw, err = conn.ReadMessage()
		if err != nil {
			t.Errorf("read control from client: %v", err)
			return
		}
		if typ != websocket.TextMessage || !strings.Contains(string(raw), `"type":"PING"`) {
			t.Errorf("client control: typ=%d raw=%s, want Text PING", typ, raw)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Connect(ctx, srv.URL, testCookie, "tok-1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	select {
	case <-gotReq:
	case <-ctx.Done():
		t.Fatal("handshake not received")
	}

	// 读 Text CONNECT → EventControl
	ev, err := conn.ReadEvent(ctx)
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if ev.Kind != EventControl || ev.Msg.Type != MsgConnect || ev.Msg.ID != "sess-1" {
		t.Errorf("CONNECT event mismatch: %+v", ev)
	}

	// 上行 Binary 裸字节（v3 纯透传，不再 hex 编码）
	if err := conn.WriteData([]byte("hi")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	// 上行 Text JSON 控制帧
	if err := conn.WriteControl(NewMessage(MsgPing, "sess-1", "")); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}
}

// 下行 Binary 帧为裸终端字节流（v3 纯透传）：EventData 原样返回，非 JSON 解析
func TestReadBinaryData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Text 控制帧 CONNECT
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"CONNECT","id":"s-1","data":""}`))
		// Binary 裸字节（shell banner，含控制序列）
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("\x1b[2Jroot@web-01:~# "))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Connect(ctx, srv.URL, testCookie, "tok-1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	ev, err := conn.ReadEvent(ctx)
	if err != nil || ev.Kind != EventControl || ev.Msg.Type != MsgConnect {
		t.Fatalf("first read: err=%v ev=%+v", err, ev)
	}
	ev, err = conn.ReadEvent(ctx)
	if err != nil {
		t.Fatalf("binary data read: %v", err)
	}
	if ev.Kind != EventData {
		t.Fatalf("binary frame kind: got %v want EventData", ev.Kind)
	}
	want := "\x1b[2Jroot@web-01:~# "
	if string(ev.Data) != want {
		t.Errorf("binary data: got %q want %q", ev.Data, want)
	}
}

// 握手被 302 重定向（→登录页）：判定为会话失效
func TestConnectHandshakeRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/core/auth/login/", http.StatusFound)
	}))
	defer srv.Close()

	_, err := Connect(context.Background(), srv.URL, testCookie, "tok-1")
	if err == nil {
		t.Fatal("want error, got nil")
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusFound {
		t.Fatalf("want 302 APIError, got %v", err)
	}
}

// 握手 401：会话失效
func TestConnectHandshakeUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := Connect(context.Background(), srv.URL, testCookie, "tok-1")
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 APIError, got %v", err)
	}
}

// 握手 404：路径可能不适用于当前版本
func TestConnectHandshakeNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := Connect(context.Background(), srv.URL, testCookie, "tok-1")
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 APIError, got %v", err)
	}
}

// 网络不可达：返回网络类错误而非 APIError
func TestConnectNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	host := srv.URL
	srv.Close()
	_, err := Connect(context.Background(), host, testCookie, "tok-1")
	if err == nil {
		t.Fatal("want network error, got nil")
	}
	var ae *APIError
	if errors.As(err, &ae) {
		t.Errorf("network error should not be APIError: %v", err)
	}
}

// 握手失败 4xx 时不 panic（Connect 返回错误而非 panic）
func TestConnectNotFoundNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Connect panicked: %v", r)
		}
	}()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	_, _ = Connect(context.Background(), srv.URL, testCookie, "tok-1")
}

// wsURL：https→wss、带 path 前缀、裸主机名补全
func TestWSURL(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"https://your-jumpserver.example.com", "wss://your-jumpserver.example.com/koko/ws/terminal/?token=tok-1"},
		{"your-jumpserver.example.com", "wss://your-jumpserver.example.com/koko/ws/terminal/?token=tok-1"},
		{"https://your-jumpserver.example.com/jms/", "wss://your-jumpserver.example.com/jms/koko/ws/terminal/?token=tok-1"},
		{"http://127.0.0.1:8080", "ws://127.0.0.1:8080/koko/ws/terminal/?token=tok-1"},
	}
	for _, c := range cases {
		got, err := wsURL(c.host, "tok-1")
		if err != nil {
			t.Errorf("wsURL(%q): %v", c.host, err)
			continue
		}
		if got != c.want {
			t.Errorf("wsURL(%q): got %s want %s", c.host, got, c.want)
		}
	}
}

// 非法 JSON 文本帧：ReadEvent 返回 ErrMalformed 而非 panic，可被上层跳过
func TestReadMalformedMessage(t *testing.T) {
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("not json{"))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"PING","id":"s","data":""}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Connect(ctx, srv.URL, testCookie, "tok-1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	ev, err := conn.ReadEvent(ctx)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("first read: want ErrMalformed, got %v (ev=%+v)", err, ev)
	}
	ev, err = conn.ReadEvent(ctx)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if ev.Kind != EventControl || ev.Msg.Type != MsgPing {
		t.Errorf("second event: got %+v, want control PING", ev)
	}
}

// 服务端直接断开（不发送关闭帧）：返回读错误而非 panic
func TestReadUnexpectedClose(t *testing.T) {
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Close() // 立即断开
	}))
	defer srv.Close()

	conn, err := Connect(context.Background(), srv.URL, testCookie, "tok-1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = conn.ReadEvent(ctx)
	if err == nil {
		t.Fatal("want read error, got nil")
	}
	if strings.Contains(err.Error(), "panic") {
		t.Fatalf("unexpected panic-ish error: %v", err)
	}
}
