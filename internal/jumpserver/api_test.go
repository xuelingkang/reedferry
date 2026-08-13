package jumpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testCookie = "sessionid=abc; csrftoken=def"

// newTestServer 构造 httptest 服务端并返回其地址。
func newTestServer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// 资产树 200：从根逐层展开收集资产叶子（BFS），字段映射 id/name/title/meta.data
func TestListAssetsTreeExpand(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != testCookie {
			t.Errorf("Cookie header: got %q", testCookie)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("key") {
		case "":
			// 根：分组节点 + 一个资产
			_, _ = w.Write([]byte(`[
				{"id":"node-1","name":"生产环境","title":"生产环境","pId":"","isParent":true,"open":true,"meta":{"type":"node","data":{}}},
				{"id":"a1","name":"web-01","title":"203.0.113.1","pId":"node-1","meta":{"type":"asset","data":{"platform_type":"Linux","org_name":"org1","address":"203.0.113.1"}}}
			]`))
		case "node-1":
			// 分组子节点：资产叶子
			_, _ = w.Write([]byte(`[
				{"id":"a2","name":"db-01","title":"203.0.113.2","pId":"node-1","meta":{"type":"asset","data":{"platform_type":"MySQL","org_name":"org1","address":"203.0.113.2"}}}
			]`))
		default:
			t.Errorf("unexpected key: %q", r.URL.Query().Get("key"))
			_, _ = w.Write([]byte(`[]`))
		}
	})

	assets, err := ListAssets(context.Background(), host, testCookie)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("got %d assets, want 2: %+v", len(assets), assets)
	}
	a0, a1 := assets[0], assets[1]
	if a0.ID != "a1" || a0.Hostname != "web-01" || a0.Address != "203.0.113.1" {
		t.Errorf("asset[0] mismatch: %+v", a0)
	}
	if a1.ID != "a2" || a1.Hostname != "db-01" || a1.Address != "203.0.113.2" {
		t.Errorf("asset[1] mismatch: %+v", a1)
	}
	if a1.PlatformType != "MySQL" || a1.OrgName != "org1" {
		t.Errorf("asset[1] extension fields: %+v", a1)
	}
}

// 展开节点时查询参数必须是 key（用 id= 会 500，实测结论）
func TestListAssetsKeyParam(t *testing.T) {
	var gotKeys []string
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("id") != "" {
			t.Errorf("id param should not be sent, got %q", q.Get("id"))
		}
		gotKeys = append(gotKeys, q.Get("key"))
		_, _ = w.Write([]byte(`[{"id":"n1","name":"g","meta":{"type":"node","data":{}}}]`))
	})
	_, err := ListAssets(context.Background(), host, testCookie)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	// 根调用无 key，n1 调用 key=n1
	if len(gotKeys) != 2 || gotKeys[0] != "" || gotKeys[1] != "n1" {
		t.Errorf("key sequence: %v", gotKeys)
	}
}

// 节点重复引用（环）：只展开一次，不无限循环
func TestListAssetsCycleSafe(t *testing.T) {
	call := 0
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		call++
		_, _ = w.Write([]byte(`[
			{"id":"n1","name":"g","meta":{"type":"node","data":{}}},
			{"id":"n1","name":"g-dup","meta":{"type":"node","data":{}}}
		]`))
	})
	if _, err := ListAssets(context.Background(), host, testCookie); err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if call != 2 { // 根 + n1 各一次
		t.Errorf("expected 2 tree calls, got %d", call)
	}
}

// meta 缺失/非法/未知类型的节点：容错跳过，不中断
func TestListAssetsTolerant(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"id":"x1","name":"no-meta"},
			{"id":"x2","name":"bad-meta","meta":"oops"},
			{"id":"x3","name":"unknown","meta":{"type":"weird","data":{}}},
			{"id":"a1","name":"ok","title":"1.2.3.4","meta":{"type":"asset","data":{}}}
		]`))
	})
	assets, err := ListAssets(context.Background(), host, testCookie)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 1 || assets[0].Hostname != "ok" {
		t.Errorf("expected only the valid asset, got %+v", assets)
	}
}

// title 缺失时回退到 meta.data.address
func TestListAssetsAddressFallback(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"id": "a1", "name": "web", "meta": {"type": "asset", "data": {"address": "203.0.113.9"}}}
		]`))
	})
	assets, err := ListAssets(context.Background(), host, testCookie)
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if assets[0].Address != "203.0.113.9" {
		t.Errorf("address fallback: got %q", assets[0].Address)
	}
}

// 404（HTML 响应）：明确报错不 panic，且可识别状态码
func TestListAssets404HTML(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not found</body></html>"))
	})
	_, err := ListAssets(context.Background(), host, testCookie)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if ae.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode: got %d want 404", ae.StatusCode)
	}
}

// 401：会话失效提示
func TestListAssetsUnauthorized(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Authentication credentials were not provided."}`))
	})
	_, err := ListAssets(context.Background(), host, testCookie)
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 APIError, got %v", err)
	}
}

// 302：跳转登录页判定为会话失效
func TestListAssetsRedirect(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/core/auth/login/", http.StatusFound)
	})
	_, err := ListAssets(context.Background(), host, testCookie)
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusFound {
		t.Fatalf("want 302 APIError, got %v", err)
	}
}

// 系统用户：permed_accounts 数组（v3 实测端点）
func TestListSystemUsersOK(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/self/assets/a1/") {
			t.Errorf("path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"permed_accounts":[
			{"id":"u1","name":"root-acc","username":"root","secret_type":"password"},
			{"id":"u2","name":"admin-acc","username":"admin","secret_type":"key"}
		]}`))
	})
	users, err := ListSystemUsers(context.Background(), host, testCookie, "a1")
	if err != nil {
		t.Fatalf("ListSystemUsers: %v", err)
	}
	if len(users) != 2 || users[0].ID != "u1" || users[0].Username != "root" {
		t.Errorf("users mismatch: %+v", users)
	}
}

// 无可用账号：空数组正常返回
func TestListSystemUsersEmpty(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"permed_accounts":[]}`))
	})
	users, err := ListSystemUsers(context.Background(), host, testCookie, "a1")
	if err != nil {
		t.Fatalf("ListSystemUsers: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("want empty, got %+v", users)
	}
}

// config test 会话校验：树根端点 200 视为有效
func TestVerifySessionOK(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "" {
			t.Errorf("VerifySession should call root (no key), got %v", r.URL.Query())
		}
		_, _ = w.Write([]byte(`[]`))
	})
	status, err := VerifySession(context.Background(), host, testCookie)
	if err != nil || status != http.StatusOK {
		t.Fatalf("VerifySession: status=%d err=%v", status, err)
	}
}

// config test 会话校验：401 返回状态码与分类错误
func TestVerifySessionUnauthorized(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	status, err := VerifySession(context.Background(), host, testCookie)
	if status != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", status)
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Errorf("want *APIError, got %v", err)
	}
}

// 网络错误（连接拒绝）：返回网络类错误而非 APIError
func TestListAssetsNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	host := srv.URL
	srv.Close()
	_, err := ListAssets(context.Background(), host, testCookie)
	if err == nil {
		t.Fatal("want network error, got nil")
	}
	var ae *APIError
	if errors.As(err, &ae) {
		t.Errorf("network error should not be APIError: %v", err)
	}
}

// 请求超时：服务端挂起（不响应）时，请求在 apiTimeout 内超时返回而非永久阻塞
// （connect 卡在"正在连接"的实测问题回归）
func TestRequestTimeout(t *testing.T) {
	old := apiTimeout
	apiTimeout = 200 * time.Millisecond
	t.Cleanup(func() { apiTimeout = old })

	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond) // 挂起，不响应（远大于 apiTimeout 200ms）
	})
	start := time.Now()
	_, err := ListAssets(context.Background(), host, testCookie)
	if err == nil {
		t.Fatal("want timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("request should time out quickly, took %v", elapsed)
	}
	// 错误应为超时类（context deadline exceeded），而非其他
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want context deadline exceeded, got %v", err)
	}
}

// 响应体惰性读取竞态回归（真实环境间歇性 context canceled）：
// 服务端 header 立即返回、body 延迟写入——body 的 ReadAll 必须在请求 ctx
// 取消（doRequest 返回时）之前完成，否则报 context canceled。
func TestReadBodyBeforeCancel(t *testing.T) {
	old := apiTimeout
	apiTimeout = 2 * time.Second // 超时窗口远大于 body 延迟
	t.Cleanup(func() { apiTimeout = old })

	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// header 已返回（http.Client.Do 立即返回），body 延迟 300ms 写入
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`[{"id":"a1","name":"web-01","title":"203.0.113.1","meta":{"type":"asset","data":{}}}]`))
	})

	assets, err := ListAssets(context.Background(), host, testCookie)
	if err != nil {
		t.Fatalf("ListAssets with delayed body: %v", err)
	}
	if len(assets) != 1 || assets[0].Hostname != "web-01" {
		t.Errorf("assets mismatch: %+v", assets)
	}
}

// CreateConnectToken：POST + CSRF 头 + 请求体字段 + 201 解析（v3 实测流程第一步）
func TestCreateConnectToken(t *testing.T) {
	// 先声明 host 再赋值：短变量声明（host := f(闭包引用 host)）作用域从语句结束后
	// 才开始，闭包内直接引用会报 undefined
	var host string
	host = newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s want POST", r.Method)
		}
		if r.Header.Get("X-CSRFToken") != "CSRF-TOKEN" {
			t.Errorf("X-CSRFToken: got %q", r.Header.Get("X-CSRFToken"))
		}
		if r.Header.Get("Cookie") != testCookie {
			t.Errorf("Cookie: got %q", r.Header.Get("Cookie"))
		}
		// CSRF 保护还校验 Referer（403 'Referer checking failed - no Referer'，v3 实测）
		if got := r.Header.Get("Referer"); got != host+"/" {
			t.Errorf("Referer: got %q, want %q/", got, host)
		}
		var body ConnectTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.Asset != "a1" || body.Account != "u1" || body.Protocol != "ssh" ||
			body.InputSecretType != "password" || body.ConnectMethod != "web" {
			t.Errorf("request body mismatch: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"tok-123","value":"secret-value"}`))
	})

	tok, err := CreateConnectToken(context.Background(), host, testCookie, "CSRF-TOKEN", "a1", "u1")
	if err != nil {
		t.Fatalf("CreateConnectToken: %v", err)
	}
	if tok.ID != "tok-123" || tok.Value != "secret-value" {
		t.Errorf("token mismatch: %+v", tok)
	}
}

// CreateConnectToken：CSRF 头不正确（缺 jms_csrftoken 对应值）时服务端 400 报错
func TestCreateConnectTokenBadCSRF(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"token from header incorrect"}`))
	})
	_, err := CreateConnectToken(context.Background(), host, testCookie, "wrong-csrf", "a1", "u1")
	if err == nil {
		t.Fatal("want error, got nil")
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 APIError, got %v", err)
	}
}

// CreateConnectToken：缺 Referer 头时服务端 403（v3 实测现象）
func TestCreateConnectTokenForbiddenNoReferer(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") == "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Referer checking failed - no Referer"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"tok-1","value":"v"}`))
	})
	// 正常调用（带 Referer）应 201 成功；若客户端未带 Referer 会收到 403
	tok, err := CreateConnectToken(context.Background(), host, testCookie, "c", "a1", "u1")
	if err != nil {
		t.Fatalf("CreateConnectToken with Referer: %v", err)
	}
	if tok.ID != "tok-1" {
		t.Errorf("token id: got %q", tok.ID)
	}
}

// CreateConnectToken：401（Cookie 过期）
func TestCreateConnectTokenUnauthorized(t *testing.T) {
	host := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/core/auth/login/", http.StatusFound)
	})
	_, err := CreateConnectToken(context.Background(), host, testCookie, "c", "a1", "u1")
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusFound {
		t.Fatalf("want 302 APIError, got %v", err)
	}
}
