package jumpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// ---------- 页面解析 ----------

func TestExtractQRToken(t *testing.T) {
	page := `<script>var qrToken = "680f3566067b46789ad805ebddfbdcc4"; var loginStyle="10";</script>`
	if got := extractQRToken(page); got != "680f3566067b46789ad805ebddfbdcc4" {
		t.Errorf("extractQRToken: got %q", got)
	}
	if got := extractQRToken("<html></html>"); got != "" {
		t.Errorf("missing token: got %q", got)
	}
}

func TestExtractHiddenInputs(t *testing.T) {
	page := `<form id="redirectForm" method="post">
		<input type="hidden" name="execution" value="exec-1"/>
		<input type="hidden" name="flowId" value="flow-1"/>
		<input type="hidden" name="_eventId" value="submit"/>
		<input type="text" name="ignored" value="x"/>
	</form>`
	form := extractHiddenInputs(page)
	if form.Get("execution") != "exec-1" || form.Get("flowId") != "flow-1" {
		t.Fatalf("hidden inputs: %+v", form)
	}
	if form.Get("_eventId") != "submit" {
		t.Errorf("_eventId: %q", form.Get("_eventId"))
	}
	if form.Has("ignored") {
		t.Error("non-hidden input should be skipped")
	}
}

func TestExtractMFAOptions(t *testing.T) {
	html := `<select id="mfa-select" name="mfa_type">
		<option value="otp">OTP</option>
		<option value="sms" disabled>SMS</option>
		<option value="mfa_custom">Custom</option>
	</select>`
	opts := extractMFAOptions(html)
	if len(opts) != 2 {
		t.Fatalf("options: got %+v, want 2 (disabled excluded)", opts)
	}
	if opts[0].Type != "otp" || opts[0].Label != "OTP" {
		t.Errorf("option[0]: %+v", opts[0])
	}
	if opts[1].Type != "mfa_custom" {
		t.Errorf("option[1]: %+v", opts[1])
	}
}

func TestExtractLoginError(t *testing.T) {
	html := `<p class="help-block red-fonts">* 验证码错误</p>`
	if got := extractLoginError(html); !strings.Contains(got, "验证码错误") {
		t.Errorf("extractLoginError: got %q", got)
	}
	if got := extractLoginError("<html></html>"); got == "" {
		t.Error("want fallback message")
	}
}

// ---------- 登录流程（httptest 模拟 JumpServer + sso.zxxk.com，见设计文档附录 D V5） ----------

const ssoPage = `<!DOCTYPE html><html><body>
<form id="redirectForm" action="" method="post">
	<input type="hidden" name="execution" value="exec-1"/>
	<input type="hidden" name="flowId" value="flow-1"/>
	<input type="hidden" name="_eventId" value="submit"/>
</form>
<script type="text/javascript">
	var qrToken = "qr-token-1";
</script>
</body></html>`

const mfaPage = `<!DOCTYPE html><form id="mfa-form">
	<input type="hidden" name="csrfmiddlewaretoken" value="csrf-mfa">
	<select id="mfa-select" name="mfa_type"><option value="otp">OTP</option></select>
</form>`

// fakeSSO 模拟统一认证域。
type fakeSSO struct {
	t        *testing.T
	server   *httptest.Server
	business string

	mu           sync.Mutex
	pollVersions []string
	statuses     []string // 依次返回的扫码状态，用尽后返回最后一项
	silent       bool     // /login 直接回 ticket（SSO 会话有效）
	dologinMsg   string
	ticket       string
	activations  []string
}

func newFakeSSO(t *testing.T, business string) *fakeSSO {
	t.Helper()
	f := &fakeSSO{
		t:          t,
		business:   business,
		statuses:   []string{"LOGINING", "LOGINED"},
		dologinMsg: "登录成功!",
		ticket:     "ST-good",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "ssoid", Value: "sso-1", Path: "/"})
			if f.isSilent() {
				target := r.URL.Query().Get("service") + "?ticket=" + f.ticket
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(ssoPage))
			return
		}
		_ = r.ParseForm()
		if got := r.Form.Get("_eventId"); got != "scanCodeLogin" {
			t.Errorf("CAS form _eventId: got %q", got)
		}
		if got := r.Form.Get("execution"); got != "exec-1" {
			t.Errorf("CAS form execution: got %q", got)
		}
		http.Redirect(w, r, f.business+"/core/auth/cas/login/?ticket="+f.ticket, http.StatusFound)
	})
	mux.HandleFunc("/user/qrcode/qrcode-login/v2/content", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("service") == "" {
			t.Error("content request without service")
		}
		body := map[string]any{
			"status": 200,
			"data": map[string]any{
				"content": "https://sso.test/login?key=qr-key-1&type=qrcode-login",
				"queryToken": map[string]any{
					"token":   r.URL.Query().Get("token"),
					"version": 1,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/user/wechat-applet/logincheck", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.pollVersions = append(f.pollVersions, r.URL.Query().Get("version"))
		status := ""
		if len(f.statuses) > 0 {
			status = f.statuses[0]
			if len(f.statuses) > 1 {
				f.statuses = f.statuses[1:]
			}
		}
		f.mu.Unlock()
		var data any
		if status != "" {
			data = map[string]any{"status": status}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 200, "data": data})
	})
	mux.HandleFunc("/user/wechat-applet/dologin", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		msg := f.dologinMsg
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 200, "message": msg})
	})
	mux.HandleFunc("/user/set-activate-flag", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.activations = append(f.activations, r.Form.Get("loginInfo"))
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"status":200,"data":true}`))
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeSSO) isSilent() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.silent
}

func (f *fakeSSO) setStatuses(s ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = s
}

// fakeBiz 模拟业务侧（JumpServer）。
type fakeBiz struct {
	t          *testing.T
	server     *httptest.Server
	requireMFA bool
}

func newFakeBiz(t *testing.T, ssoURL func(service string) string) *fakeBiz {
	t.Helper()
	b := &fakeBiz{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/core/auth/cas/login/", func(w http.ResponseWriter, r *http.Request) {
		ticket := r.URL.Query().Get("ticket")
		if ticket == "" {
			service := "http://" + r.Host + "/core/auth/cas/login/"
			http.Redirect(w, r, ssoURL(service), http.StatusFound)
			return
		}
		if ticket != "ST-good" {
			// 票据无效：回首页但不种会话
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "jms_sessionid", Value: "sess-good", Path: "/"})
		http.Redirect(w, r, "/core/auth/login/guard/", http.StatusFound)
	})
	mux.HandleFunc("/core/auth/login/guard/", func(w http.ResponseWriter, r *http.Request) {
		if b.requireMFA {
			if c, err := r.Cookie("mfa_done"); err != nil || c.Value != "1" {
				http.Redirect(w, r, "/core/auth/login/mfa/", http.StatusFound)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/core/auth/login/mfa/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(mfaPage))
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("code") == "123456" {
			http.SetCookie(w, &http.Cookie{Name: "mfa_done", Value: "1", Path: "/"})
			http.Redirect(w, r, "/core/auth/login/guard/?_=mfa_ok", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`<p class="help-block red-fonts">验证码错误</p>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 首页渲染带 CSRF 的页面：Django 在此种下 jms_csrftoken
		http.SetCookie(w, &http.Cookie{Name: "jms_csrftoken", Value: "csrf-1", Path: "/"})
		_, _ = w.Write([]byte("<html>home</html>"))
	})
	b.server = httptest.NewServer(mux)
	t.Cleanup(b.server.Close)
	return b
}

// fixture 搭一套「业务 + SSO」测试环境。
func fixture(t *testing.T) (*fakeBiz, *fakeSSO) {
	t.Helper()
	var sso *fakeSSO
	biz := newFakeBiz(t, func(service string) string {
		return sso.server.URL + "/login?service=" + url.QueryEscape(service)
	})
	sso = newFakeSSO(t, biz.server.URL)
	return biz, sso
}

// pollUntilDone 轮询到登录完成（或致命错误），最多 maxPolls 次。
func pollUntilDone(t *testing.T, flow *LoginFlow) *LoginOutcome {
	t.Helper()
	for i := 0; i < 20; i++ {
		_, outcome, err := flow.PollScan(context.Background())
		if err != nil {
			t.Fatalf("PollScan: %v", err)
		}
		if outcome != nil {
			return outcome
		}
	}
	t.Fatal("polling did not finish")
	return nil
}

func TestLoginQRSuccess(t *testing.T) {
	biz, sso := fixture(t)
	flow, outcome, err := NewLoginFlow(context.Background(), biz.server.URL, "")
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	if !outcome.NeedQR || outcome.QR == nil {
		t.Fatalf("want QR challenge, got %+v", outcome)
	}
	if !strings.Contains(outcome.QR.Content, "qr-key-1") {
		t.Errorf("QR content: %q", outcome.QR.Content)
	}
	if flow.Service() == "" {
		t.Error("service not discovered")
	}

	final := pollUntilDone(t, flow)
	if !strings.Contains(final.Cookie, "jms_sessionid=sess-good") {
		t.Errorf("business cookie: %q", final.Cookie)
	}
	if !strings.Contains(final.Cookie, "jms_csrftoken=csrf-1") {
		t.Errorf("csrf cookie missing (landing page not consumed): %q", final.Cookie)
	}
	if !strings.Contains(final.SSOCookie, "ssoid=sso-1") {
		t.Errorf("sso cookie: %q", final.SSOCookie)
	}
	// 轮询版本自增：1、2
	if got := sso.pollVersions; len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Errorf("poll versions: %v", got)
	}
}

func TestLoginSilentTicket(t *testing.T) {
	biz, sso := fixture(t)
	sso.mu.Lock()
	sso.silent = true
	sso.mu.Unlock()

	_, outcome, err := NewLoginFlow(context.Background(), biz.server.URL, "ssoid=sso-1")
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	if outcome.NeedQR {
		t.Fatal("valid SSO session should skip QR")
	}
	if !strings.Contains(outcome.Cookie, "jms_sessionid=sess-good") {
		t.Errorf("cookie: %q", outcome.Cookie)
	}
}

func TestLoginMFA(t *testing.T) {
	biz, _ := fixture(t)
	biz.requireMFA = true

	flow, outcome, err := NewLoginFlow(context.Background(), biz.server.URL, "")
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	if !outcome.NeedQR {
		t.Fatalf("want QR, got %+v", outcome)
	}
	outcome = pollUntilDone(t, flow)
	if !outcome.NeedMFA {
		t.Fatalf("want MFA challenge, got %+v", outcome)
	}
	if outcome.Prompt.DefaultType() != "otp" {
		t.Errorf("mfa default type: %q", outcome.Prompt.DefaultType())
	}

	if _, err := flow.SubmitMFA(context.Background(), "000000", "otp"); err == nil {
		t.Fatal("want bad MFA error")
	} else {
		var le *LoginError
		if !errors.As(err, &le) || le.Kind != LoginErrBadMFA {
			t.Errorf("want LoginErrBadMFA, got %v", err)
		}
	}

	final, err := flow.SubmitMFA(context.Background(), "123456", "otp")
	if err != nil {
		t.Fatalf("SubmitMFA: %v", err)
	}
	if final.NeedMFA {
		t.Fatal("MFA should be done")
	}
	if !strings.Contains(final.Cookie, "mfa_done=1") || !strings.Contains(final.Cookie, "jms_sessionid=sess-good") {
		t.Errorf("final cookie: %q", final.Cookie)
	}
}

func TestLoginPrivacyAgree(t *testing.T) {
	biz, sso := fixture(t)
	sso.mu.Lock()
	sso.dologinMsg = "同意_privacy-info"
	sso.mu.Unlock()

	flow, outcome, err := NewLoginFlow(context.Background(), biz.server.URL, "")
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	if !outcome.NeedQR {
		t.Fatalf("want QR, got %+v", outcome)
	}
	final := pollUntilDone(t, flow)
	if !strings.Contains(final.Cookie, "jms_sessionid=sess-good") {
		t.Errorf("cookie: %q", final.Cookie)
	}
	sso.mu.Lock()
	acts := append([]string(nil), sso.activations...)
	sso.mu.Unlock()
	if len(acts) != 1 || acts[0] != "同意" {
		t.Errorf("activate flag calls: %v", acts)
	}
}

func TestLoginScanStatusErrors(t *testing.T) {
	cases := []struct {
		status string
		kind   LoginErrorKind
	}{
		{"QUIT_LOGIN", LoginErrScanCancelled},
		{"EXPIRED", LoginErrQRExpired},
		{"ACCOUNT_BIND", LoginErrAccountBind},
	}
	for _, c := range cases {
		t.Run(c.status, func(t *testing.T) {
			biz, sso := fixture(t)
			sso.setStatuses(c.status)
			flow, outcome, err := NewLoginFlow(context.Background(), biz.server.URL, "")
			if err != nil {
				t.Fatalf("NewLoginFlow: %v", err)
			}
			if !outcome.NeedQR {
				t.Fatalf("want QR, got %+v", outcome)
			}
			_, _, err = flow.PollScan(context.Background())
			var le *LoginError
			if !errors.As(err, &le) || le.Kind != c.kind {
				t.Fatalf("want kind %d, got %v", c.kind, err)
			}
		})
	}
}

// 登录页缺少执行上下文：给出可操作的错误，不静默失败。
func TestLoginPageStructureChanged(t *testing.T) {
	ssoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><script>var qrToken = "t";</script></html>`))
	}))
	defer ssoSrv.Close()
	biz := newFakeBiz(t, func(service string) string {
		return ssoSrv.URL + "/login?service=" + url.QueryEscape(service)
	})
	if _, _, err := NewLoginFlow(context.Background(), biz.server.URL, ""); err == nil ||
		!strings.Contains(err.Error(), "execution") {
		t.Fatalf("want execution error, got %v", err)
	}
}

// Cookie 序列化按域隔离：业务会话与 SSO 会话分成两串，
// 不把 SSO 域 Cookie 随业务请求一起发出（生产两个域名不同，
// jar 自行隔离；测试里两个 httptest 服务同主机不同端口，
// 而 Cookie 不区分端口，故单独用两个域名验证）。
func TestSerializeCookiesPerDomain(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &LoginFlow{jar: jar, host: "https://biz.example.com", ssoBase: "https://sso.example.com"}
	f.seedCookies(f.host, "jms_sessionid=a; jms_csrftoken=b")
	f.seedCookies(f.ssoBase, "ssoid=c")

	biz := f.serializeCookies(f.host)
	if !strings.Contains(biz, "jms_sessionid=a") || !strings.Contains(biz, "jms_csrftoken=b") {
		t.Errorf("business cookie: %q", biz)
	}
	if strings.Contains(biz, "ssoid=") {
		t.Errorf("SSO cookie leaked into business cookie: %q", biz)
	}
	sso := f.serializeCookies(f.ssoBase)
	if !strings.Contains(sso, "ssoid=c") || strings.Contains(sso, "jms_sessionid") {
		t.Errorf("sso cookie: %q", sso)
	}
}

func TestLoginNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	host := srv.URL
	srv.Close()
	if _, _, err := NewLoginFlow(context.Background(), host, ""); err == nil {
		t.Fatal("want network error, got nil")
	}
}

// 调试输出脱敏：票据/令牌类查询参数不得原样打印。
func TestSafeURLRedactsSecrets(t *testing.T) {
	u, err := url.Parse("https://jumpserver.xkw.com/core/auth/cas/login/?ticket=ST-123-secret&token=tok&key=k&next=%2F")
	if err != nil {
		t.Fatal(err)
	}
	got := safeURL(u)
	for _, secret := range []string{"ST-123-secret", "token=tok", "key=k"} {
		if strings.Contains(got, secret) {
			t.Errorf("secret leaked in trace: %s", got)
		}
	}
	if !strings.Contains(got, "next=%2F") {
		t.Errorf("harmless param dropped: %s", got)
	}
}

// cookieNames 只返回字段名，不含值。
func TestCookieNames(t *testing.T) {
	got := cookieNames("jms_sessionid=secret-value; jms_csrftoken=tok")
	if strings.Contains(got, "secret-value") || strings.Contains(got, "=tok") {
		t.Errorf("values leaked: %s", got)
	}
	if got != "jms_sessionid, jms_csrftoken" {
		t.Errorf("cookieNames: %q", got)
	}
	if got := cookieNames(""); got != "（空）" {
		t.Errorf("empty: %q", got)
	}
}
