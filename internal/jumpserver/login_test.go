package jumpserver

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------- 密码加密（与前端 session-encrypt.js / 后端 common/utils/crypto.py 对齐） ----------

// mustRSA 生成 2048 位密钥对，返回私钥与 jms_public_key 形态的公钥
// （base64(PEM PUBLIC KEY)）。
func mustRSA(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, base64.StdEncoding.EncodeToString(pubPEM)
}

// 加密结果可用私钥还原：确认格式 "{rsa}:{aes}" 与算法和后端
// common/utils/crypto.py decrypt_password 一致（RSA PKCS1v1.5 + AES/ECB/ZeroPad）
func TestEncryptPasswordRoundTrip(t *testing.T) {
	priv, pubB64 := mustRSA(t)
	password := "My-P@ssw0rd!密码"
	enc, err := encryptPassword(pubB64, password)
	if err != nil {
		t.Fatalf("encryptPassword: %v", err)
	}
	parts := strings.Split(enc, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		t.Fatalf("cipher format: %q", enc)
	}
	// RSA 还原 AES key（对应 rsa_decrypt_by_session_pkey）
	keyCipher, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, priv, keyCipher)
	if err != nil {
		t.Fatalf("rsa decrypt: %v", err)
	}
	// AES/ECB/ZeroPadding 解密（对应 AESCrypto.to_16 + rstrip(b'\0')）
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	key16 := make([]byte, 16)
	copy(key16, aesKey) // 与前端 fillKey / 后端 padding_key 一致：补零到 16 字节
	block, err := aes.NewCipher(key16)
	if err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(pt[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	pt = []byte(strings.TrimRight(string(pt), "\x00"))
	if string(pt) != password {
		t.Errorf("round trip: got %q want %q", pt, password)
	}
}

// AES/ECB/ZeroPadding：长度恰为 16 整数倍时不追加填充块
// （与 CryptoJS pad.ZeroPadding / 后端 to_16 行为一致）
func TestAESZeroPadBlockBoundary(t *testing.T) {
	for _, plain := range []string{"0123456789abcdef", "0123456789abcde", ""} {
		enc, err := aesECBZeroPadEncrypt("0123456789", plain)
		if err != nil {
			t.Fatal(err)
		}
		ct, _ := base64.StdEncoding.DecodeString(enc)
		want := (len(plain) + 15) / 16 * 16
		if len(ct) != want {
			t.Errorf("plain %d bytes: cipher %d, want %d", len(plain), len(ct), want)
		}
	}
}

// parseRSAPublicKey：兼容 PEM 与裸 DER（PKIX）两种 jms_public_key 形态
func TestParseRSAPublicKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for _, b64 := range []string{
		base64.StdEncoding.EncodeToString(pemBytes),
		base64.StdEncoding.EncodeToString(der),
	} {
		pub, err := parseRSAPublicKey(b64)
		if err != nil {
			t.Fatalf("parseRSAPublicKey(%s...): %v", b64[:16], err)
		}
		if pub.N == nil || pub.E == 0 {
			t.Error("bad pubkey")
		}
	}
}

func TestParseRSAPublicKeyInvalid(t *testing.T) {
	if _, err := parseRSAPublicKey("bm90LWEta2V5"); err == nil {
		t.Error("want error for invalid key")
	}
}

// ---------- 页面解析（正则容错） ----------

func TestExtractCSRF(t *testing.T) {
	html := `<input type="hidden" name="csrfmiddlewaretoken" value="tok-123">`
	if got := extractCSRF(html); got != "tok-123" {
		t.Errorf("extractCSRF: got %q", got)
	}
	if got := extractCSRF("<html>no token</html>"); got != "" {
		t.Errorf("missing token: got %q", got)
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
	html := `<p class="help-block red-fonts">* 您输入的用户名或密码不正确，请重新输入。</p>`
	got := extractLoginError(html)
	if !strings.Contains(got, "用户名或密码不正确") {
		t.Errorf("extractLoginError: got %q", got)
	}
	// 无错误块：返回默认提示
	if got := extractLoginError("<html></html>"); got == "" {
		t.Error("want fallback message")
	}
}

func TestHasCaptchaField(t *testing.T) {
	if !hasCaptchaField(`<input name="captcha">`) {
		t.Error("captcha field not detected")
	}
	if !hasCaptchaField(`<input name="challenge">`) {
		t.Error("challenge field not detected")
	}
	if hasCaptchaField(`<form id="login-form">`) {
		t.Error("false positive")
	}
}

func TestIsThirdPartyPath(t *testing.T) {
	for _, loc := range []string{
		"/core/auth/wecom/qr/login/",
		"https://idp.example.com/openid/authorize",
		"/core/auth/cas/cas-login",
		"/core/auth/saml2/saml2-login/",
		"/core/auth/oauth2/login/",
	} {
		if !isThirdPartyPath(loc) {
			t.Errorf("third party path not detected: %s", loc)
		}
	}
	if isThirdPartyPath("/") || isThirdPartyPath("/core/auth/login/mfa/") {
		t.Error("false positive on normal path")
	}
}

// ---------- 登录流程（httptest 模拟 JumpServer v3，见设计文档附录 D V5） ----------

type fakeLoginCfg struct {
	requireMFA      bool // guard 分流到 MFA 页
	failLogin       bool // POST login 重渲染错误页（账号密码错）
	failWithCaptcha bool // 错误页带图形验证码字段
	failMFA         bool // POST mfa 重渲染错误页（验证码错）
	thirdParty      bool // POST login 302 到扫码登录
	gmssl           bool // 种 jms_gm_ssl=1
}

// fakeLoginServer 模拟登录流程：GET login(200+种 csrf/公钥/sessionid) →
// POST login(302 guard 或错误) → GET guard(302 mfa 或 /) →
// GET mfa(200+option) → POST mfa(302 guard 或错误)。同时记录提交的
// password 字段供测试断言加密格式。
func fakeLoginServer(t *testing.T, cfg fakeLoginCfg) (*httptest.Server, *string) {
	t.Helper()
	_, pubB64 := mustRSA(t)
	var mu sync.Mutex
	submittedPassword := ""
	setPassword := func(p string) {
		mu.Lock()
		submittedPassword = p
		mu.Unlock()
	}

	loginHTML := func(extra string) string {
		return `<!DOCTYPE html><form id="login-form"><input type="hidden" name="csrfmiddlewaretoken" value="csrf-1">` + extra + `</form>`
	}
	mfaHTML := `<!DOCTYPE html><form id="mfa-form"><input type="hidden" name="csrfmiddlewaretoken" value="csrf-mfa"><select id="mfa-select" name="mfa_type"><option value="otp">OTP</option><option value="sms" disabled>SMS</option></select></form>`
	errorHTML := `<p class="help-block red-fonts">验证码错误</p>`

	mux := http.NewServeMux()
	mux.HandleFunc("/core/auth/login/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if cfg.gmssl {
				http.SetCookie(w, &http.Cookie{Name: "jms_gm_ssl", Value: "1", Path: "/"})
			}
			http.SetCookie(w, &http.Cookie{Name: "jms_csrftoken", Value: "csrf-1", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "jms_public_key", Value: pubB64, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "jms_sessionid", Value: "anon", Path: "/"})
			_, _ = w.Write([]byte(loginHTML("")))
			return
		}
		// POST
		_ = r.ParseForm()
		pwd := r.Form.Get("password")
		setPassword(pwd)
		if !strings.Contains(pwd, ":") {
			t.Errorf("password not encrypted: %q", pwd)
		}
		if strings.Contains(pwd, "real-pass") {
			t.Errorf("plaintext password leaked in form: %q", pwd)
		}
		switch {
		case cfg.thirdParty:
			http.Redirect(w, r, "/core/auth/wecom/qr/login/", http.StatusFound)
		case cfg.failWithCaptcha:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(loginHTML(`<input name="captcha">`)))
		case cfg.failLogin:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(loginHTML(`<p class="help-block red-fonts">用户名或密码错误</p>`)))
		default:
			http.SetCookie(w, &http.Cookie{Name: "jms_sessionid", Value: "sess2", Path: "/"})
			http.Redirect(w, r, "/core/auth/login/guard/?_=ok", http.StatusFound)
		}
	})
	mux.HandleFunc("/core/auth/login/guard/", func(w http.ResponseWriter, r *http.Request) {
		if cfg.requireMFA {
			if c, err := r.Cookie("mfa_done"); err != nil || c.Value != "1" {
				http.Redirect(w, r, "/core/auth/login/mfa/", http.StatusFound)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/core/auth/login/mfa/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(mfaHTML))
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("code") == "123456" {
			http.SetCookie(w, &http.Cookie{Name: "mfa_done", Value: "1", Path: "/"})
			http.Redirect(w, r, "/core/auth/login/guard/?_=mfa_ok", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		if cfg.failMFA {
			_, _ = w.Write([]byte(`<form><input type="hidden" name="csrfmiddlewaretoken" value="csrf-mfa">` + errorHTML + `</form>`))
		} else {
			_, _ = w.Write([]byte(mfaHTML))
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &submittedPassword
}

func TestLoginFlowSuccessNoMFA(t *testing.T) {
	srv, submitted := fakeLoginServer(t, fakeLoginCfg{})
	flow, err := NewLoginFlow(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	outcome, err := flow.SubmitCredentials(context.Background(), "alice", "real-pass")
	if err != nil {
		t.Fatalf("SubmitCredentials: %v", err)
	}
	if outcome.NeedMFA {
		t.Fatal("unexpected MFA challenge")
	}
	if !strings.Contains(outcome.Cookie, "jms_sessionid=sess2") {
		t.Errorf("cookie missing session: %q", outcome.Cookie)
	}
	if !strings.Contains(outcome.Cookie, "jms_csrftoken=csrf-1") {
		t.Errorf("cookie missing csrf: %q", outcome.Cookie)
	}
	if !strings.Contains(*submitted, ":") {
		t.Errorf("submitted password not in encrypted format: %q", *submitted)
	}
}

func TestLoginFlowMFA(t *testing.T) {
	srv, _ := fakeLoginServer(t, fakeLoginCfg{requireMFA: true})
	flow, err := NewLoginFlow(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	outcome, err := flow.SubmitCredentials(context.Background(), "alice", "real-pass")
	if err != nil {
		t.Fatalf("SubmitCredentials: %v", err)
	}
	if !outcome.NeedMFA {
		t.Fatal("want MFA challenge")
	}
	if outcome.Prompt == nil || len(outcome.Prompt.Options) == 0 {
		t.Fatalf("want MFA options, got %+v", outcome.Prompt)
	}
	if outcome.Prompt.Options[0].Type != "otp" || outcome.Prompt.Options[0].Label != "OTP" {
		t.Errorf("MFA option[0]: %+v", outcome.Prompt.Options[0])
	}
	if outcome.Prompt.DefaultType() != "otp" {
		t.Errorf("default type: %q", outcome.Prompt.DefaultType())
	}
	// 验证码正确 → 登录完成
	final, err := flow.SubmitMFA(context.Background(), "123456", "otp")
	if err != nil {
		t.Fatalf("SubmitMFA: %v", err)
	}
	if final.NeedMFA {
		t.Fatal("MFA should be done")
	}
	if !strings.Contains(final.Cookie, "jms_sessionid=sess2") || !strings.Contains(final.Cookie, "mfa_done=1") {
		t.Errorf("final cookie: %q", final.Cookie)
	}
}

func TestLoginFlowBadMFA(t *testing.T) {
	srv, _ := fakeLoginServer(t, fakeLoginCfg{requireMFA: true, failMFA: true})
	flow, err := NewLoginFlow(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	if _, err := flow.SubmitCredentials(context.Background(), "alice", "real-pass"); err != nil {
		t.Fatalf("SubmitCredentials: %v", err)
	}
	_, err = flow.SubmitMFA(context.Background(), "000000", "otp")
	var le *LoginError
	if !errors.As(err, &le) || le.Kind != LoginErrBadMFA {
		t.Fatalf("want LoginErrBadMFA, got %v", err)
	}
	if !strings.Contains(err.Error(), "验证码错误") {
		t.Errorf("message: %v", err)
	}
}

func TestLoginFlowBadCredentials(t *testing.T) {
	srv, _ := fakeLoginServer(t, fakeLoginCfg{failLogin: true})
	flow, err := NewLoginFlow(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	_, err = flow.SubmitCredentials(context.Background(), "alice", "wrong-pass")
	var le *LoginError
	if !errors.As(err, &le) || le.Kind != LoginErrBadCredentials {
		t.Fatalf("want LoginErrBadCredentials, got %v", err)
	}
	if !strings.Contains(err.Error(), "用户名或密码错误") {
		t.Errorf("message: %v", err)
	}
}

func TestLoginFlowCaptcha(t *testing.T) {
	srv, _ := fakeLoginServer(t, fakeLoginCfg{failWithCaptcha: true})
	flow, err := NewLoginFlow(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	_, err = flow.SubmitCredentials(context.Background(), "alice", "wrong-pass")
	var le *LoginError
	if !errors.As(err, &le) || le.Kind != LoginErrCaptcha {
		t.Fatalf("want LoginErrCaptcha, got %v", err)
	}
}

func TestLoginFlowThirdParty(t *testing.T) {
	srv, _ := fakeLoginServer(t, fakeLoginCfg{thirdParty: true})
	flow, err := NewLoginFlow(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("NewLoginFlow: %v", err)
	}
	_, err = flow.SubmitCredentials(context.Background(), "alice", "real-pass")
	var le *LoginError
	if !errors.As(err, &le) || le.Kind != LoginErrThirdParty {
		t.Fatalf("want LoginErrThirdParty, got %v", err)
	}
}

func TestLoginFlowGMSSL(t *testing.T) {
	srv, _ := fakeLoginServer(t, fakeLoginCfg{gmssl: true})
	_, err := NewLoginFlow(context.Background(), srv.URL)
	var le *LoginError
	if !errors.As(err, &le) || le.Kind != LoginErrGMSSL {
		t.Fatalf("want LoginErrGMSSL, got %v", err)
	}
}

func TestLoginFlowNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	host := srv.URL
	srv.Close()
	_, err := NewLoginFlow(context.Background(), host)
	if err == nil {
		t.Fatal("want network error, got nil")
	}
	var le *LoginError
	if errors.As(err, &le) {
		t.Errorf("network error should not be LoginError: %v", err)
	}
}
