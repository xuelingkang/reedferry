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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

// 登录流程：纯 HTTP 客户端完成 JumpServer 账号密码登录（可选 2FA），
// 换取会话 Cookie 供后续 API/WS 使用。约束：不引入浏览器/无头浏览器，
// 账号密码与验证码仅存于本次调用栈，不落盘、不打印、不写日志。
//
// 流程为 jumpserver.xkw.com（JumpServer v3.x）实探结论（设计文档附录 D V5）：
//   - GET /core/auth/login/ 返回 200，页面含 csrfmiddlewaretoken，响应种下
//     jms_csrftoken / jms_public_key / jms_sessionid 等 Cookie；
//   - POST 表单（csrfmiddlewaretoken/username/password/auto_login）成功后
//     302 到 /core/auth/login/guard/，guard 再 302 分流：需要 2FA 时跳
//     /core/auth/login/mfa/（字段 code + mfa_type），否则直达业务首页；
//   - MFA 页 GET 需先有会话（guard 302 前已写入 user_id/auth_password）；
//   - 密码加密与前端 session-encrypt.js 一致：随机 AES key 经 AES/ECB/
//     ZeroPadding 加密密码，AES key 用 RSA 公钥（PKCS1 v1.5）加密，
//     输出 "{rsaKeyCipher}:{aesPasswordCipher}"（均 base64）。

const (
	loginPath      = "/core/auth/login/"
	loginGuardPath = "/core/auth/login/guard/"
	loginMFAPath   = "/core/auth/login/mfa/"
)

// LoginErrorKind 登录失败分类，CLI 层据此给出针对性提示。
type LoginErrorKind int

const (
	// LoginErrOther 未分类错误。
	LoginErrOther LoginErrorKind = iota
	// LoginErrBadCredentials 账号或密码错误。
	LoginErrBadCredentials
	// LoginErrBadMFA 2FA 动态验证码错误。
	LoginErrBadMFA
	// LoginErrCaptcha 触发图形验证码，程序内无法自动识别。
	LoginErrCaptcha
	// LoginErrThirdParty 环境配置了扫码/第三方登录，无法纯 HTTP 完成。
	LoginErrThirdParty
	// LoginErrGMSSL 环境启用国密（SM2/SM4）密码加密，当前版本不支持。
	LoginErrGMSSL
)

// LoginError 携带分类的登录错误。
type LoginError struct {
	Kind LoginErrorKind
	Msg  string
}

func (e *LoginError) Error() string { return e.Msg }

// MFAOption 描述 MFA 页可用的 2FA 验证方式（对应 <select name="mfa_type"> 的 option）。
type MFAOption struct {
	Type  string // 提交值（如 otp / sms）
	Label string // 展示名（如 OTP / SMS）
}

// MFAPrompt 是 2FA 挑战信息（NeedMFA 时由 CLI 层提示用户输入动态验证码）。
type MFAPrompt struct {
	Options []MFAOption
}

// DefaultType 返回默认 MFA 方式（第一个可用 option，与浏览器默认选中一致）。
func (p *MFAPrompt) DefaultType() string {
	if len(p.Options) == 0 {
		return ""
	}
	return p.Options[0].Type
}

// Describe 返回面向用户的 MFA 方式描述（如 "OTP / SMS"）。
func (p *MFAPrompt) Describe() string {
	labels := make([]string, 0, len(p.Options))
	for _, o := range p.Options {
		labels = append(labels, o.Label)
	}
	return strings.Join(labels, " / ")
}

// LoginOutcome 是登录一步的结果：未完成时 NeedMFA 为 true（需继续
// SubmitMFA）；完成后 Cookie 为可写入配置文件的会话 Cookie 串。
type LoginOutcome struct {
	Cookie  string     // 登录完成后的会话 Cookie 串（未完成时为空）
	NeedMFA bool       // 需要用户输入 2FA 动态验证码
	Prompt  *MFAPrompt // NeedMFA 时的挑战信息
}

// LoginFlow 驱动一次 JumpServer 登录：GET 登录页 → 提交凭据 →（可选 MFA）
// → 提取 Cookie。全程使用同一 Cookie Jar 保存服务端下发的会话；
// 302 链手动跟随（禁用自动重定向）以识别 MFA 分流。
type LoginFlow struct {
	host string
	jar  *cookiejar.Jar
	http *http.Client

	loginURL string
	mfaURL   string

	csrf string // 当前页面的 csrfmiddlewaretoken（登录页或 MFA 页）
}

// NewLoginFlow 打开登录页并初始化流程（收集 csrf 与加密公钥等 Cookie）。
// 网络不可达等错误直接返回；检测到国密方案（jms_gm_ssl=1）时返回
// LoginErrGMSSL（本环境实测未启用，见附录 D V5）。
func NewLoginFlow(ctx context.Context, host string) (*LoginFlow, error) {
	base := strings.TrimSuffix(host, "/")
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("初始化 Cookie Jar 失败：%w", err)
	}
	client := &http.Client{
		Timeout: apiTimeout,
		Jar:     jar, // 会话 Cookie 由服务端种入 Jar，登录完成后序列化写入配置
		// 302 链手动跟随：登录成功的跳转（guard → mfa/首页）需要逐跳识别
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	f := &LoginFlow{
		host:     base,
		jar:      jar,
		http:     client,
		loginURL: base + loginPath,
		mfaURL:   base + loginMFAPath,
	}
	if err := f.openLoginPage(ctx); err != nil {
		return nil, err
	}
	return f, nil
}

// openLoginPage 拉取登录页：提取 csrf 令牌并探测加密方案 Cookie。
func (f *LoginFlow) openLoginPage(ctx context.Context) error {
	raw, resp, err := f.get(ctx, f.loginURL, "")
	if err != nil {
		return fmt.Errorf("打开登录页失败（网络不可达或服务异常）：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("打开登录页失败：HTTP %d", resp.StatusCode)
	}
	f.csrf = extractCSRF(string(raw))
	if f.csrf == "" {
		return errors.New("登录页未找到 csrf 令牌（页面结构变化？），请改用浏览器登录后复制 Cookie")
	}
	// 国密方案检测：实测环境不种 jms_gm_ssl；启用国密的环境需扩展 SM2/SM4 支持
	if f.cookieValue("jms_gm_ssl") == "1" {
		return &LoginError{Kind: LoginErrGMSSL, Msg: "该环境启用了国密（SM2/SM4）密码加密，当前版本不支持；请改用浏览器登录后复制 Cookie，或由维护者扩展国密支持"}
	}
	return nil
}

// SubmitCredentials 提交账号密码（密码按 session-encrypt.js 协议加密）。
// 返回：NeedMFA=true 表示进入 2FA 挑战；否则登录完成，Cookie 可直接写入配置。
func (f *LoginFlow) SubmitCredentials(ctx context.Context, username, password string) (*LoginOutcome, error) {
	pubKey := f.cookieValue("jms_public_key")
	if pubKey == "" {
		return nil, errors.New("登录页未下发加密公钥（jms_public_key），无法加密密码；请改用浏览器登录后复制 Cookie")
	}
	enc, err := encryptPassword(pubKey, password)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("csrfmiddlewaretoken", f.csrf)
	form.Set("username", username)
	form.Set("password", enc)
	form.Set("auto_login", "on") // 等同浏览器勾选"记住我"，会话有效期更长
	raw, resp, err := f.postForm(ctx, f.loginURL, form, f.loginURL)
	if err != nil {
		return nil, fmt.Errorf("提交登录失败（网络不可达或服务异常）：%w", err)
	}
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		return f.followGuard(ctx, resp.Header.Get("Location"))
	case http.StatusOK:
		// 重渲染登录页：区分图形验证码（无法自动处理）与账号密码错误
		if hasCaptchaField(string(raw)) {
			return nil, &LoginError{Kind: LoginErrCaptcha, Msg: "登录连续失败触发图形验证码，程序内无法自动识别；请稍后重试，或改用浏览器登录后复制 Cookie"}
		}
		return nil, &LoginError{Kind: LoginErrBadCredentials, Msg: "账号或密码错误：" + extractLoginError(string(raw))}
	default:
		return nil, fmt.Errorf("登录失败：HTTP %d", resp.StatusCode)
	}
}

// SubmitMFA 提交 2FA 动态验证码（code + mfa_type，取自 MFAPrompt）。
// 成功后返回登录完成（Cookie 可写入配置）；验证码错误返回 LoginErrBadMFA。
func (f *LoginFlow) SubmitMFA(ctx context.Context, code, mfaType string) (*LoginOutcome, error) {
	if code == "" {
		return nil, errors.New("MFA 验证码为空，已取消")
	}
	form := url.Values{}
	form.Set("csrfmiddlewaretoken", f.csrf)
	form.Set("code", code)
	form.Set("mfa_type", mfaType)
	raw, resp, err := f.postForm(ctx, f.mfaURL, form, f.mfaURL)
	if err != nil {
		return nil, fmt.Errorf("提交 MFA 验证码失败（网络不可达或服务异常）：%w", err)
	}
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		return f.followGuard(ctx, resp.Header.Get("Location"))
	case http.StatusOK:
		return nil, &LoginError{Kind: LoginErrBadMFA, Msg: "JumpServer 2FA 动态验证码错误：" + extractLoginError(string(raw))}
	default:
		return nil, fmt.Errorf("MFA 校验失败：HTTP %d", resp.StatusCode)
	}
}

// followGuard 沿 guard 302 链走到终态：直达业务首页则登录完成（提取 Cookie），
// 跳 MFA 页则进入 2FA 挑战，跳第三方/扫码则返回 LoginErrThirdParty。
// 302 链最多跟随 6 跳防死循环。
func (f *LoginFlow) followGuard(ctx context.Context, location string) (*LoginOutcome, error) {
	for i := 0; i < 6; i++ {
		switch {
		case strings.Contains(location, loginMFAPath):
			return f.enterMFA(ctx)
		case strings.Contains(location, loginGuardPath):
			_, resp, err := f.get(ctx, f.resolve(location), f.loginURL)
			if err != nil {
				return nil, fmt.Errorf("跟随登录跳转失败：%w", err)
			}
			if resp.StatusCode < 300 || resp.StatusCode >= 400 {
				return nil, fmt.Errorf("登录跳转异常：HTTP %d（%s）", resp.StatusCode, location)
			}
			location = resp.Header.Get("Location")
		case isThirdPartyPath(location):
			return nil, &LoginError{Kind: LoginErrThirdParty, Msg: "该环境配置了扫码/第三方登录（企业微信/钉钉/飞书/OpenID/CAS/SAML2/OAuth2 等），程序内无法完成；请用浏览器登录后复制 Cookie，粘贴到配置文件"}
		case strings.Contains(location, loginPath):
			// 302 回登录页（如 guard 的 session_empty 分支）：会话未建立，登录实际失败
			return nil, errors.New("登录跳转回登录页（会话未建立），可能因登录窗口过期；请重新运行 reedferry 再试")
		default:
			// 直达业务首页：登录完成，会话 Cookie 已由服务端种入 Jar
			return &LoginOutcome{Cookie: f.serializeCookie()}, nil
		}
	}
	return nil, errors.New("登录跳转链异常（超过 6 次重定向），请改用浏览器登录后复制 Cookie")
}

// enterMFA 进入 2FA 挑战：拉取 MFA 页，收集 csrf 令牌与可用验证方式。
func (f *LoginFlow) enterMFA(ctx context.Context) (*LoginOutcome, error) {
	raw, resp, err := f.get(ctx, f.mfaURL, f.loginURL)
	if err != nil {
		return nil, fmt.Errorf("打开 MFA 页失败（网络不可达或服务异常）：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return nil, fmt.Errorf("MFA 会话异常（HTTP %d 跳转 %s），请重新登录", resp.StatusCode, resp.Header.Get("Location"))
		}
		return nil, fmt.Errorf("打开 MFA 页失败：HTTP %d", resp.StatusCode)
	}
	f.csrf = extractCSRF(string(raw))
	options := extractMFAOptions(string(raw))
	if len(options) == 0 {
		return nil, errors.New("MFA 页未解析到可用的验证方式（页面结构变化？），请改用浏览器登录后复制 Cookie")
	}
	return &LoginOutcome{NeedMFA: true, Prompt: &MFAPrompt{Options: options}}, nil
}

// get 执行 GET（禁自动重定向），完整读取响应体后返回。
func (f *LoginFlow) get(ctx context.Context, u, referer string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("构造请求失败：%w", err)
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("读取响应失败：%w", err)
	}
	return raw, resp, nil
}

// postForm 执行表单 POST（禁自动重定向），完整读取响应体后返回。
func (f *LoginFlow) postForm(ctx context.Context, u string, form url.Values, referer string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("构造请求失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", referer)
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("读取响应失败：%w", err)
	}
	return raw, resp, nil
}

// resolve 将（可能相对的）Location 解析为绝对 URL。
func (f *LoginFlow) resolve(location string) string {
	u, err := url.Parse(location)
	if err != nil || u.IsAbs() {
		return location
	}
	base, _ := url.Parse(f.host + "/")
	return base.ResolveReference(u).String()
}

// serializeCookie 将 Jar 中的会话 Cookie 序列化为 "k=v; k2=v2" 配置串。
func (f *LoginFlow) serializeCookie() string {
	u, _ := url.Parse(f.loginURL)
	parts := make([]string, 0, 8)
	for _, c := range f.jar.Cookies(u) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// cookieValue 返回 Jar 中指定名字的 Cookie 值（不存在返回空串）。
func (f *LoginFlow) cookieValue(name string) string {
	u, _ := url.Parse(f.loginURL)
	for _, c := range f.jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// ---------- 密码加密（与前端 session-encrypt.js / 后端 common/utils/crypto.py 对齐） ----------

// encryptPassword 按前端逻辑加密密码：
// 随机 AES key 经 AES/ECB/ZeroPadding 加密密码；AES key 用 RSA 公钥
// （PKCS1 v1.5）加密；输出 "{rsaKeyCipher}:{aesPasswordCipher}"（均 base64）。
func encryptPassword(publicKeyB64, password string) (string, error) {
	pub, err := parseRSAPublicKey(publicKeyB64)
	if err != nil {
		return "", fmt.Errorf("解析登录页 RSA 公钥失败（%v）；请改用浏览器登录后复制 Cookie", err)
	}
	aesKey := randomAESKey() // 模拟前端 (Math.random()+1).toString(36).substring(2)
	rsaCipher, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(aesKey))
	if err != nil {
		return "", fmt.Errorf("RSA 加密失败：%w", err)
	}
	aesCipher, err := aesECBZeroPadEncrypt(aesKey, password)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(rsaCipher) + ":" + aesCipher, nil
}

// parseRSAPublicKey 解析 jms_public_key Cookie（base64(PEM)）为 RSA 公钥；
// 兼容 PEM 与裸 DER（PKIX/SPKI）两种形态。
func parseRSAPublicKey(b64 string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Trim(b64, `"`))
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("公钥不是 RSA 公钥")
	}
	return rsaPub, nil
}

// randomAESKey 生成与前端等价形态的随机 AES key（10 位 base36，≤16 字节；
// 后端 padding_key 会把 key 补零到块边界）。
func randomAESKey() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err) // crypto/rand 失败属系统级异常，程序无法继续
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// aesECBZeroPadEncrypt 执行 AES/ECB + ZeroPadding（与前端 CryptoJS
// mode:ECB, pad:ZeroPadding 及后端 AESCrypto.to_16 对齐：不足 16 倍数补零，
// 整倍数不补块；输出标准 base64）。
func aesECBZeroPadEncrypt(key, plain string) (string, error) {
	keyBytes := make([]byte, 16) // 前端 fillKey：截断/补零到 16 字节
	copy(keyBytes, key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("AES 初始化失败：%w", err)
	}
	data := []byte(plain)
	if n := len(data) % aes.BlockSize; n != 0 {
		data = append(data, make([]byte, aes.BlockSize-n)...)
	}
	ciphertext := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// ---------- 页面解析（正则容错，页面结构见附录 D V5） ----------

var (
	csrfTokenRe   = regexp.MustCompile(`name="csrfmiddlewaretoken"\s+value="([^"]+)"`)
	mfaOptionRe   = regexp.MustCompile(`(?s)<option\s+value="([^"]+)"([^>]*)>(.*?)</option>`)
	errorBlockRe  = regexp.MustCompile(`(?s)<p[^>]*class="[^"]*(?:red-fonts|error)[^"]*"[^>]*>(.*?)</p>`)
	tagRe         = regexp.MustCompile(`<[^>]*>`)
	thirdPartyKws = []string{"qr/login", "/openid/", "/cas/", "/saml2/", "/oauth2/"}
)

// extractCSRF 提取页面中的 csrfmiddlewaretoken。
func extractCSRF(html string) string {
	m := csrfTokenRe.FindStringSubmatch(html)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// extractMFAOptions 解析 MFA 页 <select name="mfa_type"> 的可用验证方式
// （disabled 的 option 排除，与浏览器默认行为一致）。
func extractMFAOptions(html string) []MFAOption {
	var out []MFAOption
	for _, m := range mfaOptionRe.FindAllStringSubmatch(html, -1) {
		if strings.Contains(m[2], "disabled") {
			continue
		}
		label := strings.TrimSpace(tagRe.ReplaceAllString(m[3], ""))
		if label == "" {
			label = m[1]
		}
		out = append(out, MFAOption{Type: m[1], Label: label})
	}
	return out
}

// extractLoginError 从重渲染的登录/MFA 页提取错误文案（.red-fonts 帮助块）。
func extractLoginError(html string) string {
	m := errorBlockRe.FindStringSubmatch(html)
	if len(m) == 2 {
		if t := strings.TrimSpace(tagRe.ReplaceAllString(m[1], "")); t != "" {
			return t
		}
	}
	return "请检查输入后重试"
}

// hasCaptchaField 判断重渲染的登录页是否要求图形验证码（无法自动处理）。
// 真实环境实测：验证码字段为 captcha_0（hidden key）+ captcha_1（文本输入），
// 挑战码字段为 challenge（见附录 D V5）。
func hasCaptchaField(html string) bool {
	return strings.Contains(html, `name="captcha_0"`) || strings.Contains(html, `name="captcha"`) ||
		strings.Contains(html, `name="challenge"`)
}

// isThirdPartyPath 判断跳转目标是否为扫码/第三方认证路径（无法纯 HTTP 完成）。
func isThirdPartyPath(location string) bool {
	for _, kw := range thirdPartyKws {
		if strings.Contains(location, kw) {
			return true
		}
	}
	return false
}
