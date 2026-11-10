package jumpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// 登录流程（2026-11 实测）：JumpServer 已关闭账号密码登录，认证整体外抛给
// 公司统一认证 sso.zxxk.com（CAS）：
//   - GET /core/auth/login/ 302 到业务侧 CAS 入口 /core/auth/cas/login/；
//   - CAS 入口 302 到 SSO 登录页 sso.zxxk.com/login?service=…；
//   - SSO 登录页只剩微信扫码（账号密码入口已下线），扫码状态经
//     /user/wechat-applet/logincheck 轮询，扫码完成后 dologin 收尾，
//     再以 CAS webflow 表单（_eventId=scanCodeLogin）换回 service?ticket=；
//   - ticket 回跳业务侧 CAS 入口，服务端校验后种 jms_sessionid；业务侧自身的
//     MFA 分支（guard → /core/auth/login/mfa/）仍可能被触发。
//
// 扫码必须由人完成；可自动化的是扫码之外的全部：拉二维码、渲染、轮询、换票、
// 落盘。约束：不引入浏览器；业务域与 SSO 域的会话 Cookie 分开序列化。

const (
	casEntryPath   = "/core/auth/cas/login/"
	loginPath      = "/core/auth/login/"
	loginGuardPath = "/core/auth/login/guard/"
	loginMFAPath   = "/core/auth/login/mfa/"

	// SSO 扫码端点（sso.zxxk.com 前端 scan-code-*.js 实测）。
	ssoQRContentPath = "/user/qrcode/qrcode-login/v2/content"
	ssoScanCheckPath = "/user/wechat-applet/logincheck"
	ssoDoLoginPath   = "/user/wechat-applet/dologin"
	ssoActivatePath  = "/user/set-activate-flag"
)

// loginDebugTarget 控制登录链路追踪的落点：未设为关闭；"1" 打印到 stderr；
// 其他值视为文件路径（追加写）。每跳记录方法、脱敏 URL、状态码、跳转目标
// 与下发的 Cookie 名，用于排查 SSO 侧改版。
var loginDebugTarget = os.Getenv("REEDFERRY_LOGIN_DEBUG")

// debugWriter 返回追踪输出目标（nil 表示关闭）。
func debugWriter() io.Writer {
	switch loginDebugTarget {
	case "":
		return nil
	case "1":
		return os.Stderr
	default:
		f, err := os.OpenFile(loginDebugTarget, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil
		}
		return f
	}
}

// LoginErrorKind 登录失败分类，CLI 层据此给出针对性提示。
type LoginErrorKind int

const (
	// LoginErrOther 未分类错误。
	LoginErrOther LoginErrorKind = iota
	// LoginErrBadMFA 业务侧 2FA 动态验证码错误。
	LoginErrBadMFA
	// LoginErrScanCancelled 微信侧取消授权。
	LoginErrScanCancelled
	// LoginErrQRExpired 二维码过期。
	LoginErrQRExpired
	// LoginErrAccountBind 微信身份尚未绑定统一认证账号。
	LoginErrAccountBind
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

// QRCode 是待展示的扫码挑战：Content 为二维码承载的 URL，Token/Version 用于轮询。
type QRCode struct {
	Content string
	Token   string
	Version int
}

// LoginOutcome 是登录一步的结果：NeedQR（待扫码）、NeedMFA（待 2FA 验证码），
// 或登录完成（Cookie / SSOCookie 可写入配置）。
type LoginOutcome struct {
	Cookie    string     // 业务域会话 Cookie（登录完成时有效）
	SSOCookie string     // SSO 域会话 Cookie（用于下次静默换票）
	NeedQR    bool       // 需要展示二维码并等待扫码
	NeedMFA   bool       // 需要输入业务侧 2FA 验证码
	QR        *QRCode    // NeedQR 时的扫码挑战
	Prompt    *MFAPrompt // NeedMFA 时的挑战信息
}

// errScanNotReady 表示 dologin 尚未就绪（微信侧还没完成授权）：不是致命错误，
// 继续轮询即可。
var errScanNotReady = errors.New("扫码尚未完成")

// ScanStatus 是扫码轮询的中间状态（用于给用户显示进度）。
type ScanStatus int

const (
	// ScanWaiting 尚未扫码。
	ScanWaiting ScanStatus = iota
	// ScanScanned 已扫码，等待微信内确认授权。
	ScanScanned
)

// LoginFlow 驱动一次 SSO 扫码登录：业务 CAS 入口 → SSO 登录页 → 二维码
// →（扫码）→ 换票 → 业务会话 Cookie。全程使用同一 Cookie Jar；302 手动
// 跟随以识别 MFA 与换票分支。
type LoginFlow struct {
	host string
	jar  *cookiejar.Jar
	http *http.Client

	service  string // 业务侧 CAS 回调地址（service 参数原值）
	ssoBase  string // SSO 域基址（从第一跳 302 发现，不设配置项）
	loginURL string // SSO 登录页完整 URL（含 service）
	mfaURL   string // 业务侧 MFA 页

	form url.Values // 当前页 hidden 表单字段（CAS webflow / MFA 提交用）
	qr   *QRCode

	// scanCompletes / scanPolls 记录「已扫码」后主动尝试收尾的次数与轮询拍数：
	// 微信侧若在扫码时即完成授权，状态可能停在 LOGINING 不推进到 LOGINED，
	// 不能只等状态，需按节拍主动试 dologin。
	scanCompletes int
	scanPolls     int
}

// NewLoginFlow 打开登录链路，推进到「待扫码」或「已完成」为止。
// ssoCookie 为上次登录留下的 SSO 域会话 Cookie（可为空）：携带它访问 SSO
// 登录页时，会话仍有效则 SSO 直接回 ticket，无需再次扫码。
func NewLoginFlow(ctx context.Context, host, ssoCookie string) (*LoginFlow, *LoginOutcome, error) {
	base := strings.TrimSuffix(host, "/")
	if base == "" {
		return nil, nil, errors.New("JumpServer 地址为空")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("初始化 Cookie Jar 失败：%w", err)
	}
	client := &http.Client{
		Timeout: apiTimeout,
		Jar:     jar,
		// 302 链手动跟随：换票、guard 分流、MFA 分支需逐跳识别
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	f := &LoginFlow{
		host:   base,
		jar:    jar,
		http:   client,
		mfaURL: base + loginMFAPath,
	}

	// 第一跳：业务侧 CAS 入口，暴露 SSO 域与 service
	location, err := f.redirectTarget(ctx, base+casEntryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 JumpServer 登录入口失败：%w", err)
	}
	u, err := url.Parse(location)
	if err != nil || u.Host == "" {
		return nil, nil, fmt.Errorf("登录入口跳转目标无法解析：%s", location)
	}
	f.ssoBase = u.Scheme + "://" + u.Host
	f.loginURL = location
	f.service = u.Query().Get("service")
	if f.service == "" {
		return nil, nil, fmt.Errorf("登录入口未携带 service 参数（%s），环境配置异常", location)
	}

	if ssoCookie != "" {
		f.seedCookies(f.ssoBase, ssoCookie)
	}

	outcome, err := f.openSSO(ctx)
	if err != nil {
		return nil, nil, err
	}
	return f, outcome, nil
}

// QR 返回当前扫码挑战（NeedQR 时有效）。
func (f *LoginFlow) QR() *QRCode { return f.qr }

// Service 返回本次登录的 service 参数（业务侧 CAS 回调地址）。
func (f *LoginFlow) Service() string { return f.service }

// RefreshQR 重新拉取二维码内容（同一扫码会话内刷新，令牌不变）。
func (f *LoginFlow) RefreshQR(ctx context.Context) error {
	if f.qr == nil {
		return errors.New("当前没有待刷新的二维码")
	}
	return f.loadQR(ctx, f.qr.Token)
}

// openSSO 打开 SSO 登录页：会话仍有效时直接换票完成；否则解析页面拉取二维码。
func (f *LoginFlow) openSSO(ctx context.Context) (*LoginOutcome, error) {
	raw, resp, err := f.get(ctx, f.loginURL)
	if err != nil {
		return nil, fmt.Errorf("打开统一认证登录页失败（网络不可达或服务异常）：%w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		page := string(raw)
		token := extractQRToken(page)
		if token == "" {
			return nil, errors.New("统一认证登录页未找到扫码令牌（页面结构变化？），请改用浏览器登录后复制 Cookie")
		}
		f.form = extractHiddenInputs(page)
		if f.form.Get("execution") == "" {
			return nil, errors.New("统一认证登录页未找到 CAS 执行上下文（execution 字段缺失，页面结构变化？）")
		}
		if err := f.loadQR(ctx, token); err != nil {
			return nil, err
		}
		return &LoginOutcome{NeedQR: true, QR: f.qr}, nil
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		// SSO 会话有效：免扫码直接回 ticket
		location := f.resolve(resp.Header.Get("Location"))
		if !strings.Contains(location, "ticket=") {
			return nil, fmt.Errorf("统一认证登录页跳转异常（%s）", location)
		}
		return f.acceptTicket(ctx, location)
	default:
		return nil, fmt.Errorf("打开统一认证登录页失败：HTTP %d", resp.StatusCode)
	}
}

// loadQR 拉取二维码内容（content 为二维码承载的 URL，queryToken 用于轮询）。
func (f *LoginFlow) loadQR(ctx context.Context, token string) error {
	q := url.Values{}
	q.Set("token", token)
	q.Set("service", f.service)
	raw, resp, err := f.get(ctx, f.ssoBase+ssoQRContentPath+"?"+q.Encode())
	if err != nil {
		return fmt.Errorf("获取登录二维码失败（网络不可达或服务异常）：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取登录二维码失败：HTTP %d", resp.StatusCode)
	}
	var body struct {
		Status int `json:"status"`
		Data   struct {
			Content    string `json:"content"`
			QueryToken struct {
				Token   string `json:"token"`
				Version int    `json:"version"`
			} `json:"queryToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("解析二维码响应失败：%w", err)
	}
	if body.Status != http.StatusOK || body.Data.Content == "" {
		return fmt.Errorf("获取登录二维码失败：请稍后重试（服务端返回 %d）", body.Status)
	}
	f.qr = &QRCode{
		Content: body.Data.Content,
		Token:   body.Data.QueryToken.Token,
		Version: body.Data.QueryToken.Version,
	}
	return nil
}

// PollScan 轮询一次扫码状态：done 非空表示换票完成，err 为致命错误；
// 否则返回中间状态供 UI 提示。调用方按 scanPollInterval 节拍反复调用。
func (f *LoginFlow) PollScan(ctx context.Context) (ScanStatus, *LoginOutcome, error) {
	if f.qr == nil {
		return ScanWaiting, nil, errors.New("当前没有待轮询的二维码")
	}
	q := url.Values{}
	q.Set("token", f.qr.Token)
	q.Set("version", fmt.Sprintf("%d", f.qr.Version))
	f.qr.Version++
	raw, resp, err := f.get(ctx, f.ssoBase+ssoScanCheckPath+"?"+q.Encode())
	if err != nil || resp.StatusCode != http.StatusOK {
		return ScanWaiting, nil, nil // 网络抖动：下一拍重试
	}
	var body struct {
		Status int `json:"status"`
		Data   *struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ScanWaiting, nil, nil
	}
	if body.Status != http.StatusOK || body.Data == nil {
		traceStatus("null")
		return ScanWaiting, nil, nil // 尚未扫码（服务端 data 为空）
	}
	traceStatus(body.Data.Status)
	switch body.Data.Status {
	case "LOGINED":
		outcome, err := f.completeScan(ctx)
		if errors.Is(err, errScanNotReady) {
			return ScanScanned, nil, nil
		}
		return ScanScanned, outcome, err
	case "LOGINING":
		// 已扫码：微信侧自动授权时状态可能不再推进，主动尝试收尾。前两次每拍都
		// 试，之后每 5 拍试一次，避免反复打 dologin。
		f.scanPolls++
		if f.scanCompletes < 2 || f.scanPolls%5 == 0 {
			f.scanCompletes++
			outcome, err := f.completeScan(ctx)
			if err == nil {
				return ScanScanned, outcome, nil
			}
			if !errors.Is(err, errScanNotReady) {
				return ScanScanned, nil, err
			}
		}
		return ScanScanned, nil, nil
	case "QUIT_LOGIN":
		return ScanWaiting, nil, &LoginError{Kind: LoginErrScanCancelled, Msg: "微信侧已取消本次登录授权"}
	case "ACCOUNT_BIND":
		return ScanWaiting, nil, &LoginError{Kind: LoginErrAccountBind, Msg: "该微信尚未绑定统一认证账号，需先在浏览器完成一次绑定后再用本工具登录"}
	case "EXPIRED":
		return ScanWaiting, nil, &LoginError{Kind: LoginErrQRExpired, Msg: "二维码已过期"}
	default:
		return ScanWaiting, nil, nil
	}
}

// completeScan 扫码完成后收尾：dologin 确认 →（隐私协议分支）→ CAS 表单换票。
func (f *LoginFlow) completeScan(ctx context.Context) (*LoginOutcome, error) {
	q := url.Values{}
	q.Set("service", f.service)
	raw, resp, err := f.get(ctx, f.ssoBase+ssoDoLoginPath+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("确认扫码登录失败（网络不可达或服务异常）：%w", err)
	}
	var body struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("确认扫码登录失败：HTTP %d", resp.StatusCode)
	}
	if body.Status != http.StatusOK {
		return nil, fmt.Errorf("%w：%s", errScanNotReady, body.Message)
	}
	// 首次登录需同意隐私协议的账号：先提交同意标记，否则停在「扫码成功进不去」
	if strings.Contains(body.Message, "同意") {
		loginInfo := strings.SplitN(body.Message, "_", 2)[0]
		form := url.Values{}
		form.Set("loginInfo", loginInfo)
		if _, resp, err := f.postForm(ctx, f.ssoBase+ssoActivatePath, form, f.loginURL); err != nil || resp.StatusCode >= 400 {
			return nil, fmt.Errorf("提交隐私协议同意标记失败（HTTP %d）", resp.StatusCode)
		}
	}

	// dologin 成功后 SSO 会话已认证：再拉一次登录页，CAS 会直接回 ticket
	// （与「SSO 会话有效」同一路径）。比提交页面里的 webflow 表单更可靠——
	// 表单里的 execution 取自首次渲染，dologin 之后可能已失效，提交只会
	// 重渲染登录页（HTTP 200）。
	if outcome, ok, err := f.exchangeViaGet(ctx); err != nil {
		return nil, err
	} else if ok {
		return outcome, nil
	}

	// 兜底：按当前页面（可能是刚重渲染的新页面）的 webflow 表单提交扫码事件
	form := url.Values{}
	for k, v := range f.form {
		form[k] = append([]string(nil), v...)
	}
	form.Set("_eventId", "scanCodeLogin")
	raw, resp, err = f.postForm(ctx, f.loginURL, form, f.loginURL)
	if err != nil {
		return nil, fmt.Errorf("提交扫码结果失败（网络不可达或服务异常）：%w", err)
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("提交扫码结果失败：HTTP %d（页面可能已过期，请按 r 刷新二维码重试）", resp.StatusCode)
	}
	location := f.resolve(resp.Header.Get("Location"))
	if !strings.Contains(location, "ticket=") {
		return nil, fmt.Errorf("统一认证未返回票据（跳转目标 %s），请重试或改用浏览器登录后复制 Cookie", location)
	}
	return f.acceptTicket(ctx, location)
}

// exchangeViaGet 重新请求 SSO 登录页：会话已认证时 CAS 直接 302 回
// service?ticket=（ok=true）；仍渲染登录页（HTTP 200）时刷新表单字段并返回 ok=false。
func (f *LoginFlow) exchangeViaGet(ctx context.Context) (*LoginOutcome, bool, error) {
	raw, resp, err := f.get(ctx, f.loginURL)
	if err != nil {
		return nil, false, fmt.Errorf("请求统一认证登录页失败（网络不可达或服务异常）：%w", err)
	}
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		location := f.resolve(resp.Header.Get("Location"))
		if !strings.Contains(location, "ticket=") {
			return nil, false, nil
		}
		outcome, err := f.acceptTicket(ctx, location)
		return outcome, err == nil, err
	case http.StatusOK:
		f.form = extractHiddenInputs(string(raw))
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("请求统一认证登录页失败：HTTP %d", resp.StatusCode)
	}
}

// acceptTicket 带票据回跳业务侧，服务端校验后种会话 Cookie，再按业务侧
// 分支（MFA / guard / 落地页）收尾。
func (f *LoginFlow) acceptTicket(ctx context.Context, location string) (*LoginOutcome, error) {
	_, resp, err := f.get(ctx, location)
	if err != nil {
		return nil, fmt.Errorf("回跳 JumpServer 失败（网络不可达或服务异常）：%w", err)
	}
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		return f.followAfterAuth(ctx, f.resolve(resp.Header.Get("Location")))
	case http.StatusOK:
		return f.done(ctx)
	default:
		return nil, fmt.Errorf("ticket 校验失败：HTTP %d（可能需要重新扫码）", resp.StatusCode)
	}
}

// followAfterAuth 沿业务侧 302 链走到终态：MFA 页进入 2FA 挑战，guard
// 继续跟随，回落到登录入口表示会话未建立，其余视为落地页并消费。
func (f *LoginFlow) followAfterAuth(ctx context.Context, location string) (*LoginOutcome, error) {
	for i := 0; i < 6; i++ {
		switch {
		case strings.Contains(location, loginMFAPath):
			return f.enterMFA(ctx)
		case strings.Contains(location, loginGuardPath):
			next, err := f.redirectTarget(ctx, location)
			if err != nil {
				return nil, fmt.Errorf("跟随登录跳转失败：%w", err)
			}
			location = next
		case strings.HasPrefix(location, f.ssoBase), strings.Contains(location, loginPath):
			return nil, errors.New("ticket 未被接受（回落到登录入口），会话未建立，请重新扫码")
		default:
			return f.consumeLanding(ctx, location)
		}
	}
	return nil, errors.New("登录跳转链异常（超过 6 次重定向），请改用浏览器登录后复制 Cookie")
}

// consumeLanding 取落地页：Django 系的 CSRF Cookie（jms_csrftoken）只在渲染
// 带 CSRF 的页面时才种下，必须先消费页面再序列化 Cookie。
func (f *LoginFlow) consumeLanding(ctx context.Context, location string) (*LoginOutcome, error) {
	for i := 0; i < 4; i++ {
		_, resp, err := f.get(ctx, location)
		if err != nil {
			// 落地页取不到不影响会话本身，按完成处理（会话有效性在 done 里校验）
			return f.done(ctx)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location = f.resolve(resp.Header.Get("Location"))
			continue
		}
		break
	}
	return f.done(ctx)
}

// enterMFA 进入业务侧 2FA 挑战：拉取 MFA 页，收集可用验证方式。
func (f *LoginFlow) enterMFA(ctx context.Context) (*LoginOutcome, error) {
	raw, resp, err := f.get(ctx, f.mfaURL)
	if err != nil {
		return nil, fmt.Errorf("打开 MFA 页失败（网络不可达或服务异常）：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return nil, fmt.Errorf("MFA 会话异常（HTTP %d 跳转 %s），请重新登录", resp.StatusCode, resp.Header.Get("Location"))
		}
		return nil, fmt.Errorf("打开 MFA 页失败：HTTP %d", resp.StatusCode)
	}
	options := extractMFAOptions(string(raw))
	if len(options) == 0 {
		return nil, errors.New("MFA 页未解析到可用的验证方式（页面结构变化？），请改用浏览器登录后复制 Cookie")
	}
	f.form = extractHiddenInputs(string(raw))
	return &LoginOutcome{NeedMFA: true, Prompt: &MFAPrompt{Options: options}}, nil
}

// SubmitMFA 提交业务侧 2FA 动态验证码（code + mfa_type，取自 MFAPrompt）。
func (f *LoginFlow) SubmitMFA(ctx context.Context, code, mfaType string) (*LoginOutcome, error) {
	if code == "" {
		return nil, errors.New("MFA 验证码为空，已取消")
	}
	form := url.Values{}
	form.Set("csrfmiddlewaretoken", f.form.Get("csrfmiddlewaretoken"))
	form.Set("code", code)
	form.Set("mfa_type", mfaType)
	raw, resp, err := f.postForm(ctx, f.mfaURL, form, f.mfaURL)
	if err != nil {
		return nil, fmt.Errorf("提交 MFA 验证码失败（网络不可达或服务异常）：%w", err)
	}
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		return f.followAfterAuth(ctx, f.resolve(resp.Header.Get("Location")))
	case http.StatusOK:
		return nil, &LoginError{Kind: LoginErrBadMFA, Msg: "JumpServer 2FA 动态验证码错误：" + extractLoginError(string(raw))}
	default:
		return nil, fmt.Errorf("MFA 校验失败：HTTP %d", resp.StatusCode)
	}
}

// done 序列化两个域的会话 Cookie，并立即用业务接口校验会话确实可用：
// 匿名会话同样带 jms_sessionid，只看字段存在会把「ticket 未被接受」误判为成功。
func (f *LoginFlow) done(ctx context.Context) (*LoginOutcome, error) {
	biz := f.serializeCookies(f.host)
	if !strings.Contains(biz, "jms_sessionid=") {
		return nil, fmt.Errorf("登录后未拿到业务会话 Cookie（jms_sessionid），实际字段：%s", cookieNames(biz))
	}
	if code, err := VerifySession(ctx, f.host, biz); err != nil || code != http.StatusOK {
		return nil, fmt.Errorf("登录后会话不可用（HTTP %d，字段：%s）：ticket 未被业务侧接受，请重试或改用浏览器登录后复制 Cookie", code, cookieNames(biz))
	}
	return &LoginOutcome{Cookie: biz, SSOCookie: f.serializeCookies(f.ssoBase)}, nil
}

// ---------- HTTP 基础 ----------

// get 执行 GET（禁自动重定向），完整读取响应体后返回。
func (f *LoginFlow) get(ctx context.Context, u string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	trace(http.MethodGet, req.URL, resp)
	return raw, resp, nil
}

// postForm 执行表单 POST（禁自动重定向），完整读取响应体后返回。
func (f *LoginFlow) postForm(ctx context.Context, u string, form url.Values, referer string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		return nil, nil, err
	}
	trace(http.MethodPost, req.URL, resp)
	return raw, resp, nil
}

// trace 打印一次 HTTP 跳转摘要（URL 中票据/令牌类参数值脱敏）。
func trace(method string, u *url.URL, resp *http.Response) {
	w := debugWriter()
	if w == nil || resp == nil {
		return
	}
	fmt.Fprintf(w, "[login] %s %s -> %d", method, safeURL(u), resp.StatusCode)
	if loc := resp.Header.Get("Location"); loc != "" {
		fmt.Fprintf(w, " location=%s", loc)
	}
	fmt.Fprintln(w)
	for _, c := range resp.Cookies() {
		fmt.Fprintf(w, "[login]   set-cookie %s len=%d path=%s domain=%s\n", c.Name, len(c.Value), c.Path, c.Domain)
	}
}

// traceStatus 记录扫码状态（调试用）。
func traceStatus(status string) {
	if w := debugWriter(); w != nil {
		fmt.Fprintf(w, "[login]   scan-status=%s\n", status)
	}
}

// safeURL 输出不含凭据的 URL：查询参数值对 ticket/token/key/code 类脱敏。
func safeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	q := u.Query()
	for k := range q {
		switch strings.ToLower(k) {
		case "ticket", "token", "key", "code", "execution":
			q.Set(k, "<redacted>")
		}
	}
	out := *u
	out.RawQuery = q.Encode()
	return out.String()
}

// redirectTarget 请求 u 并返回其 302 目标（绝对 URL）；非 302 视为异常。
func (f *LoginFlow) redirectTarget(ctx context.Context, u string) (string, error) {
	_, resp, err := f.get(ctx, u)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("期望跳转，实际 HTTP %d（%s）", resp.StatusCode, u)
	}
	return f.resolve(resp.Header.Get("Location")), nil
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

// seedCookies 把 "k=v; k2=v2" 形态的 Cookie 串灌入指定域的 Jar。
func (f *LoginFlow) seedCookies(base, raw string) {
	u, err := url.Parse(base)
	if err != nil {
		return
	}
	var cookies []*http.Cookie
	for _, part := range strings.Split(raw, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || k == "" {
			continue
		}
		cookies = append(cookies, &http.Cookie{Name: k, Value: v, Path: "/"})
	}
	if len(cookies) > 0 {
		f.jar.SetCookies(u, cookies)
	}
}

// serializeCookies 把指定域的 Cookie 序列化为 "k=v; k2=v2" 配置串。
func (f *LoginFlow) serializeCookies(base string) string {
	u, err := url.Parse(base + "/")
	if err != nil {
		return ""
	}
	parts := make([]string, 0, 8)
	for _, c := range f.jar.Cookies(u) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// cookieNames 返回 Cookie 串中的字段名（不含值），用于诊断。
func cookieNames(raw string) string {
	names := make([]string, 0, 8)
	for _, part := range strings.Split(raw, ";") {
		k, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && k != "" {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return "（空）"
	}
	return strings.Join(names, ", ")
}

// ---------- 页面解析（正则容错，页面结构见设计文档附录 D V5） ----------

var (
	qrTokenRe    = regexp.MustCompile(`var\s+qrToken\s*=\s*"([^"]+)"`)
	hiddenRe     = regexp.MustCompile(`(?is)<input[^>]*type="hidden"[^>]*>`)
	nameAttrRe   = regexp.MustCompile(`(?is)name="([^"]*)"`)
	valAttrRe    = regexp.MustCompile(`(?is)value="([^"]*)"`)
	mfaOptionRe  = regexp.MustCompile(`(?s)<option\s+value="([^"]+)"([^>]*)>(.*?)</option>`)
	errorBlockRe = regexp.MustCompile(`(?s)<p[^>]*class="[^"]*(?:red-fonts|error)[^"]*"[^>]*>(.*?)</p>`)
	tagRe        = regexp.MustCompile(`<[^>]*>`)
)

// extractQRToken 提取 SSO 登录页内联脚本中的扫码令牌。
func extractQRToken(html string) string {
	if m := qrTokenRe.FindStringSubmatch(html); len(m) == 2 {
		return m[1]
	}
	return ""
}

// extractHiddenInputs 收集页面全部 hidden 表单字段（CAS webflow 提交需原样带回）。
func extractHiddenInputs(html string) url.Values {
	form := url.Values{}
	for _, tag := range hiddenRe.FindAllString(html, -1) {
		n := nameAttrRe.FindStringSubmatch(tag)
		if len(n) != 2 || n[1] == "" {
			continue
		}
		v := ""
		if m := valAttrRe.FindStringSubmatch(tag); len(m) == 2 {
			v = m[1]
		}
		form.Set(n[1], v)
	}
	return form
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

// extractLoginError 从重渲染的 MFA 页提取错误文案（.red-fonts 帮助块）。
func extractLoginError(html string) string {
	if m := errorBlockRe.FindStringSubmatch(html); len(m) == 2 {
		if t := strings.TrimSpace(tagRe.ReplaceAllString(m[1], "")); t != "" {
			return t
		}
	}
	return "请检查输入后重试"
}
