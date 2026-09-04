package jumpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// API 路径为 JumpServer v3 实测结论（设计文档附录 D V1/V2 已回填）：
// 旧路径 /api/v1/perms/users/assets/ 与 .../system-users/ 实测 404 HTML 不适用。
const (
	// apiTreePath 资产树端点：无 key 返回根节点列表；带 key 返回该节点的
	// 子节点+资产（逐层展开）。注意查询参数名是 key（autoParam 将 id 映射为
	// key），用 id= 会 500。
	apiTreePath = "/api/v1/perms/users/self/nodes/children-with-assets/tree/"
	// apiSelfAssetFmt 单资产详情端点：响应含 permed_accounts（可用账号数组）。
	apiSelfAssetFmt = "/api/v1/perms/users/self/assets/%s/"
	// apiConnectTokenPath 建连 token 创建端点（POST，v3 实测，见附录 D V3）：
	// 需携带 X-CSRFToken 头（值为 cookie 中的 jms_csrftoken），返回 201 + {id, value}。
	apiConnectTokenPath = "/api/v1/authentication/connection-token/"
)

// ConnectTokenRequest 是 connection-token 接口的请求体（v3 实测字段）。
// Account 用 permed_accounts 的 alias（实测 alias=账号 id）。
type ConnectTokenRequest struct {
	Asset           string         `json:"asset"`
	Account         string         `json:"account"`
	Protocol        string         `json:"protocol"`
	InputUsername   string         `json:"input_username"`
	InputSecret     string         `json:"input_secret"`
	InputSecretType string         `json:"input_secret_type"`
	ConnectMethod   string         `json:"connect_method"`
	ConnectOptions  map[string]any `json:"connect_options"`
}

// ConnectToken 是 connection-token 接口的响应；ID 用于 koko WebSocket 的
// ?token={id} 参数（v3 不再用 target_id + system_user_id）。
type ConnectToken struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// TreeNode 资产树节点（tree 端点响应元素）。
// meta.type='node' 为分组节点（可用 key=id 继续展开）；'asset' 为资产叶子。
type TreeNode struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Title    string          `json:"title"`
	PID      string          `json:"pId"`
	IsParent bool            `json:"isParent"`
	Open     bool            `json:"open"`
	Meta     json.RawMessage `json:"meta"`
}

// nodeMeta 是 TreeNode.Meta 的结构化形态。
type nodeMeta struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// assetData 资产叶子 meta.data 的扩展字段（容错解析，缺失置空）。
type assetData struct {
	PlatformType string `json:"platform_type"`
	OrgName      string `json:"org_name"`
	Address      string `json:"address"`
}

// Asset 资产信息（树叶子节点）：id=资产 UUID、Hostname=节点 name、
// Address=节点 title（IP）。扩展字段 PlatformType/OrgName 来自 meta.data。
type Asset struct {
	ID           string
	Hostname     string
	Address      string
	PlatformType string
	OrgName      string
}

// SystemUser 资产上的可用账号（permed_accounts 元素），
// ID 用作 WebSocket 端点的 system_user_id 参数。
type SystemUser struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	SecretType string `json:"secret_type"`
}

// APIError 携带 HTTP 状态码的错误，CLI 层据此给出针对性提示。
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string { return e.Message }

// apiTimeout 是 API 请求的超时兜底（见 doRequest 内的 ctx 包裹）。
// 包级变量便于测试临时调小；生产默认 15s。
var apiTimeout = 15 * time.Second

// httpClient 设置整体超时（覆盖连接 + 请求 + 读 body），并关闭自动跟随重定向：
// 302 通常表示会话失效跳转登录页（如 /core/auth/login/），需保留原始状态码用于判定。
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// classifyError 按状态码归类错误，给出可操作提示。
func classifyError(status int) error {
	switch status {
	case http.StatusFound, http.StatusUnauthorized, http.StatusForbidden:
		// 302 跳登录页 / 401 / 403 均视为会话失效
		return &APIError{StatusCode: status, Message: fmt.Sprintf(
			"会话可能已失效（HTTP %d）：请输入 login 重新登录，或编辑配置文件重新粘贴 Cookie 后 reload", status)}
	case http.StatusNotFound:
		// 当前实测端点见设计文档附录 D V1/V2 回填；仍 404 说明部署环境与实测不一致
		return &APIError{StatusCode: status, Message: fmt.Sprintf(
			"HTTP 404：接口路径返回 404，当前实测端点为 /api/v1/perms/users/self/nodes/children-with-assets/tree/ 与 /api/v1/perms/users/self/assets/{id}/，可能环境与实测不一致，请按设计文档附录 D 排查")}
	default:
		return &APIError{StatusCode: status, Message: fmt.Sprintf("HTTP %d", status)}
	}
}

// request 执行一次带 Cookie 的 GET 并完整读取响应体；非 200/201 返回 *APIError，
// 网络错误原样返回。
func request(ctx context.Context, host, cookie, path string, qs url.Values) ([]byte, error) {
	return doRequest(ctx, http.MethodGet, host, cookie, path, qs, "", "", nil)
}

// doRequest 执行一次带 Cookie 的 HTTP 请求（支持 POST + JSON body + CSRF 头 + Referer），
// 并**在函数内完整读取响应体**后返回。
//
// 关键：context.WithTimeout 的 cancel 在函数返回时才执行，body 的 ReadAll 发生在
// cancel 之前——避免旧实现"返回 *http.Response 由调用方惰性读 body，而此时 ctx 已
// cancel"导致的间歇性 context canceled（真实环境复现，见连接竞态修复记录）。
// 非 200/201 返回 *APIError；网络错误原样返回。
func doRequest(ctx context.Context, method, host, cookie, path string, qs url.Values, csrf, referer string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	u := host + path
	if len(qs) > 0 {
		u += "?" + qs.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败：%w", err)
	}
	req.Header.Set("Cookie", cookie)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRFToken", csrf)
	}
	if referer != "" {
		// JumpServer CSRF 保护同时校验 Referer（缺省返回 403
		// 'Referer checking failed - no Referer'）；Go 的 http.Client
		// 默认不发 Referer，浏览器天然携带故无此问题（附录 D V3）
		req.Header.Set("Referer", referer)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s 失败：%w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, classifyError(resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body) // 在 cancel（函数返回）前读完
	if err != nil {
		return nil, fmt.Errorf("读取 %s 响应失败：%w", path, err)
	}
	return raw, nil
}

// CreateConnectToken 创建 koko 建连 token（v3 实测流程第一步，见附录 D V3）。
//
// csrf 为 Cookie 中的 jms_csrftoken（JumpServer 自定义 cookie 名）；account 为
// permed_accounts 的 alias（实测 alias=账号 id）。返回的 token.ID 用作 WebSocket
// 端点 ?token={id} 参数。
func CreateConnectToken(ctx context.Context, host, cookie, csrf, assetID, account string) (*ConnectToken, error) {
	payload, err := json.Marshal(ConnectTokenRequest{
		Asset:           assetID,
		Account:         account,
		Protocol:        "ssh",
		InputUsername:   "",
		InputSecret:     "",
		InputSecretType: "password",
		ConnectMethod:   "web",
		ConnectOptions:  map[string]any{},
	})
	if err != nil {
		return nil, fmt.Errorf("构造 connection-token 请求失败：%w", err)
	}
	raw, err := doRequest(ctx, http.MethodPost, host, cookie, apiConnectTokenPath, nil, csrf, strings.TrimSuffix(host, "/")+"/", payload)
	if err != nil {
		return nil, err
	}
	var tok ConnectToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("解析 connection-token 响应失败（%v）；请按设计文档附录 D V3 排查", err)
	}
	return &tok, nil
}

// ListAssets 从根节点逐层展开资产树，收集全部资产叶子（BFS）。
// 分组节点（meta.type='node'）以其 id 作为 key 继续展开；同节点只展开一次防环。
func ListAssets(ctx context.Context, host, cookie string) ([]Asset, error) {
	var assets []Asset
	queue := []string{""} // "" 表示根节点（不带 key 参数）
	expanded := make(map[string]bool)
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		if key != "" {
			if expanded[key] {
				continue // 防环：同一节点只展开一次
			}
			expanded[key] = true
		}
		nodes, err := fetchTreeChildren(ctx, host, cookie, key)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			meta, ok := parseNodeMeta(n.Meta)
			if !ok {
				continue // meta 缺失/非法：跳过（容错，不中断）
			}
			switch meta.Type {
			case "asset":
				assets = append(assets, treeNodeToAsset(n, meta.Data))
			case "node":
				queue = append(queue, n.ID)
			default:
				// 未知类型：跳过
			}
		}
	}
	return assets, nil
}

// fetchTreeChildren 拉取节点（key="" 为根）的直接子节点列表。
func fetchTreeChildren(ctx context.Context, host, cookie, key string) ([]TreeNode, error) {
	var qs url.Values
	if key != "" {
		qs = url.Values{}
		qs.Set("key", key) // 参数名是 key 而非 id
	}
	raw, err := request(ctx, host, cookie, apiTreePath, qs)
	if err != nil {
		return nil, err
	}
	// 兼容顶层数组与 {results:[...]} 包装两种响应形态
	var nodes []TreeNode
	if err := json.Unmarshal(raw, &nodes); err == nil && nodes != nil {
		return nodes, nil
	}
	var wrapped struct {
		Results []TreeNode `json:"results"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("解析资产树响应失败（%v）；若为 404/HTML，请按设计文档附录 D V1 排查 API 路径", err)
	}
	return wrapped.Results, nil
}

// ListSystemUsers 查询资产的可用账号（permed_accounts）；缺省取数组首个为默认。
func ListSystemUsers(ctx context.Context, host, cookie, assetID string) ([]SystemUser, error) {
	raw, err := request(ctx, host, cookie, fmt.Sprintf(apiSelfAssetFmt, url.PathEscape(assetID)), nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		PermedAccounts []SystemUser `json:"permed_accounts"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("解析账号响应失败（%v）；请按设计文档附录 D V2 排查 API 路径", err)
	}
	return body.PermedAccounts, nil
}

// VerifySession 请求资产树根节点校验 Cookie 会话有效性（config test 使用），
// 返回 HTTP 状态码；200 表示有效，其他状态码同时返回 *APIError 说明原因。
func VerifySession(ctx context.Context, host, cookie string) (int, error) {
	_, err := request(ctx, host, cookie, apiTreePath, nil)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return ae.StatusCode, err
		}
		return 0, err
	}
	return http.StatusOK, nil
}

// parseNodeMeta 解析节点 meta；缺失/非法返回 ok=false。
func parseNodeMeta(raw json.RawMessage) (nodeMeta, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nodeMeta{}, false
	}
	var m nodeMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nodeMeta{}, false
	}
	return m, true
}

// treeNodeToAsset 将资产叶子节点转换为 Asset：id 取节点 id（资产 UUID），
// hostname 取节点 name，address 取节点 title（IP），扩展字段容错解析。
func treeNodeToAsset(n TreeNode, dataRaw json.RawMessage) Asset {
	var d assetData
	_ = json.Unmarshal(dataRaw, &d) // 扩展字段容错：解析失败则置空
	a := Asset{ID: n.ID, Hostname: n.Name, Address: n.Title}
	if a.Address == "" {
		a.Address = d.Address
	}
	a.PlatformType = d.PlatformType
	a.OrgName = d.OrgName
	return a
}
