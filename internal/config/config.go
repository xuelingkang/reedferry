// Package config 管理 ~/.config/reedferry/config.json 的读写（XDG 风格，跨平台统一）。
//
// 配置含 JumpServer 地址、会话 Cookie，以及可选的登录账号/密码（用户明确选择
// 存配置时启用），文件权限 0600，采用先写临时文件再 rename 的原子写，避免写入
// 中断留下半截文件。含登录凭据，勿提交版本库。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotConfigured 表示配置文件不存在（尚未执行 config init）。
var ErrNotConfigured = errors.New("reedferry: 未配置，请先运行 `reedferry config init`")

// ExampleHost 是模板配置的占位 JumpServer 地址（开源示例，用户需替换为真实地址）。
const ExampleHost = "https://your-jumpserver.example.com"

// Config 是本地配置文件结构。
//
// Username/Password 为可选的登录凭据（用户明确选择存配置）：配置后交互式登录
// 跳过对应输入，直接使用；2FA 动态验证码任何情况下不落盘、不写入配置。
type Config struct {
	Host     string `json:"host"`               // JumpServer 地址，如 https://your-jumpserver.example.com
	Cookie   string `json:"cookie"`             // 浏览器会话 Cookie，如 "sessionid=xxx; jms_csrftoken=yyy"
	Username string `json:"username,omitempty"` // 可选：登录账号；配置则登录时跳过账号输入
	Password string `json:"password,omitempty"` // 可选：登录密码（明文存储，0600 权限）；配置则登录时跳过密码输入
}

// pathOverride 仅用于测试重定向配置文件位置；为空时使用默认路径。
var pathOverride string

// Path 返回配置文件路径：$HOME/.config/reedferry/config.json（XDG 风格）。
// os.UserHomeDir 失败时 fallback 到 $HOME 环境变量。
func Path() string {
	if pathOverride != "" {
		return pathOverride
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".config", "reedferry", "config.json")
}

// Load 读取配置；文件不存在返回 ErrNotConfigured。
func Load() (*Config, error) {
	raw, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotConfigured
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// Save 以 0600 权限原子写配置：先写同目录临时文件并 fsync，再 rename 覆盖，
// 保证任何时刻配置目录中只有一个完整文件。
func Save(c *Config) error {
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), "config.json.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后为 no-op，失败时清理

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}

// EnsureConfig 确保配置文件存在：已存在则读取返回；不存在则创建示例模板
// （占位 host + 空 cookie）并返回，引导用户编辑填入真实地址与 Cookie。
func EnsureConfig() (*Config, error) {
	cfg, err := Load()
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, ErrNotConfigured) {
		return nil, err
	}
	tpl := &Config{Host: ExampleHost, Cookie: ""}
	if err := Save(tpl); err != nil {
		return nil, fmt.Errorf("创建示例配置失败：%w", err)
	}
	return tpl, nil
}

// MaskedCookie 返回脱敏后的 Cookie：仅显示前后各 8 字符，中间以省略号代替；
// 过短的 Cookie 整体打码。用于 `config show` 输出，避免完整凭据泄露到终端。
func (c *Config) MaskedCookie() string {
	const edge = 8
	if len(c.Cookie) <= edge*2 {
		return "********"
	}
	return c.Cookie[:edge] + "..." + c.Cookie[len(c.Cookie)-edge:]
}

// CSRF 返回 Cookie 串中的 jms_csrftoken。
//
// JumpServer 自定义了 CSRF 的 cookie 名（jms_csrftoken），与 Django 默认的
// csrftoken 不同——connection-token 接口校验 X-CSRFToken 头，用 csrftoken 会报
// 'token from header incorrect'（实测结论，见设计文档附录 D V3）。
func (c *Config) CSRF() string {
	return ExtractCookie(c.Cookie, "jms_csrftoken")
}

// ExtractCookie 从 "k=v; k2=v2" 格式的 Cookie 串中提取指定键的值；
// 键不存在或格式异常返回空串。
func ExtractCookie(raw, name string) string {
	for _, part := range strings.Split(raw, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && k == name {
			return v
		}
	}
	return ""
}
