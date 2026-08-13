package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 测试辅助：重定向配置文件路径到临时目录，并在用例结束后恢复。
func withConfigPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := pathOverride
	pathOverride = filepath.Join(dir, "config.json")
	t.Cleanup(func() { pathOverride = old })
	return dir
}

// U2: 配置原子写——保存后可读回一致，文件权限 0600，无临时文件残留
func TestSaveLoadRoundTrip(t *testing.T) {
	dir := withConfigPath(t)
	c := &Config{Host: "https://your-jumpserver.example.com", Cookie: "sessionid=abc; csrftoken=xyz"}
	if err := Save(c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	fi, err := os.Stat(pathOverride)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0600 {
		t.Errorf("config permission: got %o want 600", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("temp file residue: dir has %d entries, want 1 (only config.json)", len(entries))
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Host != c.Host || got.Cookie != c.Cookie {
		t.Errorf("round trip mismatch: got %+v want %+v", got, c)
	}
}

// U2 变体: 配置文件不存在时返回 ErrNotConfigured 而非报内部错误
func TestLoadNotConfigured(t *testing.T) {
	withConfigPath(t)
	if _, err := Load(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Load on missing file: got %v, want ErrNotConfigured", err)
	}
}

// U2 变体: 覆盖已有配置（原子写需保证重复保存不残留）
func TestSaveOverwrites(t *testing.T) {
	dir := withConfigPath(t)
	if err := Save(&Config{Host: "a", Cookie: "b"}); err != nil {
		t.Fatalf("Save #1: %v", err)
	}
	if err := Save(&Config{Host: "c", Cookie: "d"}); err != nil {
		t.Fatalf("Save #2: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file residue after overwrite: %d entries", len(entries))
	}
	got, err := Load()
	if err != nil || got.Host != "c" || got.Cookie != "d" {
		t.Errorf("overwrite failed: got %+v err %v", got, err)
	}
}

// FR-1: config show 的 Cookie 脱敏——仅显示前后 8 字符
func TestMaskedCookie(t *testing.T) {
	c := &Config{Cookie: "sessionid=abcdefgh; csrftoken=ijklmnopqrstuvwx"}
	m := c.MaskedCookie()
	if !strings.HasPrefix(m, "sessioni") {
		t.Errorf("masked cookie: want prefix %q, got %q", "sessioni", m)
	}
	if !strings.HasSuffix(m, "rstuvwx") {
		t.Errorf("masked cookie: want suffix %q, got %q", "rstuvwx", m)
	}
	if strings.Contains(m, "efgh; csrftoken=ijklm") {
		t.Errorf("masked cookie leaked middle part: %q", m)
	}
}

// 短 Cookie（<=16 字符）整体打码，不泄露
func TestMaskedCookieShort(t *testing.T) {
	c := &Config{Cookie: "short"}
	m := c.MaskedCookie()
	if strings.Contains(m, "short") {
		t.Errorf("short cookie leaked: %q", m)
	}
}

// 配置文件不存在时 EnsureConfig 自动创建示例模板（占位 host + 空 cookie）
func TestEnsureConfigCreatesTemplate(t *testing.T) {
	withConfigPath(t)
	cfg, err := EnsureConfig()
	if err != nil {
		t.Fatalf("EnsureConfig: %v", err)
	}
	if cfg.Host != ExampleHost {
		t.Errorf("template host: got %q want %q", cfg.Host, ExampleHost)
	}
	if cfg.Cookie != "" {
		t.Errorf("template cookie: got %q, want empty", cfg.Cookie)
	}
	// 模板已落盘
	onDisk, err := Load()
	if err != nil {
		t.Fatalf("Load after EnsureConfig: %v", err)
	}
	if onDisk.Host != ExampleHost || onDisk.Cookie != "" {
		t.Errorf("on-disk template mismatch: %+v", onDisk)
	}
	// 已存在时返回现有配置，不覆盖
	if err := Save(&Config{Host: "https://real.example.com", Cookie: "k=v"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := EnsureConfig()
	if err != nil {
		t.Fatalf("EnsureConfig existing: %v", err)
	}
	if got.Host != "https://real.example.com" {
		t.Errorf("EnsureConfig should not overwrite: got %q", got.Host)
	}
}

// Path 默认路径：$HOME/.config/reedferry/config.json（XDG 风格，跨平台统一）
func TestPathXDG(t *testing.T) {
	old := pathOverride
	pathOverride = ""
	t.Cleanup(func() { pathOverride = old })
	t.Setenv("HOME", "/home/testuser")
	if got := Path(); got != "/home/testuser/.config/reedferry/config.json" {
		t.Errorf("Path: got %q", got)
	}
}

// ExtractCookie：从 Cookie 串提取指定键的值
func TestExtractCookie(t *testing.T) {
	raw := "sessionid=abc123; jms_csrftoken=CSRF-TOKEN; csrftoken=other"
	if got := ExtractCookie(raw, "jms_csrftoken"); got != "CSRF-TOKEN" {
		t.Errorf("jms_csrftoken: got %q", got)
	}
	if got := ExtractCookie(raw, "sessionid"); got != "abc123" {
		t.Errorf("sessionid: got %q", got)
	}
	if got := ExtractCookie(raw, "missing"); got != "" {
		t.Errorf("missing key: got %q, want empty", got)
	}
}

// CSRF：取 jms_csrftoken（JumpServer 自定义 cookie 名，非 Django 默认 csrftoken）
func TestConfigCSRF(t *testing.T) {
	c := &Config{Cookie: "sessionid=abc; jms_csrftoken=REAL-CSRF; csrftoken=dummy"}
	if got := c.CSRF(); got != "REAL-CSRF" {
		t.Errorf("CSRF: got %q, want REAL-CSRF", got)
	}
	// 无 jms_csrftoken 时返回空串
	if got := (&Config{Cookie: "sessionid=abc; csrftoken=dummy"}).CSRF(); got != "" {
		t.Errorf("CSRF without jms_csrftoken: got %q, want empty", got)
	}
}
