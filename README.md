# Reedferry

> 谁谓河广？一苇杭之。——《诗经·卫风·河广》

在本地终端中连接 JumpServer 资产的轻量工具——不依赖 SSH 直连端口，借道 JumpServer 的 Web 终端通道（WebSocket），找回 `ssh` 手感的本地终端体验。

## 为什么需要它

许多 JumpServer 部署只开放浏览器 Web 终端通道（443 WebSocket），不提供 SSH 直连端口，导致本地 `ssh` 无法连接资产。浏览器终端虽然可用，但缺少本地终端的手感：本地快捷键、多标签、复制粘贴、终端复用工具等。

Reedferry 让本地终端借道 Web 通道连接 JumpServer 资产，全程仍走 JumpServer 审计。

## 特性

- 交互式 REPL：资产列表分页、关键字过滤、编号/主机名/IP 直连
- 程序内登录：Cookie 为空或失效时在终端渲染统一认证（sso.zxxk.com）的微信扫码二维码，扫码确认后自动换票并写入会话 Cookie；JumpServer 侧仍要求 2FA 时继续提示动态验证码
- 免扫码续期：同时保存统一认证域会话（`sso_cookie`），业务会话过期时先静默换票，只有统一认证会话也过期才需要再扫一次
- 兼容手动复制 Cookie：保留浏览器登录后 F12 复制 Cookie 请求头的工作流（`login` 命令 / 编辑 config.json 均可）
- 纯透传：本地终端字节流与 koko WebSocket 双向透传（v3 协议，Text JSON 控制帧 + Binary 裸字节数据帧）
- 本地终端手感：raw mode、尺寸同步、30s 心跳保活、优雅退出
- 单二进制交付，无外部依赖

## 安装

### 构建

需要 Go 1.26+：

```bash
go build -o reedferry ./cmd/reedferry
```

交叉编译（如 Linux 服务器）：

```bash
GOOS=linux GOARCH=amd64 go build -o reedferry-linux-amd64 ./cmd/reedferry
```

### 运行

```bash
./reedferry
```

## 快速开始

### 方式一：程序内扫码登录（推荐）

1. 首次运行 `reedferry` 会自动创建配置文件 `~/.config/reedferry/config.json`，编辑填入 JumpServer 地址：

   ```json
   {
     "host": "https://your-jumpserver.example.com",
     "cookie": ""
   }
   ```

2. 重新运行 `reedferry`：Cookie 为空时终端内渲染统一认证的微信二维码，用微信扫码并在手机上确认授权；若 JumpServer 仍要求 2FA，再输入动态验证码
3. 登录成功自动把会话 Cookie（业务域 + 统一认证域）写入配置文件，直接输入 `list` 查看资产、输入编号或主机名连接

### 方式二：手动复制 Cookie（原有方式）

1. 浏览器登录 JumpServer（过 MFA）
2. 复制会话 Cookie：F12 → Network → 任选一个请求 → Request Headers → **Cookie 行** → 复制
3. 编辑 `~/.config/reedferry/config.json` 填入 Cookie：

   ```json
   {
     "host": "https://your-jumpserver.example.com",
     "cookie": "sessionid=xxx; jms_csrftoken=yyy"
   }
   ```

4. 重新运行 `reedferry`（或会话失效时在 REPL 内输入 `reload` 重新拉取）

> 会话失效（401/302/403）时程序会自动提示并重新登录，无需手动处理。

## 命令

```
list / l         显示资产列表（分页，每页 10 条）
next / n         下一页
prev / p         上一页
/关键字           按主机名/IP 本地过滤（输入 / 清除过滤）
<编号>           直接连接列表中的资产
<主机名或IP>      直接输入名称连接
reload / r       重新拉取资产（编辑配置文件后生效）
login            重新登录（微信扫码，自动更新会话 Cookie）
help / ?         显示本帮助
exit / quit      退出（Ctrl-D 同样可退出）
```

## 工作原理

```
本地终端 (raw mode)  ←→  koko WebSocket (wss://)  ←→  JumpServer 资产
```

1. **认证**：会话 Cookie 两种来源——程序内扫码登录（业务 CAS 入口 → 统一认证微信扫码 → ticket 回跳 → 业务会话 Cookie，可续 2FA）；或手动复制浏览器会话 Cookie 粘贴到配置。API 请求带 `jms_sessionid`/`jms_csrftoken`，CSRF 头取 `jms_csrftoken`
2. **建连**：`POST /api/v1/authentication/connection-token/` 创建连接 token（带 CSRF 头），再以 `wss://{host}/koko/ws/terminal/?token={token}` 握手
3. **传输**：Text 帧为 JSON 控制消息（CONNECT/CLOSE 等），Binary 帧为原始终端字节流，双向透传

## 配置

配置文件位于 `~/.config/reedferry/config.json`（权限 0600）：

| 字段 | 说明 |
| --- | --- |
| `host` | JumpServer 地址，如 `https://your-jumpserver.example.com` |
| `cookie` | 业务域会话 Cookie（登录凭据，请勿提交至版本库）。可由程序内登录自动写入，也可手动粘贴浏览器 Cookie |
| `sso_cookie` | 统一认证域会话 Cookie，登录时自动写入；用于业务会话过期时静默换票，避免重复扫码 |

首次运行自动创建示例模板（host 占位、cookie 为空）；Cookie 为空或失效时程序会引导交互式登录；编辑后 `reload` 生效或重启程序。

## 安全说明

- Cookie 与 `sso_cookie` 都等价于浏览器登录态，配置文件请妥善保管（默认 0600 权限）
- 扫码授权的身份由微信侧完成，程序内不接触账号密码；2FA 动态验证码输入时隐藏回显，不打印、不写日志、不落盘
- 二维码是统一认证登录页的一次性入口（含随机 key），过期自动刷新，不包含任何凭据
- 连接仍经 JumpServer koko Web 通道，审计记录与浏览器 Web 终端一致

## 技术栈

- Go 1.26+，单二进制
- [gorilla/websocket](https://github.com/gorilla/websocket)：WebSocket 客户端
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term)：终端 raw mode 与尺寸
- [rsc.io/qr](https://pkg.go.dev/rsc.io/qr)：二维码编码（终端内以半块字符渲染）

## 致谢

- 协议链路验证参考 [karin0/jumpserver-proxy](https://github.com/karin0/jumpserver-proxy)（开源项目）

## License

MIT
