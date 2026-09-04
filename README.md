# Reedferry

> 谁谓河广？一苇杭之。——《诗经·卫风·河广》

在本地终端中连接 JumpServer 资产的轻量工具——不依赖 SSH 直连端口，借道 JumpServer 的 Web 终端通道（WebSocket），找回 `ssh` 手感的本地终端体验。

## 为什么需要它

许多 JumpServer 部署只开放浏览器 Web 终端通道（443 WebSocket），不提供 SSH 直连端口，导致本地 `ssh` 无法连接资产。浏览器终端虽然可用，但缺少本地终端的手感：本地快捷键、多标签、复制粘贴、终端复用工具等。

Reedferry 让本地终端借道 Web 通道连接 JumpServer 资产，全程仍走 JumpServer 审计。

## 特性

- 交互式 REPL：资产列表分页、关键字过滤、编号/主机名/IP 直连
- 程序内登录：Cookie 为空或失效时交互式输入账号/密码（密码隐藏回显），支持 JumpServer 2FA（TOTP）动态验证码，登录成功自动写入会话 Cookie
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

### 方式一：程序内自动登录（推荐）

1. 首次运行 `reedferry` 会自动创建配置文件 `~/.config/reedferry/config.json`，编辑填入 JumpServer 地址：

   ```json
   {
     "host": "https://your-jumpserver.example.com",
     "cookie": ""
   }
   ```

2. 重新运行 `reedferry`：Cookie 为空时进入交互式登录，输入 JumpServer 账号与密码（密码隐藏回显），若系统要求 2FA 则输入动态验证码
3. 登录成功自动把会话 Cookie 写入配置文件，直接输入 `list` 查看资产、输入编号或主机名连接

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
login            重新登录（交互式输入账号密码，自动更新会话 Cookie）
help / ?         显示本帮助
exit / quit      退出（Ctrl-D 同样可退出）
```

## 工作原理

```
本地终端 (raw mode)  ←→  koko WebSocket (wss://)  ←→  JumpServer 资产
```

1. **认证**：会话 Cookie 两种来源——程序内交互式登录（账号密码 + 可选 2FA，密码传输按服务端下发 RSA/AES 加密协议，登录成功后自动写入配置）；或手动复制浏览器会话 Cookie 粘贴到配置。API 请求带 `sessionid`/`jms_csrftoken`，CSRF 头取 `jms_csrftoken`
2. **建连**：`POST /api/v1/authentication/connection-token/` 创建连接 token（带 CSRF 头），再以 `wss://{host}/koko/ws/terminal/?token={token}` 握手
3. **传输**：Text 帧为 JSON 控制消息（CONNECT/CLOSE 等），Binary 帧为原始终端字节流，双向透传

## 配置

配置文件位于 `~/.config/reedferry/config.json`（权限 0600）：

| 字段 | 说明 |
| --- | --- |
| `host` | JumpServer 地址，如 `https://your-jumpserver.example.com` |
| `cookie` | 会话 Cookie（登录凭据，请勿提交至版本库）。可由程序内登录自动写入，也可手动粘贴浏览器 Cookie |

首次运行自动创建示例模板（host 占位、cookie 为空）；Cookie 为空或失效时程序会引导交互式登录；编辑后 `reload` 生效或重启程序。

## 安全说明

- Cookie 等价于浏览器登录态，配置文件请妥善保管（默认 0600 权限）
- 账号密码与 2FA 验证码仅用于本次会话换取 Cookie：输入时隐藏回显，不打印、不写日志、不落盘，任何情况下不持久化
- 密码传输遵循 JumpServer 登录协议：服务端下发 RSA 公钥，密码经 AES/ECB 加密、密钥经 RSA 加密后提交（与浏览器一致）
- 连接仍经 JumpServer koko Web 通道，审计记录与浏览器 Web 终端一致

## 技术栈

- Go 1.26+，单二进制
- [gorilla/websocket](https://github.com/gorilla/websocket)：WebSocket 客户端
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term)：终端 raw mode 与尺寸

## 致谢

- 协议链路验证参考 [karin0/jumpserver-proxy](https://github.com/karin0/jumpserver-proxy)（开源项目）

## License

MIT
