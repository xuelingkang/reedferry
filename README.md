# Reedferry

> 谁谓河广？一苇杭之。——《诗经·卫风·河广》

在本地终端中连接 JumpServer 资产的轻量工具——不依赖 SSH 直连端口，借道 JumpServer 的 Web 终端通道（WebSocket），找回 `ssh` 手感的本地终端体验。

## 为什么需要它

许多 JumpServer 部署只开放浏览器 Web 终端通道（443 WebSocket），不提供 SSH 直连端口，导致本地 `ssh` 无法连接资产。浏览器终端虽然可用，但缺少本地终端的手感：本地快捷键、多标签、复制粘贴、终端复用工具等。

Reedferry 让本地终端借道 Web 通道连接 JumpServer 资产，全程仍走 JumpServer 审计。

## 特性

- 交互式 REPL：资产列表分页、关键字过滤、编号/主机名/IP 直连
- 认证复用浏览器登录会话（Cookie），不触碰 MFA 登录流程
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

1. 浏览器登录 JumpServer（过 MFA）
2. 复制会话 Cookie：F12 → Network → 任选一个请求 → Request Headers → **Cookie 行** → 复制
3. 首次运行 `reedferry` 会自动创建配置文件 `~/.config/reedferry/config.json`（示例模板），编辑填入 JumpServer 地址与 Cookie：

   ```json
   {
     "host": "https://your-jumpserver.example.com",
     "cookie": "sessionid=xxx; csrftoken=yyy"
   }
   ```

4. 重新运行 `reedferry`，输入 `list` 查看资产，输入编号或主机名连接

## 命令

```
list / l         显示资产列表（分页，每页 10 条）
next / n         下一页
prev / p         上一页
/关键字           按主机名/IP 本地过滤（输入 / 清除过滤）
<编号>           直接连接列表中的资产
<主机名或IP>      直接输入名称连接
reload / r       重新拉取资产（编辑配置文件后生效）
help / ?         显示本帮助
exit / quit      退出（Ctrl-D 同样可退出）
```

## 工作原理

```
本地终端 (raw mode)  ←→  koko WebSocket (wss://)  ←→  JumpServer 资产
```

1. **认证**：复用浏览器登录会话 Cookie（含 `sessionid`/`jms_csrftoken`），不自动化登录
2. **建连**：`POST /api/v1/authentication/connection-token/` 创建连接 token（带 CSRF 头），再以 `wss://{host}/koko/ws/terminal/?token={token}` 握手
3. **传输**：Text 帧为 JSON 控制消息（CONNECT/CLOSE 等），Binary 帧为原始终端字节流，双向透传

## 配置

配置文件位于 `~/.config/reedferry/config.json`（权限 0600）：

| 字段 | 说明 |
| --- | --- |
| `host` | JumpServer 地址，如 `https://your-jumpserver.example.com` |
| `cookie` | 浏览器会话 Cookie（含登录凭据，请勿提交至版本库） |

首次运行自动创建示例模板；编辑后 `reload` 生效或重启程序。

## 安全说明

- Cookie 等价于浏览器登录态，配置文件请妥善保管（默认 0600 权限）
- 连接仍经 JumpServer koko Web 通道，审计记录与浏览器 Web 终端一致
- 本项目不自动化登录流程，不绕过 MFA

## 技术栈

- Go 1.26+，单二进制
- [gorilla/websocket](https://github.com/gorilla/websocket)：WebSocket 客户端
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term)：终端 raw mode 与尺寸

## 致谢

- 协议链路验证参考 [karin0/jumpserver-proxy](https://github.com/karin0/jumpserver-proxy)（开源项目）

## License

MIT
