// Package jumpserver 封装与 JumpServer 的全部交互：REST 资产/系统用户查询、
// koko WebSocket 通道与消息协议（hex + JSON 编解码）。
//
// 消息协议对标参考实现 karin0/jumpserver-proxy（cmd/client/web.go、
// console-stream.go、main.go），基线为 JumpServer v2 时代协议；
// 目标部署为 v3.x，字段差异按容错原则处理（不 panic，由上层跳过或提示）。
package jumpserver

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// 消息类型常量（设计文档 5.2.2 协议表，v3 纯透传：仅 Text JSON 控制帧使用 type 字段）。
const (
	MsgConnect         = "CONNECT"          // 下行：连接就绪，返回会话 id
	MsgTerminalInit    = "TERMINAL_INIT"    // 上行：告知终端尺寸
	MsgTerminalData    = "TERMINAL_DATA"    // v2 时代遗留：v3 数据帧为裸字节，不再使用
	MsgTerminalResize  = "TERMINAL_RESIZE"  // 上行：窗口尺寸变化
	MsgPing            = "PING"             // 上行：应用层心跳保活
	MsgClose           = "CLOSE"            // 下行：会话结束信号（实测：exit 后 koko 发 Text JSON CLOSE 而非 WebSocket 关闭帧）
	MsgTerminalSession = "TERMINAL_SESSION" // 下行：会话信息（CONNECT 后到达，无需处理）
)

// Message 是一条 koko WebSocket 消息。
//
// 参考实现中上行消息统一携带 id（取自 CONNECT 返回的 id）；data 为字符串：
// TERMINAL_DATA 是 hex 编码的终端字节流，TERMINAL_INIT/RESIZE 是字符串化的
// {"cols":N,"rows":N}，PING 为空字符串。
type Message struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data string `json:"data"`
}

// UnmarshalJSON 对 data 字段做容错解析：
//
//   - 字符串：原样取用（基线协议）；
//   - JSON 对象/数字（v3 可能差异）：字符串化兜底，保证 TERMINAL_DATA 的
//     hex 解码失败时由上层跳过而非整个消息解析失败（设计文档异常处理要求）；
//   - null / 缺失：置空串。
func (m *Message) UnmarshalJSON(b []byte) error {
	var raw struct {
		ID   *string         `json:"id"`
		Type *string         `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.ID != nil {
		m.ID = *raw.ID
	}
	if raw.Type != nil {
		m.Type = *raw.Type
	}
	m.Data = ""
	if len(raw.Data) > 0 && string(raw.Data) != "null" {
		if raw.Data[0] == '"' {
			// 字符串
			if err := json.Unmarshal(raw.Data, &m.Data); err != nil {
				return err
			}
		} else {
			// 非字符串（对象/数字等）：原样字符串化兜底
			m.Data = string(raw.Data)
		}
	}
	return nil
}

// MarshalJSON 输出 {id,type,data} 均为字符串的消息（上行协议基线要求 data 为字符串）。
func (m *Message) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Data string `json:"data"`
	}{
		ID:   m.ID,
		Type: m.Type,
		Data: m.Data,
	})
}

// NewMessage 构造一条上行消息。
func NewMessage(typ, id, data string) *Message {
	return &Message{Type: typ, ID: id, Data: data}
}

// DataBytes 将 data 字段按 hex 解码为原始字节流（TERMINAL_DATA 使用）。
// 解码失败（非法 hex，含 v3 下 data 为对象的情形）返回错误，由上层跳过，不 panic。
func (m *Message) DataBytes() ([]byte, error) {
	return DecodeHex(m.Data)
}

// SizeData 构造 TERMINAL_INIT / TERMINAL_RESIZE 的 data：
// 字符串化的 {"cols":N,"rows":N}（与参考实现一致，data 为字符串而非 JSON 对象）。
func SizeData(cols, rows int) string {
	return fmt.Sprintf(`{"cols":%d,"rows":%d}`, cols, rows)
}

// ParseMessage 解析一条 JSON 文本帧为 Message；非法 JSON 返回错误。
func ParseMessage(raw []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse ws message: %w", err)
	}
	return &m, nil
}

// EncodeHex 将字节流编码为 hex 字符串（上行 TERMINAL_DATA 的 data）。
func EncodeHex(b []byte) string {
	return hex.EncodeToString(b)
}

// DecodeHex 将 hex 字符串解码为字节流（下行 TERMINAL_DATA 的 data）。
func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
