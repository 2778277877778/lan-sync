# 局域网 Telegram（lan-telegram）设计草案

> 分支：`feature/lan-telegram`
> 状态：**M1 实施中**（存储 + 协议）。方向已确认。
> 基线：`lan-sync` v1.1.4（已有的服务端、密钥、发现、GUI、打包链路都复用）

## 0. 已确认的决策（2026-11-07）

| 项 | 决定 |
|---|---|
| 安全档位 | **B 档的强化版**：TLS 1.3 + 自签证书 + 指纹固定；密钥协商 X25519，载荷 AEAD |
| 历史保留 | **本地永久保存**，不自动清理 |
| 应用形态 | **独立应用**（`lan-telegram`），不与 lan-sync 合并 |
| 加密强度 | 强加密优先，接受为此引入 `cryptography` 依赖（打包进 exe） |

加密方案说明：
- 用 `cryptography`（已在本机，版本 50.0.2）生成自签证书、跑 TLS 1.3（X25519 + AES-256-GCM / ChaCha20-Poly1305）
- 首次配对时双方交换证书指纹（SHA-256 前 8 组），人工核对一次，之后固定，防中间人
- TLS 1.3 自带前向保密，比自研 AEAD 协议更稳妥；密码学代码越少越好
- 代价：exe 体积增加约 8 MB；放弃"纯标准库"这条原始约束


---

## 1. 一句话目标

在同一个局域网里，做一个**像 Telegram 一样好用**的双机/多机聊天工具：有会话列表、消息记录、已读回执、在线状态、文件与图片，**不经过任何服务器**，纯 Python 标准库。

## 2. 与 lan-sync 的关系

lan-sync 现在是「发完就走」的传输工具：消息写进 `messages.jsonl`，收件箱是一堆条目。
lan-telegram 要的是「持续的对话」：有会话、有历史、有状态。

| 能力 | lan-sync 现状 | lan-telegram 需要 | 处理 |
|---|---|---|---|
| 服务端 | `ThreadingHTTPServer` + 密钥 | 同一套 | **直接复用** |
| 认证 | `X-Sync-Key` | 同一套（可加签名） | 复用 |
| 发现 | 三路（广播/历史/扫描） | 同一套 | 复用 |
| 存储 | `messages.jsonl` 追加 | 会话/消息/回执/队列 | **换成 SQLite** |
| 取新消息 | 前端每 2.5 秒全量拉 | 增量推送 | **新增长轮询事件流** |
| 传输 | 文本 + 整文件 PUT | 文本 + 附件 + 缩略图 | 扩展 |
| 界面 | 发送页 / 收件箱表格 | 聊天式气泡界面 | **重做 UI 层** |
| 打包 | PyInstaller 单文件 | 同一套 | 复用 |

结论：**传输骨架保留，存储和界面重写**。这也是把它放在独立分支的原因——改动面大，不该污染稳定版。

## 3. 核心概念

- **设备（Device）**：一台装了程序的电脑，有稳定 ID（首次启动生成 UUID），名称可改。
- **联系人（Contact）**：记住的对方设备，含 IP、端口、设备 ID、信任状态。
- **会话（Conversation）**：两个人之间的对话（V2 再加群）。
- **消息（Message）**：文本/文件/图片，带全局唯一 ID。
- **回执（Receipt）**：送达 / 已读。

## 4. 数据模型（SQLite）

```sql
devices(id TEXT PK, name TEXT, ip TEXT, port INT, last_seen INT, trusted INT)
conversations(id TEXT PK, peer_device TEXT, title TEXT, created_at INT, last_msg_at INT,
              unread INT, muted INT)
messages(id TEXT PK,                -- uuid4，幂等去重的关键
         conv TEXT, sender TEXT, ts INT, local_ts INT,
         kind TEXT,                 -- text | file | image | system
         body TEXT,                 -- JSON
         reply_to TEXT, state TEXT, -- queued|sent|delivered|read|failed
         edited_at INT)
receipts(message_id TEXT, device TEXT, state TEXT, ts INT, PRIMARY KEY(message_id, device))
outbox(message_id TEXT PK, attempts INT, next_try INT)
cursor(device TEXT PK, last_event INT)   -- 事件流游标
```

要点：
- 用 SQLite 而不是 JSONL：分页、未读数、搜索、去重都靠索引，JSONL 会越用越慢。
- `messages.id` 是幂等键：重发同一条不会产生重复。
- `ts` 保留发送方时间，另存 `local_ts` 用于本机排序，避免两台机器时钟不一致导致消息乱序。

## 5. 通信协议（V2）

沿用现有 HTTP 服务，新增一组端点：

| 端点 | 方法 | 作用 |
|---|---|---|
| `/api/v2/hello` | POST | 握手：交换设备 ID、名称、版本、在线心跳 |
| `/api/v2/messages` | POST | 投递消息（幂等，按 `id` 去重） |
| `/api/v2/events?since=N` | GET | **长轮询**取增量事件，最多挂 25 秒 |
| `/api/v2/ack` | POST | 回执：`delivered` / `read` |
| `/api/v2/history?conv=&before=` | GET | 翻历史，分页 |
| `/api/v2/typing` | POST | 正在输入 |

消息信封：

```json
{
  "id": "9f3c…",
  "conv": "dm:deviceB",
  "from": "deviceA", "to": "deviceB",
  "ts": 1762400000123,
  "kind": "text",
  "body": {"text": "在吗"},
  "reply_to": null
}
```

**为什么用长轮询而不是 WebSocket**：标准库没有 WebSocket，自己实现要处理掩码、分片、心跳，约 200 行且容易出错；长轮询用现成的 `http.server` 就能做到 1 秒内的实时感，代码量和风险都低得多。真需要再升级。

事件流（`/events`）返回：

```json
{"events": [
  {"type": "message", "data": {...}},
  {"type": "receipt", "message_id": "…", "state": "read"},
  {"type": "presence", "device": "deviceB", "online": true},
  {"type": "typing", "device": "deviceB"}
], "cursor": 42}
```

投递语义：
- 发送方先落本地库（`state=queued`），再投递；成功则 `sent`。
- 对方 `ack` 后变 `delivered`，对方打开会话后变 `read`（两个勾变蓝）。
- 对方离线就留在 `outbox`，按 2s/5s/15s/60s 退避重试；恢复在线自动补发。
- 同一 `id` 重复投递直接返回成功，不重复入库。

## 6. 安全

分三档，按你选的档位实现：

| 档位 | 做法 | 成本 | 防护 |
|---|---|---|---|
| A 现状 | 明文 HTTP + 密钥 | 0 | 同网段有人抓包就能看内容 |
| B 传输加密 | 标准库 `ssl` + 自签证书，配对时交换指纹并固定 | 中（要管证书） | 防偷听、防中间人（有指纹校验） |
| C 端到端 | 自实现对称加密（无 AES 库，性能差） | 高 | 防服务端被控，但纯 Python 太慢，不建议 |

**建议 B**：`ssl` 是标准库，配好自签证书 + 首次配对指纹确认，安全性够用且不破坏零依赖。

## 7. 界面

Tkinter 重写，三栏式（窗口 900×640 起）：

```
┌─────────────┬────────────────────────────────┐
│ 搜索…        │  与 deviceB 的对话      ●在线   │
│ ─────────── │ ┌────────────────────────────┐ │
│ ● deviceB  2 │ │          在吗  ← 对方       │ │
│   deviceC   │ │  在 ✓✓ 22:31  → 自己        │ │
│ ─────────── │ │  [图片缩略图]                │ │
│ 我的：myse1f │ └────────────────────────────┘ │
│             │ [输入框……………] [附件] [发送]   │
└─────────────┴────────────────────────────────┘
```

- 气泡左对方右自己，右下角时间 + 状态勾，未读在会话列表显示数字徽标
- 双击图片打开原图；拖文件进窗口即发送
- 网页端同布局，移动优先——手机浏览器打开就能聊
- 保留 `lansync.exe` 命令行习惯：`send`、`inbox` 继续可用

## 8. 群聊（V2）

不做中心服务器，用**成员间扇出**：群 = 成员列表，发送时逐一向在线成员投递，离线成员进各自 outbox。
- 排序用 `(ts, sender)`，冲突时按此顺序稳定排列
- 成员变更靠 system 消息广播
- 缺点：人数多时发送变慢、成员离线期间收不到历史（需要后来者拉取）
- 规模上限建议 10 人以内，超过就不划算

## 9. 里程碑

| 阶段 | 内容 | 验收标准 |
|---|---|---|
| M0 | 本文定稿 | ✅ 方向与档位已确认（2026-11-07） |
| M1 | SQLite 存储 + 单机双实例能聊 | ✅ 12/12 项通过：收发、已读回执、幂等、分页、重启不丢、离线入队、自动补发 |
| M2 | TLS 1.3 + 证书指纹配对 | 两端握手成功，错指纹拒绝连接 |
| M3 | 图形界面（会话列表 + 气泡） | 双击即可聊，滚动流畅 |
| M4 | 文件与图片、进度、缩略图 | 100 MB 文件带进度，图片直接预览 |
| M5 | 群聊 + 搜索 + 引用回复 | 3 台机器建群，消息顺序一致 |
| M6 | 打包独立 exe | 免安装可用 |

每个里程碑都可独立发版，不追求一次做完。

## 10. 主要风险

1. **IP 会变**：设备 ID 绑定 + `devices` 表缓存 IP，变了靠发现或手动改；群聊里 IP 变化会导致投递失败。
2. **时钟不一致**：双时间戳策略缓解；同一秒内的消息顺序可能仍与本机观感不一致。
3. **无中心排序**：群聊是最终一致，不保证全网同时可见。
4. **Tkinter 性能**：消息上千条时滚动会卡，需要虚拟化列表（只渲染可视区）。
5. **体积**：功能变多后单文件源码会到 3~5k 行，需要拆模块，但打包仍可单文件。

## 11. 需要你拍板的几点

1. **范围**：先做 1:1 文本（最快能用），还是一开始就带文件和群？
2. **安全档位**：A（明文）/ B（自签 TLS，推荐）/ C（E2E）
3. **零依赖**：坚持纯标准库，还是允许引入 `cryptography` 这类库换更强的加密？
4. **独立应用还是并入 lan-sync**：我倾向**独立**（`lan-telegram.exe`），lan-sync 保持"传完就走"的轻量定位。
5. **历史保留**：永久保存，还是保留最近 N 天/上限条数自动清理？

确认这五点后，我按 M1 开始写代码，仍然先跑通两个实例互发再加界面。
