# lan-telegram

局域网聊天，独立应用。设计见 [docs/lan-telegram-design.md](../docs/lan-telegram-design.md)。

> 当前阶段：**M1 已完成**（本地存储 + 点对点协议 + 命令行）
> 加密（TLS 1.3 + 指纹固定）在 M2 接入，界面在 M3。

## 现在能做什么

- 两个实例互相发文本消息，历史永久保存在本地 SQLite
- 已读回执：对方看完，你这边状态从「已送达」变「已读」
- 消息幂等：同一条重复投递不会产生两条记录
- 离线队列：对方没开服务时消息入队，对方上线后自动补发
- 历史分页：按时间戳往前翻，不受内存限制

## 快速试

开两个终端，各自用独立数据目录（模拟两台机器）：

```powershell
# 终端 1
$env:LAN_TG_HOME="$env:TEMP\lt-A"
python lantelegram.py serve --port 32210

# 终端 2
$env:LAN_TG_HOME="$env:TEMP\lt-B"
python lantelegram.py serve --port 32220
```

两边密钥对齐后互发：

```powershell
# A 发给 B
$env:LAN_TG_HOME="$env:TEMP\lt-A"
python lantelegram.py send --target 127.0.0.1:32220 --text "在吗"

# B 看历史（看完自动回执已读）
$env:LAN_TG_HOME="$env:TEMP\lt-B"
python lantelegram.py history --with A
```

## 命令

| 命令 | 作用 |
|---|---|
| `serve [--port N] [--background]` | 启动接收服务 |
| `stop` / `status` / `info` | 停止 / 状态 / 本机信息 |
| `send --target IP[:端口] --text "..."` | 发消息 |
| `history [--with 设备] [--limit N] [--before TS]` | 会话列表或聊天记录 |
| `contacts` | 联系过的设备 |
| `key [--new]` / `pair --key K` | 查看 / 更换密钥 |

## 数据布局

```
%USERPROFILE%\.lan-telegram\      （可用 LAN_TG_HOME 覆盖）
├── config.json     设备 ID / 名称 / 端口 / 密钥
├── messages.db     SQLite：设备、会话、消息、回执、待发队列、事件流
├── state.json      运行状态
└── server.log       服务日志
```

## 协议（V2）

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api/v2/ping` | GET | 探活，返回服务与设备信息 |
| `/api/v2/hello` | POST | 握手，交换设备 ID / 名称 / 端口 |
| `/api/v2/messages` | POST | 投递消息，按 `id` 幂等去重 |
| `/api/v2/events?since=N` | GET | 长轮询取增量事件（最长挂 25 秒） |
| `/api/v2/ack` | POST | 已读回执 |
| `/api/v2/history?conv=&before=&limit=` | GET | 分页拉历史 |

鉴权沿用 lan-sync 的 `X-Sync-Key` 头（或 `?key=`）。

## 测试

```powershell
python tests/m1_check.py      # M1 验收：收发 / 回执 / 幂等 / 分页 / 重启 / 离线入队
python tests/resend_check.py  # 离线队列自动补发
```

## 路线

- [x] **M1** 存储 + 协议 + CLI
- [ ] **M2** TLS 1.3 加密、证书指纹配对
- [ ] **M3** 图形界面（会话列表 + 气泡 + 附件）
- [ ] **M4** 文件与图片、缩略图、进度
- [ ] **M5** 群聊、搜索、引用回复
- [ ] **M6** 打包独立 exe

## 与 lan-sync 的关系

lan-sync 是「传完就走」的传输工具，lan-telegram 是「持续对话」的聊天应用，两者独立，互不影响。
