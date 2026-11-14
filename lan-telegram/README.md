# lan-telegram

局域网聊天，独立应用。设计见 [docs/lan-telegram-design.md](../docs/lan-telegram-design.md)。

> 当前阶段：**M2 已完成**（本地存储 + 点对点协议 + 命令行 + TLS 1.3 加密）
> 图形界面在 M3。

## 现在能做什么

- 两个实例互相发文本消息，历史永久保存在本地 SQLite
- 已读回执：对方看完，你这边状态从「已送达」变「已读」
- 消息幂等：同一条重复投递不会产生两条记录
- 离线队列：对方没开服务时消息入队，指数退避（2/5/15/30/60 秒封顶）自动补发
- 历史分页：按时间戳往前翻，不受内存限制
- **传输加密**：自签证书 + 指纹人工核对固定，配对后仅允许 TLS 1.3，
  未固定 / 换证书的连接在握手层直接拒绝；证书 CN 内嵌设备 ID，TLS 下 `from` 无法伪造

## 加密配对流程

两台机器各执行一次（顺序：先 trust 再 tls on）：

```powershell
python lantelegram.py cert                                # 显示本机 8 组指纹
# 把指纹念给对方核对，然后互相固定：
python lantelegram.py trust --target <对方IP:端口> --expect <对方指纹>
python lantelegram.py tls on                              # 切换到 TLS 1.3（自动重启服务）
```

`tls off` 可退回明文；`trust --list` / `trust --remove <指纹前缀>` 管理固定记录。
对方换证书后需重新 trust，旧记录先用 `--remove` 清掉。

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
| `cert` | 查看/生成本机自签证书与指纹 |
| `trust --target IP[:端口] --expect <指纹>` | 核对并固定对端证书（另有 `--pem` / `--list` / `--remove`） |
| `tls on/off/status` | 启用 / 关闭 / 查看 TLS 1.3（on 需至少固定一个对端） |

## 数据布局

```
%USERPROFILE%\.lan-telegram\      （可用 LAN_TG_HOME 覆盖）
├── config.json     设备 ID / 名称 / 端口 / 密钥 / tls 开关
├── messages.db     SQLite：设备、会话、消息、回执、待发队列、事件流
├── state.json      运行状态
├── server.log      服务日志
└── certs/
    ├── cert.pem    本机自签证书（Ed25519，CN 内嵌设备 ID，10 年）
    ├── key.pem     本机私钥
    └── pins/       已固定的对端证书（按指纹命名，pins.json 记录来源）
```

## 协议（V2）

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api/v2/ping` | GET | 探活，返回服务与设备信息（TLS 下附带指纹） |
| `/api/v2/cert` | GET | 拉取本机证书 PEM 与指纹（公开信息，配对阶段免密钥可用） |
| `/api/v2/hello` | POST | 握手，交换设备 ID / 名称 / 端口（TLS 下校验证书 CN 与声明一致） |
| `/api/v2/messages` | POST | 投递消息，按 `id` 幂等去重 |
| `/api/v2/events?since=N` | GET | 长轮询取增量事件（最长挂 25 秒） |
| `/api/v2/ack` | POST | 已读回执 |
| `/api/v2/history?conv=&before=&limit=` | GET | 分页拉历史 |

鉴权沿用 lan-sync 的 `X-Sync-Key` 头（或 `?key=`）。`/cert` 是唯一免密钥端点（证书公开）。

## 测试

```powershell
python tests/m1_check.py      # M1 验收：收发 / 回执 / 幂等 / 分页 / 重启 / 离线入队
python tests/resend_check.py  # 离线队列自动补发
python tests/m2_check.py      # M2 验收：指纹配对 / TLS1.3 强制 / 明文与1.2拒绝 / 错指纹拒连
```

Windows GBK 控制台先 `$env:PYTHONUTF8="1"`。m1/m2 测试脚本内 APP 路径为绝对路径，
换机器需改 tests 里的 `APP`。

## 路线

- [x] **M1** 存储 + 协议 + CLI
- [x] **M2** TLS 1.3 加密、证书指纹配对（2026-11-14）
- [ ] **M3** 图形界面（会话列表 + 气泡 + 附件）
- [ ] **M4** 文件与图片、缩略图、进度
- [ ] **M5** 群聊、搜索、引用回复
- [ ] **M6** 打包独立 exe

## 与 lan-sync 的关系

lan-sync 是「传完就走」的传输工具，lan-telegram 是「持续对话」的聊天应用，两者独立，互不影响。
