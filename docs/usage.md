# lan-sync：局域网双机互传

纯 Python 标准库实现的点对点传输，**零第三方依赖**，不经过任何云服务，文件和数据只在你自己的局域网里流动。

## 快速开始（图形界面，推荐）

日常使用直接双击 `scripts\lan-sync-gui.exe`（或运行 `lansync.exe gui`），打开即自动在后台启动接收服务：

- **发送页**：点「发现设备」自动列出局域网内已开服务的机器，选中后发文本或文件（可多选，带进度条）
- **收件箱页**：自动刷新收到的内容，双击文件直接打开，双击文本复制到剪贴板
- **设置页**：改端口、设备名、配对密钥；改密钥会自动重启服务生效
- 顶部「打开网页」：在浏览器里打开同一套接收/上传界面（适合手机传东西到电脑）；服务没在跑时会自动先拉起
- 发送失败会**弹窗提示**、状态栏变红，不会只留一行灰字

关闭窗口后后台服务继续运行；要停服务点顶部「停止服务」。

## 部署前提（重要）

- `scripts\` 下有两套等价程序，任选其一：
  - 源码版：`lansync.py`（命令行）/ `lansync_gui.pyw`（双击直接开图形界面），需要 Python 3
  - 打包版：`lansync.exe`（命令行）/ `lan-sync-gui.exe`（图形界面），各约 14 MB，**对端免装 Python**
- 两台机器在**同一个路由器/局域网**下（连同一个 WiFi 或有线）
- 首次使用前确认 Windows 防火墙放行（见下文「防火墙」）

如果对端机器还没有本程序：先在本机执行 `firewall` 拿到放行命令，然后**用 U 盘或任意方式把 `scripts\lansync.exe` + `scripts\lan-sync-gui.exe`（对端无 Python），或 `scripts\lansync.py` + `scripts\lansync_gui.pyw`（对端有 Python）拷到对端**，放到同一目录即可，免安装。

## 核心概念

每台机器有两个身份，可同时是接收方和发送方：

| 身份 | 做什么 | 关键命令 |
|---|---|---|
| 接收方 | 起一个 HTTP 服务，等着收东西 | `serve --background` |
| 发送方 | 把文本/文件推给对方 | `send --target <对方IP>` |

**配对密钥**：防止同网段的其他设备乱发东西。两台机器的密钥必须一致，默认自动生成 8 位随机串。用 `info` 查看，用 `pair --key` 对齐。

---

## 标准操作流程

把脚本路径记为 `LA`（下文命令都基于它）。执行时一律用**绝对路径**调用：

- 源码版：`python <LA> <子命令>`，如 `python C:\tools\lansync.py info`
- exe 版：`<EXE> <子命令>`，如 `C:\tools\lansync.exe info`，子命令与源码版完全一致

### 第 1 步：确认双方网络信息

```powershell
python <LA> info
```

输出示例：

```
=== 本机 lan-sync 信息 ===
  设备名  : DESKTOP-A
  局域网IP: 192.168.1.7
  端口    : 32100
  配对密钥: 3f9c1a2b
  服务状态: 未运行（发送前请先 serve --background）
```

把这个 IP、端口、密钥三项告诉用户，或让用户从另一台机器上读出来对照。

### 第 2 步：接收方启动服务

```powershell
python <LA> serve --background
```

后台常驻，会返回 JSON：`{"already": false, "port": 32100, "pid": 12345, "key": "3f9c1a2b", "ips": ["192.168.1.7"]}`

已启动过会返回 `{"already": true, ...}`，不会重复起进程。**不需要用户保持任何窗口开着。**

### 第 3 步：两台机器对齐密钥

两台都执行一次，`<KEY>` 用同一个值（可以就用任意一台 `info` 里的密钥）：

```powershell
python <LA> pair --key <KEY>
```

`pair` 会自动重启后台服务让新密钥立即生效，不用手动 stop。

### 第 4 步：发送

```powershell
# 只发文本
python <LA> send --target 192.168.1.7 --text "老板，明天的会议改到 10 点"

# 发文件（支持多个、支持目录、支持中文名）
python <LA> send --target 192.168.1.7 --file "D:\报告\Q3总结.pdf"

# 文件 + 一句话一起发
python <LA> send --target 192.168.1.7 --text "文件已发" --file "D:\a.xlsx" "D:\b.docx"

# 不知道对方 IP？自动发现
python <LA> send --target auto --text "你好"
```

`--target` 也可以写 `IP:端口`，端口默认 32100。

### 第 5 步：接收方查看收到的内容

```powershell
python <LA> inbox
```

输出会带上每个文件的**绝对路径**，直接把这个路径告诉用户即可（文件真实落盘位置：`%USERPROFILE%\.marvis-lan-sync\inbox\files\`）。

---

## 命令速查

| 命令 | 作用 |
|---|---|
| `gui` | 打开图形界面（日常使用推荐） |
| `info` | 本机 IP / 端口 / 密钥 / 服务状态 |
| `serve` | 前台启动接收服务（会占用终端） |
| `serve --background` | 后台启动，适合 agent 调用 |
| `status` | JSON 格式的服务状态 |
| `stop` | 停止后台服务 |
| `discover` | 扫描局域网内已开服务的设备 |
| `send --target <IP> --text <内容>` | 发文本 |
| `send --target <IP> --file <路径...>` | 发文件/目录 |
| `inbox [--limit N]` | 查看收件箱 |
| `pair --key <KEY>` | 设置配对密钥并自动重启服务 |
| `firewall` | 打印 Windows 防火墙放行命令 |

---

## 网页互传界面（给人用，不是给 agent 用）

接收方起了服务后，在同网段的**任意设备浏览器**打开（包括手机）：

```
http://<接收方IP>:32100/?key=<配对密钥>
```

页面上可以直接拖文件上传、发文本、点链接下载收件箱里的文件。适合用户不想敲命令、或者想用手机传东西到电脑的场景。

---

## 防火墙

首次执行 `firewall` 会打印两条 `netsh` 命令。需要**管理员权限**的 PowerShell 执行：

```powershell
netsh advfirewall firewall add rule name="Marvis lan-sync TCP 32100" dir=in action=allow protocol=TCP localport=32100
netsh advfirewall firewall add rule name="Marvis lan-sync UDP 32101" dir=in action=allow protocol=UDP localport=32101
```

TCP 规则必须加（传文件靠它）；UDP 规则只影响 `discover` 自动发现，不加也能用 `--target 手动IP` 传。

---

## 排障对照表

| 现象 | 原因 | 处理 |
|---|---|---|
| `连不上 IP:端口` | 对方服务没起 / 防火墙拦了 / 不同网段 | 让对方 `serve --background`；查 `firewall`；双方 `info` 对比 IP 前三段是否一致 |
| `密钥不匹配（401）` | 两台 `pair` 值不一样 | 两边执行同一个 `pair --key <KEY>` |
| `discover` 找不到设备 | 路由器屏蔽广播 / 对方 UDP 被拦 | 直接用对方 `info` 里的 IP 加 `--target` |
| 提示"已有一个服务在运行" | 端口已被本机上个实例占用 | 先 `stop` 再 `serve --background` |
| 收到的文件重名 | 同名文件自动加 `(1)` `(2)` 后缀，不覆盖 | 正常行为，告知用户实际文件名 |
| 服务异常退出 | 见日志 | `%USERPROFILE%\.marvis-lan-sync\server.log` |

---

## 给 Marvis 的执行要点

1. **先 `info` 再动手**：每次接到互传任务，先跑 `info` 拿到本机 IP 和密钥，再看服务状态；未运行就直接 `serve --background`，不要让用户手动开窗口。
2. **`--background` 是首选**：除非用户明确要盯着看输出，否则一律后台启动，避免卡住终端。
3. **IP 只信 `info` 的输出**，不要凭记忆或猜网段。
4. **发送结果要如实转述**：`send` 打印的成功/失败条数、文件大小、耗时都要报给用户；失败时把 HTTP 状态码对应的原因说清楚，不要只说"失败了"。
5. **收件箱路径直接给用户**：`inbox` 输出里每条文件都有绝对路径，用 Markdown 链接形式给出，方便点击。
6. **密钥不要回显给第三方**：只在用户明确询问本机密钥时告知。
7. **多台设备时不要瞎猜**：`send --target auto` 发现多台会报错并列出候选，此时把这个列表交给用户选，不要自己挑一个。
8. **自测用 `LAN_SYNC_HOME`**：需要在一台机器上模拟两端时，给两个进程设不同的 `LAN_SYNC_HOME` 环境变量隔离数据目录，避免污染真实收件箱。
*（内容由AI生成，仅供参考）*
