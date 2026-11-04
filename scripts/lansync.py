#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lan-sync: 局域网双机互传（文本 + 文件），纯 Python 标准库，零第三方依赖。

用法概览（详细见 SKILL.md）：
    python lansync.py gui                       # 打开图形界面（推荐给日常使用）
    python lansync.py info                      # 本机信息：IP / 端口 / 配对密钥
    python lansync.py serve --background        # 后台启动接收服务
    python lansync.py status                    # 服务状态
    python lansync.py discover                  # 发现局域网内其他机器
    python lansync.py send --target auto --text "你好"
    python lansync.py send --target 192.168.1.7 --file "D:/a.pdf"
    python lansync.py inbox                     # 查看收到的东西
    python lansync.py pair --key <共享密钥>      # 两台机器对齐配对密钥
    python lansync.py stop                      # 停止后台服务
"""

import argparse
import http.client
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "1.1.2"
SERVICE = "marvis-lan-sync"
DEFAULT_PORT = 32100
DEFAULT_DISCOVERY_PORT = 32101
CHUNK = 1 << 20  # 1 MiB
CREATE_NO_WINDOW = 0x08000000  # 子进程不弹控制台窗口（窗口版 GUI 下必须）
LOG_MAX_BYTES = 2 * 1024 * 1024


# ---------------------------------------------------------------- 配置与路径

def home_dir() -> Path:
    """数据根目录。LAN_SYNC_HOME 便于在同一台机器上跑多个实例做自测。"""
    env = os.environ.get("LAN_SYNC_HOME")
    base = Path(env) if env else Path.home() / ".marvis-lan-sync"
    return base


def paths():
    h = home_dir()
    return {
        "root": h,
        "config": h / "config.json",
        "inbox_files": h / "inbox" / "files",
        "inbox_msgs": h / "inbox" / "messages.jsonl",
        "state": h / "state.json",
        "log": h / "server.log",
    }


def load_config() -> dict:
    p = paths()
    p["root"].mkdir(parents=True, exist_ok=True)
    cfg = {
        "device_name": socket.gethostname(),
        "port": DEFAULT_PORT,
        "discovery_port": DEFAULT_DISCOVERY_PORT,
        "key": "",
    }
    existed = p["config"].exists()
    if existed:
        try:
            # utf-8-sig: 兼容记事本/PowerShell 写入的带 BOM 配置
            cfg.update(json.loads(p["config"].read_text(encoding="utf-8-sig")))
        except Exception:
            backup = p["config"].with_suffix(".broken.json")
            try:
                p["config"].replace(backup)
                print(f"[警告] 配置文件无法解析，已备份为 {backup}，将重新生成。", file=sys.stderr)
            except Exception:
                pass
    if not cfg.get("key"):
        cfg["key"] = secrets.token_hex(4)
    if not existed or not p["config"].exists():
        save_config(cfg)
    return cfg


def save_config(cfg: dict) -> None:
    p = paths()
    p["root"].mkdir(parents=True, exist_ok=True)
    p["config"].write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def read_state() -> dict:
    p = paths()
    if p["state"].exists():
        try:
            return json.loads(p["state"].read_text(encoding="utf-8-sig"))
        except Exception:
            return {}
    return {}


def write_state(st: dict) -> None:
    try:
        paths()["state"].write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- 网络工具

_LOCAL_IPS = {"at": 0.0, "ips": []}


def local_ips(max_age: float = 60.0):
    """本机局域网 IP。结果缓存一段时间：GUI 每几秒刷新一次状态，
    而探测要建 socket + getaddrinfo，没必要每次都做。"""
    now = time.time()
    if _LOCAL_IPS["ips"] and now - _LOCAL_IPS["at"] < max_age:
        return list(_LOCAL_IPS["ips"])
    ips = []
    for probe in ("8.8.8.8", "114.114.114.114"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect((probe, 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
            break
        except Exception:
            continue
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    if ips:
        _LOCAL_IPS["at"] = now
        _LOCAL_IPS["ips"] = list(ips)
    return ips


def broadcast_targets(ip_list):
    """255.255.255.255 加各网卡的定向广播，兼容屏蔽全局广播的路由器。"""
    targets = {"255.255.255.255"}
    for ip in ip_list:
        parts = ip.split(".")
        if len(parts) == 4:
            targets.add(".".join(parts[:3]) + ".255")
    return targets


def discover(timeout: float = 2.0):
    """UDP 广播寻找局域网内已启动接收服务的设备。"""
    cfg = load_config()
    dport = int(cfg.get("discovery_port", DEFAULT_DISCOVERY_PORT))
    my_name = cfg.get("device_name", socket.gethostname())
    found = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.3)

    payload = json.dumps({"service": SERVICE, "op": "discover"}).encode("utf-8")
    for target in broadcast_targets(local_ips()):
        try:
            sock.sendto(payload, (target, dport))
        except Exception:
            pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            break
        try:
            obj = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        if obj.get("service") != SERVICE or obj.get("op") != "reply":
            continue
        ip = obj.get("ip") or addr[0]
        if ip.startswith("127."):
            ip = addr[0]
        if obj.get("device") == my_name and ip in local_ips():
            continue  # 自己
        found[ip] = {
            "ip": ip,
            "device": obj.get("device", "unknown"),
            "port": obj.get("port", DEFAULT_PORT),
        }
    sock.close()
    return list(found.values())


def resolve_target(target: str):
    """把 --target 解析成 (ip, port)。auto 时自动发现唯一设备。"""
    cfg = load_config()
    if target and target.lower() != "auto":
        if ":" in target:
            host, _, port = target.rpartition(":")
            return host, int(port)
        return target, int(cfg.get("port", DEFAULT_PORT))

    peers = discover()
    if not peers:
        die("没有发现在线设备。请确认对端已执行 `serve`，且两台机器在同一局域网。")
    if len(peers) > 1:
        lines = ["发现多台设备，请用 --target <IP> 指定："]
        for p in peers:
            lines.append(f"    {p['ip']}  ({p['device']})")
        die("\n".join(lines))
    return peers[0]["ip"], int(peers[0]["port"])


def existing_instance(port: int):
    """端口上是否已有 lan-sync 服务在响应。Windows 的 SO_REUSEADDR 允许两个进程
    同时 bind 同一端口，连接会被随机分走，必须靠这个预检把双开挡在门外。"""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1.5)
        conn.request("GET", "/api/ping")
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "ignore")
        conn.close()
        obj = json.loads(raw)
        if obj.get("service") == SERVICE:
            return obj
    except Exception:
        pass
    return None


def verify_self(port: int, key: str) -> bool:
    """用自家密钥访问一次，确认端口上应答的确实是本进程，而不是残留实例。"""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/api/inbox?key=" + urllib.parse.quote(key))
        resp = conn.getresponse()
        resp.read()
        ok = resp.status == 200
        conn.close()
        return ok
    except Exception:
        return False


def die(msg: str, code: int = 1):
    print(f"[错误] {msg}", file=sys.stderr)
    sys.exit(code)


def _ensure_streams():
    """窗口版 exe（无控制台）下 sys.stdout/stderr 可能是 None，补上空流避免 print 崩溃。"""
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = sys.stdout


# ---------------------------------------------------------------- 接收服务

def unique_path(folder: Path, name: str) -> Path:
    name = os.path.basename(name) or "unnamed"
    target = folder / name
    if not target.exists():
        return target
    stem, suffix = os.path.splitext(name)
    i = 1
    while True:
        cand = folder / f"{stem}({i}){suffix}"
        if not cand.exists():
            return cand
        i += 1


class SyncServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """浏览器预连接/取消下载会不断触发 ConnectionReset，默认实现会把完整堆栈
        写进日志，把真正的错误淹掉。这类断连属于正常现象，直接忽略。"""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError, TimeoutError)):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = f"LanSync/{VERSION}"
    protocol_version = "HTTP/1.1"
    timeout = 60  # 空闲连接不无限占线程

    # ---- 基础响应 ----
    def _json(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if code >= 400:
            # 鉴权失败时客户端可能还没发完 body，直接断开比留在 keep-alive 里更安全
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code: int, text: str):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self, query: dict) -> bool:
        key = self.headers.get("X-Sync-Key") or query.get("key", [""])[0]
        return bool(key) and key == self.server.sync_key

    def log_message(self, fmt, *args):
        line = f"{now_str()} {self.address_string()} {fmt % args}\n"
        try:
            log = paths()["log"]
            # 简单轮转：超限就改名，避免日志无限增长
            if log.exists() and log.stat().st_size > LOG_MAX_BYTES:
                backup = log.with_suffix(".1.log")
                try:
                    if backup.exists():
                        backup.unlink()
                    log.replace(backup)
                except Exception:
                    pass
            with open(log, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    # ---- GET ----
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        p = paths()
        cfg = load_config()

        if route == "/api/ping":
            return self._json(200, {
                "ok": True, "service": SERVICE, "version": VERSION,
                "device": cfg.get("device_name"), "auth_required": True,
            })

        if route == "/":
            token = query.get("key", [""])[0]
            if token != self.server.sync_key:
                return self._html(401, "<h3>需要密钥</h3><p>请访问 http://IP:端口/?key=配对密钥</p>")
            return self._html(200, WEB_UI.replace("__KEY__", token))

        if route == "/api/inbox":
            if not self._authed(query):
                return self._json(401, {"ok": False, "error": "密钥不匹配"})
            return self._json(200, {"ok": True, "items": inbox_items()})

        if route == "/api/download":
            if not self._authed(query):
                return self._json(401, {"ok": False, "error": "密钥不匹配"})
            name = query.get("name", [""])[0]
            fpath = p["inbox_files"] / os.path.basename(name)
            if not fpath.exists():
                return self._json(404, {"ok": False, "error": "文件不存在"})
            size = fpath.stat().st_size
            self.send_response(200)
            disp = urllib.parse.quote(fpath.name)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{disp}")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(fpath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            return

        return self._json(404, {"ok": False, "error": "not found"})

    # ---- POST: 文本 ----
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self._authed(query):
            self._json(401, {"ok": False, "error": "密钥不匹配"})
            return
        if parsed.path != "/api/text":
            self._json(404, {"ok": False, "error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "error": "bad json"})
            return
        text = (obj.get("text") or "").strip()
        if not text:
            self._json(400, {"ok": False, "error": "空内容"})
            return
        append_message(kind="text", text=text, sender=obj.get("from") or "unknown")
        self._json(200, {"ok": True, "received": len(text)})

    # ---- PUT: 文件 ----
    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self._authed(query):
            self._json(401, {"ok": False, "error": "密钥不匹配"})
            return
        if parsed.path != "/api/file":
            self._json(404, {"ok": False, "error": "not found"})
            return
        name = query.get("name", ["upload.bin"])[0]
        sender = query.get("from", ["unknown"])[0]
        length = int(self.headers.get("Content-Length") or 0)
        p = paths()
        p["inbox_files"].mkdir(parents=True, exist_ok=True)
        dest = unique_path(p["inbox_files"], name)
        received = 0
        with open(dest, "wb") as f:
            while received < length:
                chunk = self.rfile.read(min(CHUNK, length - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
        append_message(kind="file", text="", sender=sender, name=dest.name, size=received)
        self._json(200, {"ok": True, "saved": dest.name, "bytes": received})

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def append_message(kind: str, text: str, sender: str, name: str = "", size: int = 0) -> None:
    p = paths()
    p["inbox_msgs"].parent.mkdir(parents=True, exist_ok=True)
    rec = {"time": now_str(), "from": sender, "kind": kind, "text": text, "name": name, "size": size}
    with open(p["inbox_msgs"], "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def read_messages():
    p = paths()
    out = []
    if p["inbox_msgs"].exists():
        for line in p["inbox_msgs"].read_text(encoding="utf-8-sig", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def inbox_items(limit: int = 50):
    p = paths()
    msgs = read_messages()
    file_meta = {}
    items = []
    for rec in msgs:
        if rec.get("kind") == "file":
            file_meta[rec.get("name", "")] = rec
        else:
            items.append({"type": "text", "time": rec.get("time", ""),
                          "from": rec.get("from", ""), "text": rec.get("text", "")})
    if p["inbox_files"].exists():
        for f in sorted(p["inbox_files"].iterdir()):
            if not f.is_file():
                continue
            meta = file_meta.get(f.name, {})
            items.append({
                "type": "file",
                "time": meta.get("time") or datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "from": meta.get("from", ""), "name": f.name,
                "size": f.stat().st_size, "path": str(f),
            })
    items.sort(key=lambda x: x.get("time", ""))
    return items[-limit:]


def udp_responder(stop_event: threading.Event):
    cfg = load_config()
    dport = int(cfg.get("discovery_port", DEFAULT_DISCOVERY_PORT))
    port = int(cfg.get("port", DEFAULT_PORT))
    name = cfg.get("device_name", socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", dport))
    except OSError:
        return
    s.settimeout(1.0)
    while not stop_event.is_set():
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            break
        try:
            obj = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        if obj.get("service") != SERVICE or obj.get("op") != "discover":
            continue
        ips = local_ips()
        reply = json.dumps({
            "service": SERVICE, "op": "reply", "device": name,
            "port": port, "ip": ips[0] if ips else "127.0.0.1",
        }, ensure_ascii=False).encode("utf-8")
        try:
            s.sendto(reply, addr)
        except Exception:
            pass
    s.close()


def cleanup_meipass(path: str) -> None:
    """删除 PyInstaller 临时解压目录，只认 %TEMP% 下的 _MEI*。

    taskkill /F 会跳过 bootloader 的正常清理，导致每次后台启动在 TEMP 里
    留下一个十几 MB 的 _MEI 目录；stop 和下次 serve 启动时用它兜底。
    """
    if not path or path == getattr(sys, "_MEIPASS", ""):
        return
    try:
        target = Path(path).resolve()
        if target.parent != Path(tempfile.gettempdir()).resolve() or not target.name.startswith("_MEI"):
            return
        for _ in range(10):
            if not target.exists():
                return
            shutil.rmtree(target, ignore_errors=True)
            if not target.exists():
                return
            time.sleep(0.2)
    except Exception:
        pass


def cleanup_stale_meipass(st: dict) -> None:
    """兜底清理残留解压目录；bootloader 还活着时交给它自己清理（它 1 秒内完成，
    抢删反而会让它收尾卡住十几秒）。"""
    mp = st.get("meipass")
    if not mp:
        return
    boot = st.get("boot_pid")
    if boot and is_running(boot):
        return
    cleanup_meipass(mp)


def cmd_serve(args):
    cfg = load_config()

    # Windows 的 SO_REUSEADDR 允许两个进程绑同一端口，后启动的会静默抢不到请求。
    # 与其让用户对着"发了却收不到"发愣，不如在这里明确拦住。
    prev = read_state()
    if prev.get("pid") and prev["pid"] != os.getpid() and is_running(prev["pid"]):
        die(f"已有一个 lan-sync 服务在运行（PID {prev['pid']}，端口 {prev.get('port')}）。"
            f"如需重启请先执行 stop。")
    cleanup_stale_meipass(prev)

    port = int(getattr(args, "port", None) or cfg.get("port", DEFAULT_PORT))

    busy = existing_instance(port)
    if busy:
        die(f"端口 {port} 上已有一个 lan-sync 服务在运行（设备 {busy.get('device')}）。"
            f"如需重启请先执行 stop。")

    for _ in range(20):
        try:
            srv = SyncServer(("0.0.0.0", port), Handler)
            break
        except OSError:
            port += 1
    else:
        die("找不到可用端口")

    srv.sync_key = cfg["key"]
    srv.daemon_threads = True
    if port != cfg.get("port"):
        cfg["port"] = port
        save_config(cfg)

    stop_event = threading.Event()
    threading.Thread(target=udp_responder, args=(stop_event,), daemon=True).start()

    write_state({"pid": os.getpid(), "port": port, "started": now_str(),
                 "device": cfg.get("device_name"),
                 "meipass": getattr(sys, "_MEIPASS", ""),
                 "boot_pid": os.getppid()})

    print(f"[lan-sync] 接收服务已启动  {cfg.get('device_name')}")
    addrs = "  ".join(f"http://{ip}:{port}" for ip in local_ips()) or f"http://127.0.0.1:{port}"
    print(f"  地址: {addrs}")
    print(f"  配对密钥: {cfg['key']}")
    print(f"  收件目录: {paths()['root'] / 'inbox'}")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        write_state({})


def start_background():
    """以脱离父进程的方式启动服务，供 agent 一条命令搞定。"""
    cfg = load_config()
    st = read_state()
    if st.get("pid") and is_running(st["pid"]):
        return {"already": True, "port": st.get("port"), "pid": st["pid"]}

    # PyInstaller 打包后 __file__ 指向临时解压目录，必须用 exe 自身路径重启。
    # 窗口版 GUI exe 旁边若放着控制台版 lansync.exe，优先用它起服务，
    # 避免无控制台进程的 stdout 语义问题（日志仍由 start_background 重定向到文件）。
    if getattr(sys, "frozen", False):
        exe = sys.executable
        sibling = Path(exe).with_name("lansync.exe")
        if sibling.exists() and str(sibling).lower() != str(exe).lower():
            exe = str(sibling)
        cmd = [exe, "serve"]
    else:
        cmd = [sys.executable, os.path.abspath(__file__), "serve"]
    log = paths()["log"]
    paths()["root"].mkdir(parents=True, exist_ok=True)
    creationflags = 0
    if os.name == "nt":
        creationflags = 0x00000008 | 0x00000200 | CREATE_NO_WINDOW  # DETACHED | 新进程组 | 不弹窗
    # PyInstaller onefile 子进程会继承 _PYI_APPLICATION_HOME_DIR / _PYI_PARENT_PROCESS_LEVEL
    # 转而复用父进程的解压目录，父进程退出时便删不掉自己的 _MEI 目录（警告 + 残留），
    # 还存在清理竞态。这两个变量一起摘掉，子进程才会当作全新启动、解压到独立目录。
    env = dict(os.environ)
    env.pop("_PYI_APPLICATION_HOME_DIR", None)
    env.pop("_PYI_PARENT_PROCESS_LEVEL", None)
    env.pop("_MEIPASS2", None)
    logf = open(log, "a", encoding="utf-8")
    proc = subprocess.Popen(
        cmd,
        stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
        creationflags=creationflags, close_fds=True, env=env,
    )
    for _ in range(40):
        time.sleep(0.15)
        st = read_state()
        if st.get("pid") and is_running(st["pid"]):
            port = st.get("port") or cfg.get("port")
            info = {"already": False, "port": port, "pid": st["pid"],
                    "key": cfg["key"], "ips": local_ips()}
            if not verify_self(port, cfg["key"]):
                info["warning"] = (f"端口 {port} 上应答的不是本进程，可能有残留实例占着该端口；"
                                   f"先执行 stop 或结束残留 python 进程后重试。")
            return info
    return {"already": False, "port": None, "pid": proc.pid, "warning": "启动超时，请查看日志",
            "log": str(log)}


def _win_handle_alive(pid: int):
    """用 Win32 API 判断进程存活，避免启动 tasklist 子进程。

    从窗口版 GUI 里 spawn 任何控制台程序都会闪一下黑窗，所以这条热路径
    （状态栏每 4 秒查一次、启动时轮询 40 次）必须走零进程的实现。
    返回 True/False；取不到结论时返回 None 以便回退。
    """
    try:
        import ctypes
        from ctypes import wintypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h:
            return True if ctypes.get_last_error() == 5 else False  # 5=拒绝访问，说明进程在
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return None
            return code.value == STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        return None


def _win_terminate(pid: int) -> bool:
    try:
        import ctypes
        PROCESS_TERMINATE = 0x0001
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not h:
            return False
        try:
            return bool(k32.TerminateProcess(h, 1))
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False


def is_running(pid: int) -> bool:
    if not pid:
        return False
    try:
        pid = int(pid)
    except Exception:
        return False
    if os.name == "nt":
        alive = _win_handle_alive(pid)
        if alive is not None:
            return alive
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                                 capture_output=True, text=True, timeout=10,
                                 creationflags=CREATE_NO_WINDOW)
            return str(pid) in out.stdout
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def stop_service(quiet: bool = False):
    st = read_state()
    pid = st.get("pid")
    if not pid or not is_running(pid):
        write_state({})
        cleanup_stale_meipass(st)
        if not quiet:
            print("[lan-sync] 服务未在运行")
        return False
    try:
        if os.name == "nt":
            if not _win_terminate(pid):
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True,
                               timeout=15, creationflags=CREATE_NO_WINDOW)
        else:
            os.kill(pid, 15)
        if not quiet:
            print(f"[lan-sync] 已停止服务 (PID {pid})")
    except Exception as e:
        if not quiet:
            print(f"[错误] 停止失败: {e}", file=sys.stderr)
    cleanup_stale_meipass(st)
    write_state({})
    return True


# ---------------------------------------------------------------- 发送

def post_text(ip: str, port: int, key: str, text: str, sender: str) -> dict:
    conn = http.client.HTTPConnection(ip, port, timeout=20)
    body = json.dumps({"text": text, "from": sender}, ensure_ascii=False).encode("utf-8")
    conn.request("POST", "/api/text", body=body, headers={
        "Content-Type": "application/json; charset=utf-8",
        "X-Sync-Key": key,
        "Content-Length": str(len(body)),
    })
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", "ignore")
    conn.close()
    return {"status": resp.status, "body": data}


def put_file(ip: str, port: int, key: str, path: Path, sender: str, progress=None) -> dict:
    size = path.stat().st_size
    q = urllib.parse.urlencode({"name": path.name, "from": sender})
    conn = http.client.HTTPConnection(ip, port, timeout=300)
    conn.putrequest("PUT", f"/api/file?{q}")
    conn.putheader("X-Sync-Key", key)
    conn.putheader("Content-Type", "application/octet-stream")
    conn.putheader("Content-Length", str(size))
    conn.endheaders()
    sent = 0
    t0 = time.time()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            conn.send(chunk)
            sent += len(chunk)
            if progress:
                try:
                    progress(sent, size)
                except Exception:
                    pass
            elif size > 8 * 1024 * 1024:
                pct = sent * 100 // max(size, 1)
                print(f"\r  上传 {pct}% ({sent // 1024} / {size // 1024} KB)", end="", flush=True)
    if not progress and size > 8 * 1024 * 1024:
        print()
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", "ignore")
    conn.close()
    cost = max(time.time() - t0, 0.001)
    return {"status": resp.status, "body": data, "seconds": round(cost, 2), "bytes": size}


def cmd_send(args):
    cfg = load_config()
    if not args.text and not args.file:
        die("没有要发送的内容，请加 --text 或 --file")
    ip, port = resolve_target(args.target)
    sender = cfg.get("device_name", socket.gethostname())

    # 先 ping 探活，给出比 401 更明确的错误
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=5)
        conn.request("GET", "/api/ping")
        r = conn.getresponse()
        info = json.loads(r.read().decode("utf-8", "ignore") or "{}")
        conn.close()
    except Exception as e:
        die(f"连不上 {ip}:{port} —— {e}\n请确认对端已启动服务（serve），且防火墙已放行该端口。")

    results = []
    if args.text:
        res = post_text(ip, port, cfg["key"], args.text, sender)
        if res["status"] == 401:
            die("密钥不匹配（401）。请在两台机器上执行 `pair --key <同一个密钥>` 对齐后重试。")
        results.append(("文本", res["status"]))

    for f in args.file or []:
        fp = Path(f).expanduser()
        if not fp.exists():
            die(f"文件不存在: {fp}")
        files = [x for x in fp.rglob("*") if x.is_file()] if fp.is_dir() else [fp]
        if fp.is_dir():
            print(f"  目录 {fp} 内含 {len(files)} 个文件，逐个发送")
        for one in files:
            res = put_file(ip, port, cfg["key"], one, sender)
            if res["status"] == 401:
                die("密钥不匹配（401）。请在两台机器上执行 `pair --key <同一个密钥>` 对齐后重试。")
            ok = res["status"] == 200
            print(f"  {'OK' if ok else 'FAIL'} {one.name}  {res['bytes'] // 1024} KB  {res['seconds']}s")
            results.append((one.name, res["status"]))

    bad = [r for r in results if r[1] != 200]
    print(f"\n发送到 {info.get('device', '?')} ({ip}:{port})：成功 {len(results) - len(bad)}，失败 {len(bad)}")
    if bad:
        for name, code in bad:
            print(f"  失败: {name} -> HTTP {code}")
        sys.exit(1)


def cmd_info(args):
    cfg = load_config()
    st = read_state()
    ips = local_ips()
    print("=== 本机 lan-sync 信息 ===")
    print(f"  设备名  : {cfg.get('device_name')}")
    print(f"  局域网IP: {', '.join(ips) if ips else '未获取到，检查网络连接'}")
    print(f"  端口    : {cfg.get('port')}")
    print(f"  配对密钥: {cfg['key']}")
    running = bool(st.get("pid") and is_running(st["pid"]))
    print(f"  服务状态: {'运行中 PID ' + str(st.get('pid')) if running else '未运行（发送前请先 serve --background）'}")
    print(f"  数据目录: {paths()['root']}")
    print("\n对端要发东西给这台机器，需要这三项：IP + 端口 + 配对密钥")


def cmd_status(args):
    cfg = load_config()
    st = read_state()
    running = bool(st.get("pid") and is_running(st["pid"]))
    print(json.dumps({
        "running": running,
        "pid": st.get("pid") if running else None,
        "port": st.get("port") or cfg.get("port"),
        "device": cfg.get("device_name"),
        "ips": local_ips(),
        "key": cfg["key"],
        "inbox": str(paths()["root"] / "inbox"),
    }, ensure_ascii=False, indent=2))


def cmd_discover(args):
    peers = discover(timeout=args.timeout)
    if not peers:
        print("未发现局域网内其他在线设备。")
        print("提示：对端需先运行 serve；若已运行仍发现不到，路由器可能屏蔽了广播，")
        print("     可直接用对方 info 里的 IP 加 --target 手动指定。")
        return
    print(f"发现 {len(peers)} 台设备：")
    for p in peers:
        print(f"  {p['ip']:<16} {p['device']}  (端口 {p['port']})")


def cmd_pair(args):
    if not args.key:
        die("请提供密钥：pair --key <字符串>")
    cfg = load_config()
    cfg["key"] = args.key.strip()
    save_config(cfg)
    print(f"[lan-sync] 配对密钥已更新为: {cfg['key']}")
    # 服务进程启动时已把密钥读进内存，改配置后必须重启才生效，否则会出现"明明改了却仍然 401"
    st = read_state()
    if st.get("pid") and is_running(st["pid"]):
        stop_service(quiet=True)
        time.sleep(0.6)
        res = start_background()
        print(f"  服务已自动重启以应用新密钥（端口 {res.get('port', cfg['port'])}）")
    print("请在另一台机器上执行同样的命令，两边保持一致。")


def cmd_inbox(args):
    items = inbox_items(limit=args.limit)
    if not items:
        print("收件箱是空的。")
        return
    print(f"收件箱（最近 {len(items)} 条，按时间升序）\n")
    for it in items:
        if it["type"] == "text":
            print(f"[{it['time']}] 文本  from {it['from']}")
            print(f"    {it['text']}")
        else:
            print(f"[{it['time']}] 文件  {it['name']}  {it['size'] // 1024} KB  from {it['from']}")
            print(f"    路径: {it['path']}")
        print()


def cmd_firewall(args):
    cfg = load_config()
    port = cfg.get("port", DEFAULT_PORT)
    dport = cfg.get("discovery_port", DEFAULT_DISCOVERY_PORT)
    print("若对端连不上本机，多半是 Windows 防火墙拦截。用【管理员】PowerShell 执行：\n")
    print(f'  netsh advfirewall firewall add rule name="Marvis lan-sync TCP {port}" dir=in action=allow protocol=TCP localport={port}')
    print(f'  netsh advfirewall firewall add rule name="Marvis lan-sync UDP {dport}" dir=in action=allow protocol=UDP localport={dport}')
    print("\n（TCP 规则就能传文件；UDP 规则只用于自动发现，不加也能用 --target 手动指定 IP。）")


# ---------------------------------------------------------------- 网页 UI

WEB_UI = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>lan-sync 接收端</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:760px;margin:0 auto;padding:24px;line-height:1.6}
h1{font-size:20px;margin:0 0 4px}
.sub{opacity:.6;font-size:13px;margin-bottom:20px}
.card{border:1px solid #8883;border-radius:10px;padding:16px;margin-bottom:16px}
textarea{width:100%;min-height:90px;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #8886;font:inherit;background:transparent;color:inherit}
button{padding:8px 18px;border-radius:8px;border:1px solid #8886;background:#2563eb;color:#fff;font:inherit;cursor:pointer}
.item{padding:10px 0;border-bottom:1px solid #8882}
.item:last-child{border-bottom:none}
.t{opacity:.55;font-size:12px}
.hint{font-size:12px;opacity:.6}
</style></head><body>
<h1>lan-sync 接收端</h1>
<div class="sub" id="dev">已连接</div>

<div class="card">
  <div style="margin-bottom:8px">发文件到这台电脑</div>
  <input type="file" id="file" multiple>
  <div style="margin-top:10px"><button id="up">上传</button> <span class="hint" id="upmsg"></span></div>
</div>

<div class="card">
  <div style="margin-bottom:8px">发一段文本</div>
  <textarea id="txt" placeholder="Ctrl+Enter 发送"></textarea>
  <div style="margin-top:10px"><button id="send">发送</button> <span class="hint" id="txtmsg"></span></div>
</div>

<div class="card">
  <div style="margin-bottom:8px">收件箱 <button id="refresh" style="float:right;padding:2px 10px;font-size:13px">刷新</button></div>
  <div id="list"><div class="hint">加载中…</div></div>
</div>

<script>
const KEY = "__KEY__";
const H = {"X-Sync-Key": KEY};

async function loadInbox(){
  const r = await fetch("/api/inbox?key="+encodeURIComponent(KEY));
  if(!r.ok){document.getElementById("list").innerHTML='<div class="hint">密钥无效</div>';return;}
  const d = await r.json();
  const box = document.getElementById("list");
  if(!d.items.length){box.innerHTML='<div class="hint">暂无内容</div>';return;}
  box.innerHTML = d.items.slice().reverse().map(it=>{
    if(it.type==="text"){
      return `<div class="item"><div class="t">${it.time} · 文本 ${it.from||""}</div><div>${escapeHtml(it.text)}</div></div>`;
    }
    return `<div class="item"><div class="t">${it.time} · 文件 ${it.from||""}</div>
      <a href="/api/download?key=${encodeURIComponent(KEY)}&name=${encodeURIComponent(it.name)}" download>${escapeHtml(it.name)}</a>
      <span class="hint">${Math.round(it.size/1024)} KB</span></div>`;
  }).join("");
}
function escapeHtml(s){return (s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}

document.getElementById("up").onclick = async ()=>{
  const files = document.getElementById("file").files;
  if(!files.length) return;
  const msg = document.getElementById("upmsg");
  for(const f of files){
    msg.textContent = "上传中 "+f.name;
    const r = await fetch("/api/file?name="+encodeURIComponent(f.name), {method:"PUT", headers:H, body:f});
    msg.textContent = r.ok ? "已上传 "+f.name : "失败 "+f.name;
  }
  document.getElementById("file").value="";
  loadInbox();
};
document.getElementById("send").onclick = async ()=>{
  const t = document.getElementById("txt").value.trim();
  if(!t) return;
  const r = await fetch("/api/text", {method:"POST", headers:{...H,"Content-Type":"application/json"}, body:JSON.stringify({text:t})});
  document.getElementById("txtmsg").textContent = r.ok ? "已发送" : "发送失败";
  document.getElementById("txt").value="";
  loadInbox();
};
document.getElementById("txt").addEventListener("keydown", e=>{
  if(e.ctrlKey && e.key==="Enter") document.getElementById("send").click();
});
document.getElementById("refresh").onclick = loadInbox;
fetch("/api/ping").then(r=>r.json()).then(d=>{document.getElementById("dev").textContent="设备："+d.device+" · lan-sync "+d.version;});
loadInbox();
</script></body></html>
"""


# ---------------------------------------------------------------- 图形界面

def _open_path(p) -> bool:
    try:
        os.startfile(str(p))  # type: ignore[attr-defined]
        return True
    except Exception:
        return False


def gui():
    """Tkinter 桌面界面（纯标准库，无需额外依赖）。"""
    _ensure_streams()
    selftest = os.environ.get("LAN_SYNC_GUI_SELFTEST") == "1"
    if os.name == "nt" and not selftest:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    try:
        import queue
        import tkinter as tk
        import webbrowser
        from tkinter import filedialog, messagebox, ttk
    except Exception as e:
        die(f"无法加载图形界面（需要 tkinter）：{e}")

    cfg = load_config()
    root = tk.Tk()
    root.title("lan-sync 局域网互传")
    root.geometry("880x640")
    root.minsize(780, 580)
    if selftest:
        root.withdraw()

    # 后台线程 -> 主线程的唯一通道（tkinter 不是线程安全的）
    q = queue.Queue()

    def ui(fn, *args):
        q.put((fn, args))

    def poll_queue():
        try:
            while True:
                fn, args = q.get_nowait()
                try:
                    fn(*args)
                except Exception:
                    pass
        except queue.Empty:
            pass
        root.after(80, poll_queue)

    tip = tk.StringVar(value="就绪")
    info = tk.StringVar(value="本机信息加载中…")
    svc = tk.StringVar(value="服务：检查中…")

    def is_service_running():
        st = read_state()
        return st, bool(st.get("pid") and is_running(st["pid"]))

    def refresh_status():
        def work():
            st, running = is_service_running()
            ips = local_ips()   # 探测放在后台线程，主线程只负责显示
            ui(apply_status, st, running, ips)
        threading.Thread(target=work, daemon=True).start()

    def apply_status(st, running, ips=None):
        port = st.get("port") or cfg.get("port", DEFAULT_PORT)
        if ips is None:
            ips = list(_LOCAL_IPS["ips"])
        info.set(f"本机 {', '.join(ips) if ips else '未获取到 IP'}  ·  端口 {port}  ·  密钥 {cfg.get('key')}")
        if running:
            svc.set(f"● 服务运行中  PID {st['pid']}")
        else:
            svc.set("○ 服务未运行")

    # ---------- 顶部 ----------
    top = ttk.Frame(root, padding=(14, 12, 14, 4))
    top.pack(fill="x")
    ttk.Label(top, textvariable=info, font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
    line2 = ttk.Frame(top)
    line2.pack(fill="x", pady=(6, 0))
    ttk.Label(line2, textvariable=svc).pack(side="left")
    ttk.Button(line2, text="打开网页", width=10, command=lambda: open_web()).pack(side="right")
    ttk.Button(line2, text="停止服务", width=10, command=lambda: stop_svc()).pack(side="right", padx=(0, 6))
    ttk.Button(line2, text="启动服务", width=10, command=lambda: start_svc()).pack(side="right", padx=(0, 6))

    # ---------- 标签页 ----------
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=14, pady=6)
    send_tab = ttk.Frame(nb, padding=12)
    nb.add(send_tab, text="发送")
    inbox_tab = ttk.Frame(nb, padding=12)
    nb.add(inbox_tab, text="收件箱")
    set_tab = ttk.Frame(nb, padding=12)
    nb.add(set_tab, text="设置")

    # ---------- 状态栏 ----------
    bar = ttk.Frame(root, padding=(14, 0, 14, 8))
    bar.pack(fill="x")
    tip_label = ttk.Label(bar, textvariable=tip, foreground="#777")
    tip_label.pack(anchor="w")

    def set_tip(text, error=False):
        tip.set(text)
        try:
            tip_label.configure(foreground="#c0392b" if error else "#777")
        except Exception:
            pass

    def report_error(title, msg):
        """失败要显眼：状态栏变红 + 弹窗，避免像之前那样被灰色小字淹没。"""
        set_tip(f"{title}：{msg}", error=True)
        try:
            messagebox.showerror(title, msg)
        except Exception:
            pass

    # ---------- 发送页 ----------
    trow = ttk.Frame(send_tab)
    trow.pack(fill="x")
    ttk.Label(trow, text="目标设备").pack(side="left")
    target_box = ttk.Combobox(trow, width=34)
    target_box.pack(side="left", padx=(8, 6))
    ttk.Button(trow, text="发现设备", command=lambda: do_discover()).pack(side="left")
    ttk.Button(trow, text="用本机", width=8, command=lambda: use_self()).pack(side="left", padx=(6, 0))

    ttk.Label(send_tab, text="文本").pack(anchor="w", pady=(14, 4))
    text_box = tk.Text(send_tab, height=7, wrap="word", undo=True)
    text_box.pack(fill="x")
    trow2 = ttk.Frame(send_tab)
    trow2.pack(fill="x", pady=(6, 0))
    send_text_btn = ttk.Button(trow2, text="发送文本 (Ctrl+Enter)", command=lambda: send_text())
    send_text_btn.pack(side="left")
    text_box.bind("<Control-Return>", lambda e: (send_text(), "break")[1])

    ttk.Label(send_tab, text="文件").pack(anchor="w", pady=(16, 4))
    frow = ttk.Frame(send_tab)
    frow.pack(fill="x")
    files_var = tk.StringVar(value="未选择文件")
    ttk.Label(frow, textvariable=files_var, foreground="#555").pack(side="left", fill="x", expand=True)
    ttk.Button(frow, text="选择文件…", command=lambda: pick_files()).pack(side="right")
    frow2 = ttk.Frame(send_tab)
    frow2.pack(fill="x", pady=(6, 0))
    send_files_btn = ttk.Button(frow2, text="发送文件", command=lambda: send_files())
    send_files_btn.pack(side="left")
    prog = ttk.Progressbar(frow2, orient="horizontal", length=280, mode="determinate", maximum=100)
    prog.pack(side="left", padx=(12, 0))
    prog_var = tk.StringVar(value="")
    ttk.Label(frow2, textvariable=prog_var).pack(side="left", padx=(8, 0))

    chosen = {"files": []}

    def pick_files():
        picked = filedialog.askopenfilenames(title="选择要发送的文件")
        if not picked:
            return
        chosen["files"] = [Path(p) for p in picked]
        names = "、".join(p.name for p in chosen["files"][:3])
        more = f" 等 {len(chosen['files'])} 个" if len(chosen["files"]) > 3 else ""
        files_var.set(names + more)

    def use_self():
        target_box.delete(0, "end")
        target_box.insert(0, "127.0.0.1")

    def parse_target():
        s = target_box.get().strip()
        if not s:
            tip.set("请先填写目标 IP，或点“发现设备”")
            return None
        if ":" in s:
            host, _, port = s.rpartition(":")
            try:
                return host, int(port)
            except Exception:
                pass
        return s, int(cfg.get("port", DEFAULT_PORT))

    def sender_name():
        return cfg.get("device_name", socket.gethostname())

    def send_text():
        content = text_box.get("1.0", "end").strip()
        if not content:
            tip.set("文本为空")
            return
        tgt = parse_target()
        if not tgt:
            return
        ip, port = tgt
        send_text_btn.configure(state="disabled")
        tip.set(f"正在发送文本到 {ip}:{port} …")

        def done():
            send_text_btn.configure(state="normal")
            text_box.delete("1.0", "end")
            set_tip(f"文本已发送到 {ip}:{port}")

        def failed(msg):
            send_text_btn.configure(state="normal")
            report_error("发送失败", msg)

        def work():
            try:
                res = post_text(ip, port, cfg["key"], content, sender_name())
                if res["status"] == 401:
                    raise RuntimeError("密钥不匹配（401），请先在两台机器上用同一密钥配对")
                if res["status"] != 200:
                    raise RuntimeError(f"HTTP {res['status']}")
                ui(done)
            except Exception as e:
                ui(failed, str(e))

        threading.Thread(target=work, daemon=True).start()

    def send_files():
        if not chosen["files"]:
            tip.set("请先选择文件")
            return
        tgt = parse_target()
        if not tgt:
            return
        ip, port = tgt
        paths_ = list(chosen["files"])
        total = sum(p.stat().st_size for p in paths_) or 1
        send_files_btn.configure(state="disabled")
        send_text_btn.configure(state="disabled")
        prog["value"] = 0
        prog_var.set("0%")
        done_bytes = {"n": 0}

        def on_progress(sent, size):
            pct = int((done_bytes["n"] + sent) * 100 // total)
            ui(set_prog, pct)

        def set_prog(pct):
            prog["value"] = pct
            prog_var.set(f"{pct}%")

        def finished():
            send_files_btn.configure(state="normal")
            send_text_btn.configure(state="normal")
            prog_var.set("完成")
            set_tip(f"已发送 {len(paths_)} 个文件到 {ip}:{port}")

        def failed(msg):
            send_files_btn.configure(state="normal")
            send_text_btn.configure(state="normal")
            report_error("发送失败", msg)

        def work():
            try:
                for p in paths_:
                    res = put_file(ip, port, cfg["key"], p, sender_name(), progress=on_progress)
                    if res["status"] == 401:
                        raise RuntimeError("密钥不匹配（401），请先在两台机器上用同一密钥配对")
                    if res["status"] != 200:
                        raise RuntimeError(f"{p.name} 发送失败（HTTP {res['status']}）")
                    done_bytes["n"] += p.stat().st_size
                ui(finished)
            except Exception as e:
                ui(failed, str(e))

        threading.Thread(target=work, daemon=True).start()

    def do_discover():
        tip.set("正在发现局域网设备…")

        def work():
            peers = discover(timeout=1.5)
            ui(show_peers, peers)

        def show_peers(peers):
            if not peers:
                tip.set("未发现设备（对端需先启动服务；也可直接填 IP）")
                return
            values = [f"{p['ip']}:{p['port']}" for p in peers]
            target_box.configure(values=values)
            target_box.delete(0, "end")
            target_box.insert(0, values[0])
            tip.set(f"发现 {len(peers)} 台设备，已填入第一台")

        threading.Thread(target=work, daemon=True).start()

    # ---------- 收件箱页 ----------
    cols = ("time", "kind", "from", "content", "size")
    tree = ttk.Treeview(inbox_tab, columns=cols, show="headings", height=14)
    widths = {"time": 130, "kind": 52, "from": 90, "content": 380, "size": 80}
    heads = {"time": "时间", "kind": "类型", "from": "来源", "content": "内容 / 文件", "size": "大小"}
    for c in cols:
        tree.heading(c, text=heads[c])
        tree.column(c, width=widths[c], anchor="w", stretch=(c == "content"))
    tree.pack(fill="both", expand=True)

    ibar = ttk.Frame(inbox_tab)
    ibar.pack(fill="x", pady=(8, 0))
    ttk.Button(ibar, text="刷新", command=lambda: refresh_inbox()).pack(side="left")
    ttk.Button(ibar, text="打开收件文件夹", command=lambda: _open_path(paths()["root"] / "inbox")).pack(side="left", padx=6)
    ttk.Label(ibar, text="双击文件行可直接打开；双击文本行复制到剪贴板", foreground="#888").pack(side="left", padx=8)

    tree_items = {}
    inbox_busy = {"on": False}

    def refresh_inbox():
        # 读 messages.jsonl + 遍历收件目录都在后台线程做，避免收件多了界面卡顿
        if inbox_busy["on"]:
            return
        inbox_busy["on"] = True

        def work():
            try:
                items = inbox_items(limit=100)
            except Exception:
                items = None
            ui(render_inbox, items)

        threading.Thread(target=work, daemon=True).start()

    def render_inbox(items):
        inbox_busy["on"] = False
        if items is None:
            return
        tree.delete(*tree.get_children())
        tree_items.clear()
        for it in items:
            if it["type"] == "text":
                text = (it.get("text") or "").replace("\n", " ")
                vals = (it.get("time", ""), "文本", it.get("from", ""), text[:100], "")
            else:
                vals = (it.get("time", ""), "文件", it.get("from", ""),
                        it.get("name", ""), f"{it.get('size', 0) // 1024} KB")
            iid = tree.insert("", "end", values=vals)
            tree_items[iid] = it
        if not items:
            set_tip("收件箱是空的")

    def open_row(_event=None):
        sel = tree.selection()
        if not sel:
            return
        it = tree_items.get(sel[0])
        if not it:
            return
        if it.get("type") == "file":
            if not _open_path(it["path"]):
                tip.set("打开文件失败：" + it["path"])
        else:
            root.clipboard_clear()
            root.clipboard_append(it.get("text", ""))
            tip.set("文本已复制到剪贴板")

    tree.bind("<Double-1>", open_row)

    def tick_inbox():
        try:
            if nb.index("current") == 1:
                refresh_inbox()
        except Exception:
            pass
        root.after(2500, tick_inbox)

    # ---------- 设置页 ----------
    form = ttk.Frame(set_tab)
    form.pack(fill="x")

    def add_field(row, label, var, width):
        ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=var, width=width).grid(row=row, column=1, sticky="w")

    port_var = tk.StringVar(value=str(cfg.get("port", DEFAULT_PORT)))
    dport_var = tk.StringVar(value=str(cfg.get("discovery_port", DEFAULT_DISCOVERY_PORT)))
    name_var = tk.StringVar(value=cfg.get("device_name", socket.gethostname()))
    key_var = tk.StringVar(value=cfg.get("key", ""))
    add_field(0, "接收端口", port_var, 10)
    add_field(1, "发现端口 (UDP)", dport_var, 10)
    add_field(2, "设备名", name_var, 24)
    add_field(3, "配对密钥", key_var, 24)

    brow = ttk.Frame(set_tab)
    brow.pack(fill="x", pady=(14, 0))

    def save_settings():
        try:
            p_num = int(port_var.get())
            dp_num = int(dport_var.get())
        except Exception:
            tip.set("端口必须是数字")
            return
        cfg["port"] = p_num
        cfg["discovery_port"] = dp_num
        cfg["device_name"] = name_var.get().strip() or socket.gethostname()
        cfg["key"] = key_var.get().strip() or cfg["key"]
        save_config(cfg)
        tip.set("设置已保存（端口变更需重启服务生效）")
        refresh_status()

    def apply_key():
        new_key = key_var.get().strip()
        if not new_key:
            tip.set("密钥不能为空")
            return
        cfg["key"] = new_key
        save_config(cfg)
        tip.set("密钥已更新，正在重启服务…")

        def work():
            st, running = is_service_running()
            if running:
                stop_service(quiet=True)
                time.sleep(0.5)
                start_background()
            ui(refresh_status)

        threading.Thread(target=work, daemon=True).start()

    def show_firewall():
        p = cfg.get("port", DEFAULT_PORT)
        dp = cfg.get("discovery_port", DEFAULT_DISCOVERY_PORT)
        msg = ("对端连不上时，多半是 Windows 防火墙拦截。\n"
               "请用【管理员】PowerShell 执行：\n\n"
               f'netsh advfirewall firewall add rule name="Marvis lan-sync TCP {p}" dir=in action=allow protocol=TCP localport={p}\n'
               f'netsh advfirewall firewall add rule name="Marvis lan-sync UDP {dp}" dir=in action=allow protocol=UDP localport={dp}\n\n'
               "TCP 规则即可传文件；UDP 规则只用于自动发现。")
        messagebox.showinfo("防火墙放行命令", msg)

    ttk.Button(brow, text="保存设置", command=save_settings).pack(side="left")
    ttk.Button(brow, text="应用密钥并重启服务", command=apply_key).pack(side="left", padx=8)
    ttk.Button(brow, text="打开数据目录", command=lambda: _open_path(paths()["root"])).pack(side="left")
    ttk.Button(brow, text="防火墙放行命令", command=show_firewall).pack(side="left", padx=8)

    # ---------- 服务控制 ----------
    def start_svc():
        def work():
            try:
                res = start_background()
                ui(after_start, res)
            except Exception as e:
                ui(lambda: tip.set(f"启动失败：{e}"))

        def after_start(res):
            if res.get("warning"):
                set_tip("启动异常：" + str(res["warning"]), error=True)
            else:
                set_tip(f"服务已启动（端口 {res.get('port')}）")
            refresh_status()

        threading.Thread(target=work, daemon=True).start()

    def stop_svc():
        def work():
            ok = stop_service(quiet=True)
            ui(after_stop, ok)

        def after_stop(ok):
            tip.set("服务已停止" if ok else "服务本来就没有运行")
            refresh_status()

        threading.Thread(target=work, daemon=True).start()

    def open_web():
        # 先确保服务在跑：服务被系统/杀软结束或用户误关后，直接开浏览器只会看到连不上
        tip.set("正在检查服务…")

        def work():
            st, running = is_service_running()
            if not running:
                try:
                    start_background()
                except Exception:
                    pass
                st, running = is_service_running()
            port = st.get("port") or cfg.get("port", DEFAULT_PORT)
            url = f"http://127.0.0.1:{port}/?key={urllib.parse.quote(cfg['key'])}"
            ui(finish_open_web, url, running)

        threading.Thread(target=work, daemon=True).start()

    def finish_open_web(url, running):
        refresh_status()
        if not running:
            root.clipboard_clear()
            root.clipboard_append(url)
            tip.set("服务启动失败，网页地址已复制到剪贴板，可手动打开")
            return
        opened = False
        try:
            opened = webbrowser.open(url)
        except Exception:
            opened = False
        if not opened:
            try:
                os.startfile(url)
                opened = True
            except Exception:
                opened = False
        if not opened:
            try:
                subprocess.Popen(["cmd", "/c", "start", "", url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=0x00000008 | CREATE_NO_WINDOW)  # 后台起，不弹黑窗
                opened = True
            except Exception:
                opened = False
        if opened:
            tip.set("已打开网页：" + url)
        else:
            root.clipboard_clear()
            root.clipboard_append(url)
            tip.set("无法自动打开浏览器，地址已复制到剪贴板")

    def tick_status():
        # 定时刷新状态，避免服务已退出但界面仍显示“运行中”
        refresh_status()
        root.after(4000, tick_status)

    # ---------- 启动 ----------
    def boot():
        refresh_status()
        refresh_inbox()
        if selftest:
            return

        def check():
            st, running = is_service_running()
            if not running:
                ui(start_svc)

        threading.Thread(target=check, daemon=True).start()

    root.after(120, poll_queue)
    root.after(200, boot)
    root.after(2600, tick_inbox)
    root.after(4000, tick_status)
    if os.environ.get("LAN_SYNC_GUI_OPENWEB_TEST") == "1":
        # 隐藏测试钩子：启动后自动点一次“打开网页”，供自动化验证窗口版 exe
        root.after(1500, open_web)
    if selftest:
        root.after(1500, root.destroy)

    root.mainloop()
    if selftest:
        print("GUI SELFTEST OK")


# ---------------------------------------------------------------- CLI

def build_parser():
    ap = argparse.ArgumentParser(prog="lansync", description="局域网双机互传（文本 + 文件）")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("gui", help="打开图形界面").set_defaults(func=lambda a: gui())

    sp = sub.add_parser("serve", help="启动接收服务")
    sp.add_argument("--port", type=int, default=None)
    sp.add_argument("--background", action="store_true", help="后台运行")
    sp.set_defaults(func=lambda a: (print(json.dumps(start_background(), ensure_ascii=False)) if a.background else cmd_serve(a)))

    sub.add_parser("stop", help="停止后台服务").set_defaults(func=lambda a: stop_service())
    sub.add_parser("status", help="服务状态").set_defaults(func=cmd_status)
    sub.add_parser("info", help="本机 IP / 端口 / 密钥").set_defaults(func=cmd_info)

    sp = sub.add_parser("discover", help="发现局域网内其他设备")
    sp.add_argument("--timeout", type=float, default=2.0)
    sp.set_defaults(func=cmd_discover)

    sp = sub.add_parser("send", help="发送文本或文件")
    sp.add_argument("--target", default="auto", help="对方 IP[:端口]，或 auto 自动发现")
    sp.add_argument("--text", help="要发送的文本")
    sp.add_argument("--file", nargs="*", help="要发送的文件或目录，可多个")
    sp.set_defaults(func=cmd_send)

    sp = sub.add_parser("inbox", help="查看收件箱")
    sp.add_argument("--limit", type=int, default=30)
    sp.set_defaults(func=cmd_inbox)

    sp = sub.add_parser("pair", help="设置配对密钥")
    sp.add_argument("--key", required=False)
    sp.set_defaults(func=cmd_pair)

    sub.add_parser("firewall", help="输出放行防火墙的命令").set_defaults(func=cmd_firewall)
    return ap


def main():
    _ensure_streams()
    ap = build_parser()
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
