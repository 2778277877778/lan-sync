# -*- coding: utf-8 -*-
"""M2 验收：自签证书、指纹人工核对配对、TLS 1.3 双向通信、错指纹握手层拒绝、明文不通传。

角色：A/B 走完整配对并启用 TLS；C 作为「指纹不符」的干扰证书来源。
验收标准（设计文档 §9）：两端握手成功，错指纹拒绝连接。
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

APP = Path(r"C:\Users\szwht\DeepSeek Bot\lan-sync\lan-telegram\lantelegram.py")
BASE = Path(os.environ.get("TEMP", ".")) / "lt-m2"
KEY = "m2key0123"
PORT = {"A": 32250, "B": 32260, "C": 32270}

results = []
procs = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {detail}")


def home(name):
    return BASE / name


def env(name):
    return dict(os.environ, LAN_TG_HOME=str(home(name)))


def run(name, *args):
    return subprocess.run([sys.executable, str(APP), *args], env=env(name),
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def start_plain(name):
    h = home(name)
    h.mkdir(parents=True, exist_ok=True)
    (h / "config.json").write_text(json.dumps({
        "device_id": f"dev{name}{'0' * 28}"[:32], "device_name": name,
        "port": PORT[name], "key": KEY, "tls": False}), encoding="utf-8")
    p = subprocess.Popen([sys.executable, str(APP), "serve"], env=env(name),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    return p


def wait_up_plain(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v2/ping", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def tls_ctx(name, lo=None, hi=None):
    """构建与客户端一致的测试上下文：证书+固定指纹，可指定版本区间。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = lo or ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = hi or ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    pins = home(name) / "certs" / "pins"
    cadata = "".join(f.read_text(encoding="utf-8") for f in sorted(pins.glob("*.pem")))
    ctx.load_verify_locations(cadata=cadata)
    ctx.load_cert_chain(str(home(name) / "certs" / "cert.pem"),
                        str(home(name) / "certs" / "key.pem"))
    return ctx


def wait_up_tls(name, port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                with tls_ctx(name).wrap_socket(s, server_hostname="127.0.0.1") as t:
                    if t.version() == "TLSv1.3":
                        return True
        except Exception:
            time.sleep(0.3)
    return False


def enable_tls(name):
    cfg = json.loads((home(name) / "config.json").read_text(encoding="utf-8"))
    cfg["tls"] = True
    (home(name) / "config.json").write_text(json.dumps(cfg), encoding="utf-8")


shutil.rmtree(BASE, ignore_errors=True)
try:
    pA = start_plain("A")
    pB = start_plain("B")
    pC = start_plain("C")
    print("=== 启动（明文阶段） ===")
    check("A/B/C 明文服务启动", wait_up_plain(PORT["A"]) and wait_up_plain(PORT["B"])
          and wait_up_plain(PORT["C"]))

    print("=== 证书与指纹 ===")
    rA = run("A", "cert")
    rB = run("B", "cert")
    fpA = rA.stdout.split("完整指纹")[-1].split("\n")[0].strip().lstrip(": ").strip()
    fpB = rB.stdout.split("完整指纹")[-1].split("\n")[0].strip().lstrip(": ").strip()
    check("cert 生成自签证书并显示指纹", len(fpA) == 64 and len(fpB) == 64 and fpA != fpB,
          f"{fpA[:8]}… / {fpB[:8]}…")

    print("=== 配对（指纹核对） ===")
    r = run("B", "trust", "--target", f"127.0.0.1:{PORT['A']}", "--expect", fpA[:32])
    ok_b = "已固定对端证书" in (r.stdout or "")
    r = run("A", "trust", "--target", f"127.0.0.1:{PORT['B']}", "--expect", fpB[:32])
    ok_a = "已固定对端证书" in (r.stdout or "")
    check("双向 trust 成功（--target 拉证书+指纹相符）", ok_a and ok_b)
    r = run("C", "trust", "--target", f"127.0.0.1:{PORT['A']}", "--expect", "0123456789abcdef")
    check("指纹不符时拒绝固定", r.returncode != 0 and "指纹核对不符" in (r.stderr or ""),
          (r.stderr or "").strip().splitlines()[0][:40] if r.stderr else "")

    print("=== 启用 TLS 1.3 ===")
    pA.terminate(); pA.wait(timeout=10)
    pB.terminate(); pB.wait(timeout=10)
    time.sleep(0.6)
    enable_tls("A"); enable_tls("B")
    pA = subprocess.Popen([sys.executable, str(APP), "serve"], env=env("A"),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pB = subprocess.Popen([sys.executable, str(APP), "serve"], env=env("B"),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs += [pA, pB]
    # 注意：每个节点的固定库里只有「对方」的证书，探活必须用发起方的上下文
    # （B 的 ctx 固定了 A → 可验证 A 的服务端；反之亦然）。
    check("A/B TLS 服务启动", wait_up_tls("B", PORT["A"]) and wait_up_tls("A", PORT["B"]))

    print("=== TLS 双向通信 ===")
    r = run("A", "send", "--target", f"127.0.0.1:{PORT['B']}", "--text", "TLS第一句")
    check("A→B 发送成功（TLS 握手+密钥+CN 绑定）", "已发送给" in (r.stdout or ""),
          (r.stdout or r.stderr).strip()[:50])
    r = run("B", "history", "--with", "A")
    check("B 看到消息并触发已读回执", "TLS第一句" in (r.stdout or ""))
    time.sleep(1.0)
    r = run("A", "history", "--with", "B")
    check("A 侧状态变已读（回执走 TLS）", "已读" in (r.stdout or ""))

    print("=== 协议强度 ===")
    ok_plain_fail = False
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT['B']}/api/v2/ping", timeout=3) as _r:
            ok_plain_fail = False
    except Exception:
        ok_plain_fail = True
    check("明文请求打 TLS 端口不通传", ok_plain_fail)
    ok_12_fail = False
    try:
        with socket.create_connection(("127.0.0.1", PORT["B"]), timeout=3) as s:
            tls_ctx("A", lo=ssl.TLSVersion.TLSv1_2, hi=ssl.TLSVersion.TLSv1_2) \
                .wrap_socket(s, server_hostname="127.0.0.1")
    except Exception:
        ok_12_fail = True
    with socket.create_connection(("127.0.0.1", PORT["B"]), timeout=3) as s:
        t = tls_ctx("A").wrap_socket(s, server_hostname="127.0.0.1")
        ver = t.version()
        t.close()
    check("TLS 1.2 被拒 · 协商结果为 TLS 1.3", ok_12_fail and ver == "TLSv1.3", ver)

    print("=== 错指纹拒绝（握手层） ===")
    pins_A = home("A") / "certs" / "pins"
    b_pem_file = next(iter(pins_A.glob("*.pem")))
    backup = b_pem_file.read_bytes()
    run("C", "cert")  # 确保 C 有自己的证书
    b_pem_file.write_bytes((home("C") / "certs" / "cert.pem").read_bytes())  # 换成干扰证书
    r = run("A", "send", "--target", f"127.0.0.1:{PORT['B']}", "--text", "不该送达")
    err = ((r.stderr or "").strip().splitlines() or [""])[0]
    tamper_rejected = r.returncode != 0 and ("证书" in err or "TLS" in err)
    check("固定指纹被换后握手即拒绝", tamper_rejected, err[:60])
    rb = run("B", "history", "--with", "A")
    check("干扰期间消息未送达 B", "不该送达" not in (rb.stdout or ""))
    b_pem_file.write_bytes(backup)  # 恢复正确证书
    r = run("A", "send", "--target", f"127.0.0.1:{PORT['B']}", "--text", "恢复后送达")
    check("恢复固定后重新连通", "已发送给" in (r.stdout or ""))

    print("\n=== 汇总 ===")
    bad = [x for x in results if not x[1]]
    print(f"通过 {len(results) - len(bad)}/{len(results)}")
    for name, ok, detail in bad:
        print("  未通过:", name, detail)
    if bad:
        sys.exit(1)
finally:
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)
    shutil.rmtree(BASE, ignore_errors=True)
