# -*- coding: utf-8 -*-
"""验证离线队列自动补发：B 离线 → A 发消息入队 → B 上线 → 自动送达。"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

APP = Path(r"C:\Users\szwht\DeepSeek Bot\lan-sync\lan-telegram\lantelegram.py")
BASE = Path(os.environ.get("TEMP", ".")) / "lt-resend"
KEY = "resendkey1"


def setup(name, port):
    home = BASE / name
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.json").write_text(json.dumps({
        "device_id": f"dev{name}{'0' * 28}"[:32], "device_name": name,
        "port": port, "key": KEY}), encoding="utf-8")
    env = dict(os.environ, LAN_TG_HOME=str(home))
    p = subprocess.Popen([sys.executable, str(APP), "serve"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return home, env, p


def wait_up(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v2/ping", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


shutil.rmtree(BASE, ignore_errors=True)
homeA, envA, pA = setup("A", 32230)
homeB, envB, pB = setup("B", 32240)
try:
    assert wait_up(32230) and wait_up(32240)
    # 先建立一次联系，让 A 认识 B
    subprocess.run([sys.executable, str(APP), "send", "--target", "127.0.0.1:32240",
                    "--text", "建立联系"], env=envA, capture_output=True)
    time.sleep(0.5)

    # B 下线
    pB.terminate()
    pB.wait(timeout=10)
    time.sleep(0.6)

    r = subprocess.run([sys.executable, str(APP), "send", "--target", "127.0.0.1:32240",
                        "--text", "离线期间发的消息"], env=envA,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    print("A 发送结果:", (r.stdout or r.stderr).strip()[:80])

    # B 重新上线
    homeB2, envB2, pB2 = setup("B", 32240)
    pB = pB2
    print("B 上线:", wait_up(32240))

    # 等待 A 的重试 worker（5 秒一轮）
    ok = False
    for _ in range(20):
        time.sleep(1)
        r = subprocess.run([sys.executable, str(APP), "history", "--with", "A"],
                           env=envB2, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if "离线期间发的消息" in (r.stdout or ""):
            ok = True
            break
    print("B 是否收到补发:", ok)
    if ok:
        print((r.stdout or "").strip())
    print("RESULT:", "PASS" if ok else "FAIL")
finally:
    for p in (pA, pB):
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)
    shutil.rmtree(BASE, ignore_errors=True)
