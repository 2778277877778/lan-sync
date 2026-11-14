# -*- coding: utf-8 -*-
"""M1 验收：两个实例互发、历史、幂等、已读回执、重启不丢、分页。"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

APP = Path(r"C:\Users\szwht\DeepSeek Bot\lan-sync\lan-telegram\lantelegram.py")
BASE = Path(os.environ.get("TEMP", ".")) / "lt-m1"
KEY = "m1key0123"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {detail}")


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


def run(env, *args):
    return subprocess.run([sys.executable, str(APP), *args], env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


shutil.rmtree(BASE, ignore_errors=True)
homeA, envA, pA = setup("A", 32210)
homeB, envB, pB = setup("B", 32220)
try:
    print("=== 启动 ===")
    check("A 服务启动", wait_up(32210))
    check("B 服务启动", wait_up(32220))

    print("=== 发送与接收 ===")
    r = run(envA, "send", "--target", "127.0.0.1:32220", "--text", "第一条消息")
    print("   ", (r.stdout or r.stderr).strip())
    check("A 发送成功", "已发送" in (r.stdout or ""))

    r = run(envB, "history", "--with", "A")
    out = r.stdout or ""
    check("B 看到消息", "第一条消息" in out, "")
    print("   B history:\n" + "\n".join("     " + l for l in out.strip().splitlines()[:4]))

    print("=== 已读回执 ===")
    time.sleep(0.8)
    r = run(envA, "history", "--with", "B")
    check("A 侧状态变已读", "已读" in (r.stdout or ""), f"({(r.stdout or '').strip().splitlines()[-1] if (r.stdout or '').strip() else ''})")

    print("=== 幂等：同一 id 发两次 ===")
    import http.client
    devB = json.loads((homeB / "config.json").read_text(encoding="utf-8"))
    env_obj = {"id": "dup-id-0001", "from": json.loads((homeA / "config.json").read_text(encoding="utf-8"))["device_id"],
               "from_name": "A", "from_port": 32210, "ts": int(time.time() * 1000),
               "kind": "text", "body": {"text": "重复测试"}}
    codes = []
    for _ in range(2):
        c = http.client.HTTPConnection("127.0.0.1", 32220, timeout=5)
        c.request("POST", "/api/v2/messages", body=json.dumps(env_obj).encode(),
                  headers={"X-Sync-Key": KEY, "Content-Type": "application/json"})
        body = json.loads(c.getresponse().read().decode())
        c.close()
        codes.append(body.get("duplicate"))
    check("第二次判定为重复", codes == [False, True], f"{codes}")

    import sqlite3
    con = sqlite3.connect(str(homeB / "messages.db"))
    n = con.execute("SELECT COUNT(*) FROM messages WHERE id='dup-id-0001'").fetchone()[0]
    con.close()
    check("库中只有一条", n == 1, f"count={n}")

    print("=== 分页 ===")
    for i in range(5):
        run(envA, "send", "--target", "127.0.0.1:32220", "--text", f"分页{i}")
    r = run(envB, "history", "--with", "A", "--limit", "3")
    lines = [l for l in (r.stdout or "").splitlines() if l.startswith("[")]
    check("limit=3 生效", len(lines) == 3, f"lines={len(lines)}")
    first_ts = lines[0].split("]")[0][1:]
    check("返回的是最近 3 条", "分页4" in (r.stdout or "") and "第一条消息" not in (r.stdout or ""))

    print("=== 重启不丢 ===")
    pB.terminate()
    pB.wait(timeout=10)
    time.sleep(0.5)
    homeB2, envB2, pB2 = setup("B", 32220)
    check("B 重启成功", wait_up(32220))
    r = run(envB2, "history", "--with", "A")
    check("重启后历史仍在", "分页4" in (r.stdout or ""), "")
    pB = pB2

    print("=== 离线队列 ===")
    pB.terminate()
    pB.wait(timeout=10)
    time.sleep(0.4)
    r = run(envA, "send", "--target", "127.0.0.1:32220", "--text", "离线时发的")
    check("离线时提示入队", "入队" in (r.stdout or r.stderr or ""), (r.stdout or r.stderr or "").strip()[:40])

    print("\n=== 汇总 ===")
    bad = [x for x in results if not x[1]]
    print(f"通过 {len(results)-len(bad)}/{len(results)}")
    for name, ok, detail in bad:
        print("  未通过:", name, detail)
finally:
    for p in (pA, pB):
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)
    shutil.rmtree(BASE, ignore_errors=True)
