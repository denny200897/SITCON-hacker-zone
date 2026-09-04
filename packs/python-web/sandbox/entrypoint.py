#!/usr/bin/env python3
"""Aegis 沙箱 entrypoint（pack 內容物；SPEC §17.1）。

三階段：(a) 起 service（template metadata 決定 cmd），以 wait_for 輪詢（上限 20s）；
(b) 執行 exploit（python /aegis/witness/exploit.py，payload 從 /aegis/payload.txt 讀、
    目標位址取環境變數 AEGIS_TARGET_URL）；(c) 收尾傾 dump。
全程 stdout/stderr 導入 /aegis/out/run.log。

Exit code 契約（閉集，SPEC §17.1）：
  0   流程跑完（不代表攻擊成功；成功只由 host 端 oracle checker 判定）
  2   service 未在限期內就緒（harness）
  3   exploit 腳本例外崩潰（harness）
"""
import os
import socket
import subprocess
import sys
import time
import urllib.request

OUT_DIR = "/aegis/out"
RUN_LOG = os.path.join(OUT_DIR, "run.log")
PORT = int(os.environ.get("AEGIS_SERVICE_PORT", "8000"))
HEALTH_PATH = os.environ.get("AEGIS_HEALTH_PATH", "/healthz")
WAIT_LIMIT = 20  # 秒（§17.1 上限）
LOG = open(RUN_LOG, "a", buffering=1)


def log(*parts):
    line = " ".join(str(p) for p in parts)
    LOG.write(line + "\n")
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def start_service():
    cmd = os.environ.get("AEGIS_SERVICE_CMD")
    if not cmd:
        log("[entrypoint] no AEGIS_SERVICE_CMD; nothing to start")
        return 0
    log("[entrypoint] starting service:", cmd)
    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=open(os.path.join(OUT_DIR, "service.log"), "a", buffering=1),
        stderr=subprocess.STDOUT,
    )
    return proc


def wait_for(port, path, limit):
    """以 HTTP healthz 輪詢，上限 limit 秒；就緒回 True。"""
    url = f"http://127.0.0.1:{port}{path}"
    deadline = os.times()[4] + limit
    import time
    end = time.time() + limit
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                log("[entrypoint] service ready:", resp.status)
                return True
        except Exception as exc:  # noqa: BLE001 — 就緒輪詢，任何錯誤都視為未就緒
            log("[entrypoint] waiting:", exc)
            time.sleep(0.3)
    return False


def run_exploit():
    # §17.1：exploit 從環境變數 AEGIS_TARGET_URL 取目標位址
    os.environ["AEGIS_TARGET_URL"] = f"http://127.0.0.1:{PORT}"
    log("[entrypoint] running exploit (AEGIS_TARGET_URL=%s)" % os.environ["AEGIS_TARGET_URL"])
    return subprocess.call([sys.executable, "/aegis/witness/exploit.py"])


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    proc = start_service()
    port = int(os.environ.get("AEGIS_SERVICE_PORT", "8000"))
    health = os.environ.get("AEGIS_HEALTH_PATH", "/healthz")
    if proc:
        if not wait_for(port, health, WAIT_LIMIT):
            log("[entrypoint] service failed to become ready (exit 2)")
            return 2
    code = run_exploit()
    if code != 0:
        log("[entrypoint] exploit crashed (exit 3)")
        return 3
    log("[entrypoint] flow complete (exit 0; success is decided by host-side oracle)")
    if proc:
        proc.terminate()
    return 0


if __name__ == "__main__":
    import time  # noqa: F401 — wait_for 使用
    try:
        sys.exit(main())
    finally:
        LOG.flush()
        LOG.close()