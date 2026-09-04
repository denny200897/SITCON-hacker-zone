#!/usr/bin/env python3
"""Aegis 沙箱 entrypoint（pack 內容物；SPEC §17.1、ADR 0005）。

以 AEGIS_ROLE 選擇角色（ADR 0005 雙容器信任切分）：
  未設定（legacy 單容器）：起 service → 等就緒 → 跑 exploit（舊行為不變）。
  target（容器 T，trusted side）：起 service → 等就緒 → 常駐（host 端 reclaim 終止）。
  driver（容器 W）：不跑 service；等 AEGIS_TARGET_URL 的 health 就緒 → 跑 exploit。

共用三階段：(a) 起 service（template metadata 決定 cmd），以 health 輪詢（上限
20s）；(b) 執行 exploit（python /aegis/witness/exploit.py，payload 從
/aegis/payload.txt 讀、目標位址取環境變數 AEGIS_TARGET_URL）；(c) 收尾傾 dump。
全程 log 導入 /aegis/out/run.log（driver 容器的 /aegis/out 為 tmpfs）。

Exit code 契約（閉集，SPEC §17.1）：
  0   流程跑完（不代表攻擊成功；成功只由 host 端 oracle checker 判定）
  2   service 未在限期內就緒（harness）
  3   exploit 腳本例外崩潰（harness）
"""
import os
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


def wait_url(url, limit):
    """以 HTTP 輪詢 url，上限 limit 秒；就緒回 True。"""
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
    # §17.1：exploit 從環境變數 AEGIS_TARGET_URL 取目標位址（legacy 單容器自行
    # 組本機位址；driver 模式由 policy 編譯的 env 提供，此處不覆寫）。
    os.environ.setdefault("AEGIS_TARGET_URL", "http://127.0.0.1:%d" % PORT)
    log("[entrypoint] running exploit (AEGIS_TARGET_URL=%s)" % os.environ["AEGIS_TARGET_URL"])
    return subprocess.call([sys.executable, "/aegis/witness/exploit.py"])


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    role = os.environ.get("AEGIS_ROLE", "")
    if role == "driver":
        # ADR 0005：容器 W（模型 driver）不跑 service；trusted side 的位址由
        # policy 編譯的 AEGIS_TARGET_URL 提供，等它就緒後執行 exploit。
        base = os.environ.get("AEGIS_TARGET_URL", "")
        if not base:
            log("[entrypoint] driver 模式缺 AEGIS_TARGET_URL（exit 2）")
            return 2
        if not wait_url(base + HEALTH_PATH, WAIT_LIMIT):
            log("[entrypoint] trusted side not ready (exit 2)")
            return 2
        code = run_exploit()
        if code != 0:
            log("[entrypoint] exploit crashed (exit 3)")
            return 3
        log("[entrypoint] flow complete (exit 0; success is decided by host-side oracle)")
        return 0
    proc = start_service()
    if proc:
        if not wait_url("http://127.0.0.1:%d%s" % (PORT, HEALTH_PATH), WAIT_LIMIT):
            log("[entrypoint] service failed to become ready (exit 2)")
            return 2
    if role == "target":
        # ADR 0005：容器 T 是常駐 trusted side；服務就緒後保持運行（host 端
        # reclaim 終止）。服務死掉則一併退出（非零），W 端會因連線失敗顯性錯誤。
        if proc:
            code = proc.wait()
            log("[entrypoint] target role: service exited (%s)" % code)
            return code if code else 0
        log("[entrypoint] target role: no service; holding")
        time.sleep(3600)
        return 0
    code = run_exploit()
    if code != 0:
        log("[entrypoint] exploit crashed (exit 3)")
        return 3
    log("[entrypoint] flow complete (exit 0; success is decided by host-side oracle)")
    if proc:
        proc.terminate()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        LOG.flush()
        LOG.close()