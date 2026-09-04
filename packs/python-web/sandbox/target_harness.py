#!/usr/bin/env python3
"""Aegis target harness（pack 內容物；ADR 0005 雙容器信任切分的 trusted side）。

容器 T（trusted side）內由 entrypoint 以 AEGIS_SERVICE_CMD 啟動。職責：讀取
policy compiler 編譯的 /aegis/witness/binding.json（純資料：module/class/method
與宣告式 setup，絕非模型執行碼）、把 /target 加進 sys.path、import 目標模組、
無參建構 class、依序執行 setup 呼叫，之後以 HTTP 服務 payload 輸入：

  GET /healthz                   → {"ok": true}
  GET /c/<payload>               → target.method(payload)（JSON 回應）

模型產生的 driver（容器 W）只打本服務的 HTTP 面。SQL 觀測由 sitecustomize 的
shim 在本容器內攔截（設有 AEGIS_OBSERVER_ADDR 時轉送 trusted observer）；W
內沒有 observer 位址也沒有本檔案——可信事件只能由真實執行目標碼的 T 產生
（ADR 0005；P0-01 的封鎖面）。

Exit code：初始化失敗（binding 缺檔／模組匯入失敗等）直接崩潰（非零），由
entrypoint 的 health 輪詢偵測 → exit 2（harness）。
"""
import json
import os
import sys

BINDING_PATH = os.environ.get("AEGIS_TARGET_BINDING", "/aegis/witness/binding.json")
TARGET_ROOT = "/target"
PORT = int(os.environ.get("AEGIS_SERVICE_PORT", "8000"))


def load_binding():
    """載入 binding、執行宣告式 setup，回傳要餵 payload 的 target method。"""
    with open(BINDING_PATH, encoding="utf-8") as f:
        doc = json.load(f)
    module_name = doc["module"]
    class_name = doc.get("class") or ""
    method_name = doc["method"]
    setup = doc.get("setup") or []
    sys.path.insert(0, TARGET_ROOT)
    target = __import__(module_name)
    if class_name:
        target = getattr(target, class_name)()  # 無參建構（§17.9-2 的 v1 接線契約）
    for call in setup:
        getattr(target, call["method"])(*call["args"])
    return getattr(target, method_name)


def main():
    from flask import Flask, jsonify

    method = load_binding()
    app = Flask(__name__)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/c/<path:payload>")
    def call(payload):
        # Flask 的 route 參數已 URL-decode 一次；不得二次 unquote（payload 內含
        # % 字元會被破壞）。
        try:
            result = method(payload)
        except Exception as exc:  # noqa: BLE001 — 目標方法的例外本身就是觀測面
            return {"error": "%s: %s" % (type(exc).__name__, exc)}, 500
        return jsonify(result)

    # 0.0.0.0：driver 容器（W）跨容器呼叫；health 輪詢走 127.0.0.1 同樣可用。
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()