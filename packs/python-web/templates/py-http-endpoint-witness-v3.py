# harness 樣板：py/http-endpoint/v3（witness 模式；SPEC §2.2、§6.1-2）
#
# 見證骨架——prover 的 generated_files 取代本檔成為 /aegis/witness/ 注入內容；
# 本檔是「可直接填空的 witness 骨架」，供 prover 依樣填空，也供 replay 測試。
# 約束（§2.2）：import 原碼（sys.path 掛 /target 唯讀）、最小 wiring（≤8 檔）、
# 單一入口；exploit 不自行硬編 payload（從 /aegis/payload.txt 讀）。
#
# 佔位符（由 prover 填空）：
#   {{TARGET_MODULE}}  —— 目標 repo 內被質疑的 module（如 app）
#   {{TARGET_CLASS}}   —— 類別名（如 UserRepo）
#   {{TARGET_METHOD}}  —— 方法名（如 find_by_name）
#   {{NONCE}}          —— policy compiler 統一替換，prover 事前不知實際值
import os
import sqlite3
import sys

sys.path.insert(0, "/target")  # import 原碼（唯讀掛載點）——禁止複製改寫（§2.2-1）

from {{TARGET_MODULE}} import {{TARGET_CLASS}}  # noqa: E402

PORT = int(os.environ.get("AEGIS_SERVICE_PORT", "8000"))

_repo = {{TARGET_CLASS}}()

app = _build_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)