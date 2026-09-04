# ADR 0005：observer-backed run 的雙容器信任切分（P0-01 修補）

日期：2026-09-04
狀態：已採納（對應 review docs/CODE-REVIEW-2026-09-04.md 的 P0-01）
關聯：ADR 0004（trusted observer）、ADR 0002（witness 注入 staging）、SPEC §17

## 背景

P0-01（review）：trusted SQL observer 可被 adversarial witness 偽造。舊架構下
`packs/python-web/sandbox/sitecustomize.py` 的 trace shim 與模型產生的
`witness/*.py` 跑在**同一個容器**：`internal/observerproxy` 的 TCP 協定接受任何
連線的 `{op:"execute", sql, params}` 並把結果寫進 trusted volume 的
`sql_trace.jsonl`。攻擊腳本不必呼叫 target symbol——直接向
`observer:8787` 送出含 nonce 的 SQL 字串即可假造 trace，讓 oracle 誤判 PROVEN。
任何「token／共用秘密」式的鑑權都救不了：shim 拿得到的 secret，攻擊碼同樣拿得到
（同 process、同檔案系統、同環境變數）。

## 決策

observer-backed run（`spec.ObserverImage != ""`）改為**雙容器＋雙網路**：

```
network A（observer internal, aegis-ssrf-<runID>）          network B（driver internal, aegis-driver-<runID>）
┌──────────────────────┐    ┌─────────────────────────┐     ┌──────────────────────────────┐
│ observer sidecar     │    │ 容器 T（trusted side）  │◄────│ 容器 W（driver）             │
│ observer-proxy:8787  │    │ entrypoint(role=target) │ HTTP│ entrypoint(role=driver)      │
│ trusted volume 唯一  │    │  └ pack harness         │     │  └ witness/exploit.py（模型） │
│ 寫入者（ADR 0004）   │    │    └ /target snapshot   │     │  └ /aegis/payload.txt        │
└──────────────────────┘    └─────────────────────────┘     └──────────────────────────────┘
```

- **容器 T**（trusted side）：同一 pack 映像，cmd 仍為
  `/aegis/entrypoint.py --template <id>`，環境多 `AEGIS_ROLE=target`。它起
  `service` cmd（witness 模式下是 pack 自帶的 `target_harness.py`；direct 模式下是
  `/target` 的目標服務），掛 /target snapshot（ro）、out volume、witness volume（ro）。
  進 network A（連 observer）與 network B（以 alias `target` 被驅動端呼叫）。
  **容器內不含任何模型產生檔案的執行**：T 跑的是 pack 內容物與被審 repo 原碼。
- **容器 W**（driver）：模型 generated_files（`witness/*`）與 payload 只掛進 W。
  cmd 同為 entrypoint，環境 `AEGIS_ROLE=driver`＋`AEGIS_TARGET_URL`，等 T 的
  health 就緒後執行 exploit 腳本。**不掛 /target、不進 network A、不掛
  trusted volume**——模型程式碼與 observer 之間沒有任何網路路徑，trace 只能由
  T 內的 shim（經 target_harness／目標服務真實執行 SQL）產生。
- **target binding 走宣告式資料**：prover 在 WitnessSpec 帶入新的 optional
  `wiring` 欄（`{"setup":[{"method","args":[JSON 字面值]}]}`；method 名須為
  identifier、args 不得含可執行內容、大小上限 4KiB、允許 `{{NONCE}}` placeholder、
  同樣過金鑰掃描）。policy compiler 驗證後把 `target_symbol`＋`wiring` 編成
  `target/binding.json`（RunRequest 的新 `target.files`），由 T 內 pack 自帶的
  `target_harness.py` 解析：`sys.path.insert(0,"/target")`、import 模組、無參
  建構、依序執行 setup、之後以 HTTP 服務 `GET /c/<urlquoted payload>` →
  `method(payload)`。模型端永不提供 binding 執行碼，只提供資料。
- **W 的 `/aegis/out` 為 tmpfs**（uid/gid 65532、16m）：entrypoint 的 run.log 照寫
  （docker logs 仍收得到），但 W 寫不出任何會被收回的 artifact——out volume 只掛
  T。artifacts 收回（§17.6）以 T 的 out volume＋trusted volume 為來源；`fs_diff`
  主證據仍取自 W（run_result 描述 W 的 exit／stdout／stderr），T 的 diff 另存
  `fs_diff_target.txt`（資訊性）。
- **生命週期**（prove.executeRun）：StageWitness（單一 per-run volume，同時含
  `witness/*` 與 `target/*` 檔）→ StartObserver（建 network A＋B、trusted volume、
  起 observer sidecar）→ docker create T（network A）→ `docker network connect
  aegis-driver-<runID> T --alias target` → StartDetached(T) → create W →
  Start(W, timeout)（W 的 exit 維持 §17.1 契約）→ logs（T 的另存 target.log）→
  ReclaimPair（diff 兩容器、收回、rm 兩容器、刪兩網路＋trusted/out/witness
  volume、StopObserver）。
- **non-observer run 不變**：RunRequest 無 `driver`/`target`/`observer` 鍵時走
  原單容器路徑（`sitecustomize` 的本地 TracedConnection 寫 out volume，
  與模型碼同容器但無可信事件可偽造——單容器模式本就無 trusted observer）。

## 為何是雙容器而非加鑑權

observer 的可信事件要求「SQL 真的執行於目標程式」。任何跑在 W 內的機制
（token、來源檢查、單向牆）都在攻擊碼的可控範圍內；唯一不依賴 W 自律的邊界
是網路拓撲。切分後 W 沒有到 observer 的路由（network B 是 `--internal`、僅
T 兩側掛接），任意 witness 程式無法自行產生可信事件。

## 殘餘風險（記錄在案，不在本 ADR 範圍）

- T 內的目標 repo 原碼本身是攻擊者（威脅模型 T12：使用者自己的 repo）時，
  它與 shim 同容器、可直接寫 `AEGIS_SQL_TRACE` 或連 observer。此為審計對象
  即攻擊者的問題，SPEC §17 的威脅模型不涵蓋。
- W 的 exit code 與 stdout/stderr 仍是自證輸出；oracle 判定不讀它們（§17.3
  既有原則，非本 ADR 新增）。

## 後果

- `schemas/witness_spec.schema.json` 增 optional `wiring`；
  `schemas/run_request.schema.json` 增 optional `driver`、`target`。
- pack 的新增內容物：`sandbox/target_harness.py`；`entrypoint.py` 改為
  role-aware（`AEGIS_ROLE` 未設 → 舊單容器行為不變）。
- E2E 新增 adversarial test：witness 不呼叫 target symbol、直接對
  `observer:8787` 進行連線嘗試 → 終態不得為 PROVEN（trace 只能由 T 產生）。
- 映像內容變更 → 依 §17.10 重建並重錄 manifest digest。