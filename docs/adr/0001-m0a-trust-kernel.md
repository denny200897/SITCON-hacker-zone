# ADR 0001 — M0a Trust Kernel 工程決策記錄

日期：2026-09-04　｜　狀態：accepted

## 決策

1. **Canonical JSON 唯一路徑**（§21.4）：`internal/evidence.canonical()` 為全工具唯一序列化路徑。
   待 hash 物件一律 `map[string]any`；解碼一律 `json.Decoder`＋`UseNumber()`；
   `SetEscapeHTML(false)`＋去尾換行；整數 `int64`、定點小數 `json.Number(strconv.FormatFloat(v,'f',2,64))`。
   struct 一律禁止進 hash 路徑（fixture 測試鎖定 struct/map 序列化差異作提醒）。

2. **Schema 真源與 $ref**：11 個 `schemas/*.schema.json` 為唯一機讀真源（§21.1）。
   `internal/schemav.Registry` 單一 compiler 註冊全部資源（$id 相互解析），
   `disabledLoader` 阻擋任何外部 schema 載入（防證明迴圈中途動環境）。

3. **Journal**：`modernc.org/sqlite`（純 Go 無 cgo）＋ WAL；event type 閉集
   （§21.3，17 種）；ID 分配以 `BEGIN IMMEDIATE` 交易保證 monotonic zero-pad 4
   （§21.2），序列 v1 下同樣照此實作。

4. **Policy compiler**：WitnessSpec 驗證閉集（§17.9-1~7）逐條實作為 `SpecError` 閉集
   reason；RunRequest 組裝（caps/mounts/network/image）全部由政策決定，
   nonce 由 runner 產生、prover 事前未知（§17.2），SpecError 訊息不含 nonce。

5. **Sandbox flags**：§17.1 canonical run flags 落為 `sandbox.DockerArgs` 純函式，
   每條 hardening flag 有 unit test；docker 整合測試以 `docker inspect` 逐項驗證
   生效（§22 M0a），docker 不可用時 skip 不影響其他測試。逾時 host 端強制
   （context.WithTimeout + docker kill → exit 124）。

6. **Budget/classification**：§19 決策樹（依序第一命中）落為 `budget.Classify`；
   §9.3 停止條件落為 `budget.OnFailure`——放棄權完全在 orchestrator。

## 影響

- oracle 條件種類為 checker 內封閉 enum，pack 只能引用不能擴充（防 rule 直譯器，§17.3）。
- pack ABI 驗證拒載條件含「touch 缺漏」（§17.3）與「不支援 capability」（§6.4）。
- 映像解析序（§17.10）：manifest digest → 本地 images.json → ENV_ERROR；不自動構建。

## 追溯

每條決策回溯 `docs/threat-model.md` 的 T1/T2/T3/T4/T5/T9/T10。