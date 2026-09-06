# Aegis 介面與資料契約

本文以 [cmd/aegis/main.go](../cmd/aegis/main.go)、[domain](../internal/domain/domain.go) 與 [schemas](../schemas) 為依據，版本基準見 [文件索引](README.md)。JSON Schema 採 draft 2020-12；本文件是欄位導覽，完整 required、enum、pattern 與 additionalProperties 規則仍以各 schema 為準。

## 1. CLI 契約

| 命令 | 輸入與行為 | 主要產物 |
| --- | --- | --- |
| `aegis`／`aegis console` | 真實終端進 TUI，其他輸入環境走文字 console | 使用者設定、互動命令結果 |
| `aegis review [repo root]` | Scan → environment → prove → replay → report | 單一 run 下的全部可完成產物 |
| `aegis scan` | 建立快照與新的掃描產物 | Inventory、coverage、candidates、triage、findings、journal |
| `aegis prove [F-####]` | 處理指定 finding，省略 ID 則處理該 run 的 findings | 更新 findings、evidence、journal |
| `aegis replay` | 離線驗證 bundle 與 oracle 結果 | 命令成功或驗證錯誤 |
| `aegis report` | 產生報告，可明確更新人類 disposition | `findings.json`、`findings.sarif`、`report.md` |

### 1.1 Flags

| Flag | 適用命令 | 預設／語意 |
| --- | --- | --- |
| `--target PATH` | review、scan、prove、replay、report | `.`；目標根目錄 |
| `--target-subdir PATH` | review、scan、prove | 限定子樹；使用子樹時須留意設定與 run 根目錄的實際解析 |
| `--run-dir PATH` | review、scan、prove、replay、report | review／scan 指定輸出；其他階段選擇既有 run |
| `--pack PATH` | review、scan、prove、replay | 預設 `packs/python-web`，由 CLI 解析本地或嵌入資產 |
| `--watch` | review、scan、prove、report | `false`；顯示 AI 活動與階段摘要 |
| `--hypotheses N` | review、prove | `0` 表示使用設定值，正值覆寫假設上限 |
| `--approve-build` | review、prove | `false`；預先核准所需 proof image 建置，供非互動執行 |
| `--spec FILE` | prove | 手動 WitnessSpec JSON，免去模型產生 spec 的步驟 |
| `--set-disposition F-####=VALUE` | report | 可重複指定；只接受 disposition 閉集 |

`review` 可用位置參數傳 repo，但不得同時傳 `--target`。其他命令的精確位置參數限制請以其 `--help` 與實作為準；腳本統一使用 `--target` 最明確。

未指定 run 時，scan／review 建立 `out/run-YYYYMMDD-HHMMSS.nnnnnnnnn`（UTC）。後續階段從目標的 `out/` 選名稱字典序最大的 `run-*` 目錄，不是依修改時間。CI 與平行工作應傳入明確且各自獨立的 `--run-dir`；不要用 scan 覆寫已有證據的 run。

### 1.2 退出碼與不完整結果

CLI `main()` 在命令回傳 error 時以 `1` 結束，正常完成為 `0`。沒有「找到漏洞就必定非零」的專用退出碼；CI 的安全阻擋條件須另外解析 findings。

`review` 在 scan 失敗時停止。Environment、prove 或 replay 出錯時會盡可能產生 report，再返回錯誤。`report.md` 存在不代表整段審查完成；應同時檢查命令退出碼、coverage、environment 與 verification。

## 2. Run 目錄與 schema 對照

```text
out/run-<UTC timestamp>/
  inventory.json
  coverage.json
  candidates.json
  triage.json
  findings.json
  environment.json          # 進行 runtime check 時
  journal.sqlite
  ai-events.jsonl           # AI 階段事件
  audit.jsonl               # Agent 工具與 gate 紀錄
  findings.sarif            # report 階段
  report.md                 # report 階段
  evidence/                 # 已產生 proof evidence 時
    EV-0001.json
    ...
    bundle.manifest.json
    runs/
      R-0001/
        run_request.json
        sql_trace.jsonl     # SQL observer run
        ...                 # 依 run 路徑收回的產物
```

這是合併各階段的示意，不保證每次執行都產生所有檔案。`journal.sqlite-wal`／`journal.sqlite-shm` 也可能在資料庫使用期間存在。

| Schema | 資料用途 |
| --- | --- |
| [inventory](../schemas/inventory.schema.json) | 檔案、語言、入口等盤點資料 |
| [candidate](../schemas/candidate.schema.json) | 單筆候選；`candidates.json` 為陣列 |
| [triage](../schemas/triage.schema.json) | 單筆候選分流；`triage.json` 為陣列 |
| [finding](../schemas/finding.schema.json) | 單筆 finding；`findings.json` 為陣列 |
| [witness_spec](../schemas/witness_spec.schema.json) | 模型或使用者提交的 proof 提案 |
| [run_request](../schemas/run_request.schema.json) | Policy 產生的容器請求 |
| [run_result](../schemas/run_result.schema.json) | 執行退出碼、輸出摘要、artifact hash 等結果 |
| [evidence](../schemas/evidence.schema.json) | 含鏈結、request 與 oracle 結果的 EV 記錄 |
| [journal_event](../schemas/journal_event.schema.json) | Journal 事件的邏輯契約 |
| [environment](../schemas/environment.schema.json) | 標準 CLI 的 Python runtime 檢查結果 |
| [environment_spec](../schemas/environment_spec.schema.json) | Agent environment 提案；不是標準 CLI 的 WitnessSpec |
| [pack_manifest](../schemas/pack_manifest.schema.json) | Pack ABI、規則、template、oracle、映像 |
| [settings](../schemas/settings.schema.json) | 設定的結構描述；實際設定檔使用 TOML，由 settings 套件載入 |
| [tools](../schemas/tools.schema.json) | Agent 工具參數 definitions |

`coverage.json` 目前由 CLI 的 `coverageRecord` 定義，沒有獨立 schema 檔。`bundle.manifest.json` 則由 evidence store 的格式管理。不要假設目錄中的每個 JSON 都對應一份同名 schema。

## 3. Finding 與三維狀態

Finding 的必要欄位是 `id`、`sink`、`sources`、`reachability`、`verification`、`disposition`、`snapshot_id`。`sink` 必須有檔名、起算為 1 的行號、symbol 與 type；來源 origin 為 `semgrep` 或 `llm`。

常用 optional 欄位包括 `proof_supported`、`proof_note`、`review_evidence`、`cwe`、`mode`、`assumptions`、`evidence_id`、`severity`、`confidence`、`rationale`、`reject_scope`、`not_proven_reason`。

| 維度 | 閉集值 | 解讀 |
| --- | --- | --- |
| Reachability | `UNKNOWN`、`D0`、`D1`、`D2`、`D3` | 靜態可達性／所需接線程度 |
| Verification | `NOT_RUN`、`PROVEN`、`HYPOTHESIS_REJECTED`、`NOT_PROVEN`、`ENV_ERROR` | 機械驗證的進度或結果 |
| Disposition | `OPEN`、`FALSE_POSITIVE`、`ACCEPTED_RISK`、`FIXED` | 人類處置，不由 LLM 自行設定 |

三者獨立：`FIXED` 不會自動把舊快照的 `PROVEN` 改成未成立；修補後應對新快照重新審查。D0 為預設輸入流可達，D1 為非預設路徑可達，D2 為需薄接線的 callable sink，D3 為缺少有證據的 caller；證據不足則 `UNKNOWN`。D0／D1 對應 direct，D2／D3 對應 witness。

`HYPOTHESIS_REJECTED` 限於被測 sink、context、payload family 與 snapshot，不能外推成整個 repo 安全。`NOT_PROVEN` 的原因閉集為 `harness_budget`、`sandbox_budget`、`oscillation`、`user_cancelled`。`ENV_ERROR` 表示環境驗證無法完成。

人類更新範例：

```sh
aegis report --target /path/to/repo --run-dir /path/to/run \
  --set-disposition F-0001=ACCEPTED_RISK
```

該命令更新處置並重新產生報告；若設定 Reporter，仍可能呼叫模型。

## 4. 失敗分類與停止條件

以下是容器／runner 的退出碼分類，與 host CLI 的 `0/1` 分開：

| Run exit | 含義 | 分類 |
| --- | --- | --- |
| `0` | Run 完成 | 進 oracle／控制實驗判斷 |
| `2` | Service 尚未就緒 | harness |
| `3` | Exploit 執行錯誤 | harness |
| `124` | Host 強制逾時 | env |
| `125`、`126`、`127` | Docker 或命令環境錯誤 | env |
| 其他非零值 | 非預期執行錯誤 | 防禦性歸 env |

預設每個 finding 有 env 修正 5 次、harness 修正 8 次、不同假設 3 個、沙箱 10 分鐘的預算。這不是 LLM 費用上限。

| 觀察結果 | 扣抵／終態 |
| --- | --- |
| Provider transport 或 Docker 環境失敗 | 扣 env；耗盡為 `ENV_ERROR` |
| Negative 漏洞 oracle 誤觸發 | harness，標記 oracle misfire |
| Positive touch 失敗、service／exploit 錯誤或控制順序違規 | harness；耗盡為 `NOT_PROVEN/harness_budget` |
| Harness 連續兩次相同 exit 與 stderr hash | `NOT_PROVEN/oscillation`，但預算耗盡判斷優先 |
| Positive 已通過，exploit exit 0 且 oracle false | `controlled_miss`，扣假設；耗盡為 `HYPOTHESIS_REJECTED` |
| 控制實驗通過且 exploit oracle true | `PROVEN` |
| 累積 sandbox 秒數達上限 | `NOT_PROVEN/sandbox_budget` |

`uncontrolled` 雖是 domain 中保留的分類，v1 流程不允許用它繞過 positive control；不合法旗標組合會回 error。

## 5. WitnessSpec 與 RunRequest

WitnessSpec 的 required 欄位：

| 欄位 | 限制 |
| --- | --- |
| `template_id` | 必須能在 pack 解析 |
| `target_symbol` | 必須能在快照中靜態解析 |
| `oracle_id` | 必須與 template 同 family |
| `payload` | 非空、policy 限 2048 bytes、含 `{{NONCE}}` 或 `{{NONCE_HEX}}` |
| `generated_files` | `witness/<name>` 相對路徑；禁止 traversal；副檔名須在 template 白名單；最多 8 檔、合計 256 KiB |
| `run_mode` | `direct` 或 `witness`，須符合 template |

Schema 的 `payload.maxLength` 計字元，policy 的 Go `len` 計 bytes，因此非 ASCII payload 必須同時滿足兩者。僅通過 schema 不保證 policy 接受。

Optional `assumptions` 在 D2／D3 時須至少一條。`learning_notes` 若提供，必須恰有三項，用於「上輪學到什麼／本輪改什麼／預期觀察」；其他 optional 欄位含 `payload_variant` 與 `wiring`。

Wiring 是宣告式資料，不是任意 Python：`setup` 最多 16 個 `{method,args}`，method 須為 identifier；args 可包含字串、數字、布林、null 與巢狀陣列，不接受物件，也不接受 nonce placeholder。編成 binding 後大小上限 4096 bytes，仍須通過 secret scan。使用者應從 [E2E fixture 與測試](../tests/e2e/sqli_e2e_test.go) 查看完整可執行 spec，而非只填齊 required 欄位便假設可證明。

RunRequest 由 policy compiler 產生，模型不得設定 image、network、timeout、service command 或掛載來源。Observer-backed request 包含 `observer`、`driver`、`target.files`；orchestrator 將其轉為 target／driver RunSpec，`target.files` 的鍵須帶 `target/` 前綴。修改這些欄位代表修改信任邊界，應同步檢查 sandbox flags 與 ADR。

## 6. Evidence 與 canonical hash

ID 使用以下格式：finding `F-0001`、evidence `EV-0001`、sandbox run `R-0001`、guardrail `GR-0001`，由 journal 分配。Snapshot 為 `SN-` 加 tree hash 前 12 hex，與上述流水號不同。Schema 限四位流水號；不要把它當成無限長 ID 契約。

Evidence 的 canonical 規則定義在 [canonical.go](../internal/evidence/canonical.go)：

1. 待 hash 根物件為 `map[string]any`，不直接 hash struct。
2. 解碼使用 `json.Decoder.UseNumber()`，避免先轉成 float64 丟失數字字面。
3. JSON map keys 排序、不加格式化空白、沒有尾換行、不做 HTML escaping。
4. 整數使用 `int64` 或 `json.Number`；需固定小數位的欄位使用既定 helper。
5. Hash 格式為 `sha256:<hex>`，canonical 版本為 `canonical-v1`。

EV 記錄透過 `prev_evidence_hash` 鏈結，鏈首為 null。`bundle.manifest.json` 包含 `version=aegis-bundle-v1`、有序 evidence 清單、count、tail hash 與 root hash。Store 重開時先驗證既有 chain，再接續追加。

Run evidence 包含 `run_request_hash`、`run_result.artifact_hashes`、oracle ID／nonce／結果與 paired touch 結果；若 artifact 曾遮蔽，另有 `run_result.artifact_redactions`。Artifact hash 是保存後原始 bytes 的 hash，RunRequest hash 則是 canonical JSON hash，兩者不能用同一種任意 pretty-print 後的 hash 替代。

重新排版 EV、手動改 artifact 或混用別次 run 的 request 都可能破壞驗證。要分享可 replay 的結果，保留整個 evidence 目錄及相容 pack；要繼續 prove，還需要原 run 的 findings、journal 與對應 snapshot cache。

## 7. SQLite journal

[journal.go](../internal/journal/journal.go) 使用純 Go SQLite driver，啟用並核對 WAL、單一開啟連線、5000 ms busy timeout，ID 分配使用 immediate transaction。三張表為：

| Table | Columns | 用途 |
| --- | --- | --- |
| `meta` | `key TEXT PRIMARY KEY`, `value TEXT NOT NULL` | 保存 `schema_version` |
| `events` | `seq INTEGER PRIMARY KEY AUTOINCREMENT`, `type`, `finding_id`, `ts`, `schema_version`, `payload` | 依序追加事件；後六欄為 TEXT，finding_id 可空字串 |
| `id_alloc` | `prefix TEXT PRIMARY KEY`, `next INTEGER NOT NULL` | F／EV／R／GR 各自的下一個 ID |

Timestamp 為 UTC RFC3339Nano，payload 為 canonical JSON。Append 前檢查事件類型、finding ID 與 secret pattern。Journal schema 版本目前為字串 `1.0`；pack ABI 的 `schema_version` 則為整數 `1`，兩者不是同一個欄位契約。Journal 版本不符時拒絕開啟，沒有自動跨版本遷移。

事件閉集包含：`run_started`、`snapshot_created`、`stage_completed`、`candidate_created`、`candidate_merged`、`finding_created`、`triage_updated`、`witness_spec_submitted`、`witness_spec_rejected`、`run_requested`、`run_completed`、`evidence_written`、`verification_updated`、`budget_updated`、`disposition_updated`、`report_written`、`cancelled`。這是允許值集合，不表示每個 run 都會發出每一種事件。

唯讀調查範例（需另有 `sqlite3` 命令）：

```sh
sqlite3 -readonly /path/to/run/journal.sqlite \
  'SELECT seq, type, finding_id, ts FROM events ORDER BY seq;'
```

Journal 採應用程式層 append-only，並不是防管理者改寫的資料庫。備份時讓執行程序先正常結束，或使用 SQLite 備份機制；不要在活躍寫入期間只複製主檔而忽略 WAL。
