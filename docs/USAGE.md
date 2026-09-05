# Aegis 使用方式

## 前置需求

- Go 1.24（從原始碼建置時）
- Docker daemon
- `semgrep` 命令（建議；已設定 reviewer 時可在缺少／失敗時降級為純 LLM 全局審查）
- 至少一個 Anthropic 或 OpenAI-compatible provider 與 API key（自動 prove 時）

在專案根目錄建置：

```sh
go build -o ./bin/aegis ./cmd/aegis
```

## 首次設定

執行 `./bin/aegis`（或 `./bin/aegis console`）進入互動 console，再依序輸入：

```text
/provider add anthropic
/key set anthropic
/model set all anthropic/<你的模型 ID>
/doctor
/review --target /path/to/repo --watch
exit
```

真實終端機預設啟動英文 TUI；輸入 `/lang zh` 可切換為繁體中文，`/lang en`
切回英文。語言偏好會寫入使用者 `settings.toml`。TUI 執行審查命令時會自動開啟
AI 回覆與工具活動串流；pipe、CI 與測試環境仍使用原有純文字 console。
TUI 不攔截滑鼠，因此可直接拖曳選取後用 macOS `Cmd+C`；也可輸入 `/copy`
或按 `Ctrl+Y`，一次複製目前完整 transcript（ANSI 色碼會先移除）。

互動模式可直接執行完整流水線；`/review`、`/scan`、`/prove`、`/report`、`/replay`
接受與同名一次性 CLI 完全相同的參數。含空白的路徑可使用單引號或雙引號。

`/provider add` 會互動詢問 provider type：`anthropic`、`openai-compat`（會再詢問 `base_url`），或 `openrouter` 捷徑——仍以 openai-compat 落盤，`base_url` 直接 Enter 即採 `https://openrouter.ai/api/v1`（可貼自訂端點覆蓋）。`/model set` 的角色可給 `all`，一次把同一個 `<provider>/<model-id>` 設到全部五個角色（之後仍可逐一覆寫單一角色）。API key 優先從 `AEGIS_<PROVIDER>_API_KEY` 讀取，其次為 OS keychain，再其次才是權限 `0600` 的 credentials 檔。金鑰不應放入 `aegis.toml`。

schema、bundled pack、snapshot 與 image 記錄預設放在作業系統的使用者 cache；CI 或受限環境可用絕對路徑 `AEGIS_CACHE_DIR` 覆寫。

也可在待掃 repo 的 `aegis.toml` 設定模型與預算：

```toml
[providers.anthropic]
type = "anthropic"

[models]
prover = "anthropic/<你的模型 ID>"

[budget]
max_env_fixes_per_finding = 5
max_harness_fixes_per_finding = 8
max_hypotheses_per_finding = 3
max_sandbox_minutes_per_finding = 10
```

## 標準流程

bundled `python-web` pack 與 schemas 已內嵌進 binary，可從任意工作目錄執行：

```sh
./bin/aegis review --target /path/to/repo --watch
```

`review` 是一般使用者入口：自動建立單一 run，依序完成 scan、對所有 finding
執行 prove、離線 replay evidence，最後才產生 report。沒有 candidate 時會清楚略過
prove/replay。已設定 reviewer 時，候選發現不受 pack 語言或 sink 白名單限制；pack
只決定哪些 finding 能進 sandbox/oracle proof。尚無 proof 支援的 finding 仍保留在
報告並標示「尚未機械實證」。只有未設定 reviewer、detector 又完全不適用時才會
fail closed，避免產生誤導性的「0 弱點」報告。

LLM reviewer 採兩階段全局審查：先分批讀取跨語言原始碼與設定檔，從輸入面、
信任邊界、認證授權、狀態競態、資料流與業務邏輯找候選；再以全 repo inventory
與全部批次候選做跨檔綜整、去重和攻擊鏈補強。每個候選必須帶可在 snapshot 中
核對的 `file:line` evidence，否則不收錄。Semgrep 是獨立補充來源，不是 LLM 的
搜尋空間上限。

Reviewer 本身以唯讀 agent tool loop 運作：先取得 inventory 與分批檔名，再自行呼叫
`read_code`、`search_code`、`semgrep` 探索實際程式碼。每組工具呼叫前，模型被要求
輸出一段可公開的 investigation commentary；watch 串流以 Claude 風格呈現——`💭`
標示模型的思考(commentary，獨立縮排區塊)、`⏺ tool 參數` 配對下一行 `⎿ 結果摘要`、
`● phase` 作為分節標題。這些是供應商實際回傳的公開說明，不是偽造或揭露供應商
未提供的隱藏 chain-of-thought。純記帳的事件(送出的 payload 位元組數、token 用量)
不進 watch 串流，只保留在 run 目錄的 `ai-events.jsonl`。

inventory 目前辨識 Python、Go、JavaScript/TypeScript、Java/Kotlin、PHP、Ruby、
C#、Rust、Scala、Vue、Svelte，以及常見 markup、設定檔、shell 與 Dockerfile。
未列入辨識表、但具有非資料型副檔名且內容是 UTF-8 文字的檔案，也會以未知語言
原始碼送交 reviewer；`.txt/.csv/.log/.lock/.map` 等資料或產物預設不送出。

加入 `--watch` 可在終端看到 review plan、批次進度、公開的
`analysis_summary`、candidate 數量、prover 工具活動與明確完成／失敗狀態：

```sh
./bin/aegis review --target /path/to/repo --watch
```

終端不會傾印 source bundle、完整 prompt、完整 JSON 或 `read_code` 結果；這些完整
可稽核事件只寫入 run 目錄的 `ai-events.jsonl`。政策閘決策與工具參數仍寫在
`audit.jsonl`。兩者皆為權限 `0600`。供應商未回傳、或屬於模型內部的隱藏
chain-of-thought 不會也不能被偽造展示；介面顯示的是模型實際可見輸出與證據摘要。

### Detector、build runtime 與 proof oracle

三種能力分開呈現於 `coverage.json` 與報告：

- Semgrep detector 只快速產生 pattern candidate；其 `languages` 不代表能 build。
- Proof runtime 由 template 的 digest-pinned image、service command 與允許的 witness
  檔案決定。AI 不能任意挑 host compiler 或可變 Docker image，以免繞過 sandbox。
- 成功 build 只證明環境可編譯／啟動，不等於漏洞成立。`PROVEN` 還必須由該漏洞
  家族的可信 oracle 觀察到 nonce-backed 副作用。

因此「proof runtime 不能執行 `.go`」表示目前缺 Go 的固定建置／啟動 backend，
不是 Semgrep 禁止掃 Go。LLM 仍會審查並回報 Go finding；在 Go runtime 和對應
oracle 加入前，它會清楚維持未機械實證狀態。

`scan`、`prove`、`replay`、`report` 仍保留作為 CI、除錯與斷點續跑的進階介面：

```sh
./bin/aegis scan --target /path/to/repo
./bin/aegis prove --target /path/to/repo --watch
./bin/aegis replay --target /path/to/repo
./bin/aegis report --target /path/to/repo
```

- `scan` 建立 immutable snapshot，執行確定性 detector；若已設定 reviewer，會再依序呼叫 recon、reviewer 與 triager 完成模型審查，最後產生 `inventory.json`、`candidates.json`、`triage.json` 與 `findings.json`。未設定 reviewer 時保留零 LLM 的確定性掃描模式。
- `prove F-0001` 從最新 scan run 讀 finding，透過設定好的 prover tool loop 自動產生 WitnessSpec，再執行三控制 sandbox。省略 finding ID 會依序處理該 run 的全部 findings。
- `--hypotheses N` 可覆寫 `[budget]` 的假設上限。
- `report` 產生 `findings.json`、`findings.sarif` 與 `report.md`；已設定 reporter 時由該角色撰寫 Markdown，否則使用確定性模板。
- `replay` 離線重驗 evidence bundle。
- 若不是使用最新 run，四個命令都可用 `--run-dir /path/to/out/run-...` 明確指定。

人工 WitnessSpec 仍可用於離線除錯，但此模式不呼叫 LLM，且必須指定單一 finding：

```sh
./bin/aegis prove F-0001 --target /path/to/repo --spec witness.json
```

所有 run 產物預設位於目標 repo 的 `out/run-<timestamp>/`；工具呼叫記在 `audit.jsonl`，狀態轉移記在 `journal.sqlite`。
