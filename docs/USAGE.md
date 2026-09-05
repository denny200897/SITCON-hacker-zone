# Aegis 使用方式

## 前置需求

- Go 1.24（從原始碼建置時）
- Docker daemon
- `semgrep` 命令
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
/model set prover anthropic/<你的模型 ID>
/doctor
exit
```

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
./bin/aegis scan --target /path/to/repo
./bin/aegis prove F-0001 --target /path/to/repo --watch
./bin/aegis report --target /path/to/repo
./bin/aegis replay --target /path/to/repo
```

- `scan` 建立 immutable snapshot，再產生 `inventory.json`、`candidates.json`、`triage.json` 與 `findings.json`。
- `prove F-0001` 從最新 scan run 讀 finding，透過設定好的 prover tool loop 自動產生 WitnessSpec，再執行三控制 sandbox。省略 finding ID 會依序處理該 run 的全部 findings。
- `--hypotheses N` 可覆寫 `[budget]` 的假設上限。
- `report` 產生 `findings.json`、`findings.sarif` 與 `report.md`。
- `replay` 離線重驗 evidence bundle。
- 若不是使用最新 run，四個命令都可用 `--run-dir /path/to/out/run-...` 明確指定。

人工 WitnessSpec 仍可用於離線除錯，但此模式不呼叫 LLM，且必須指定單一 finding：

```sh
./bin/aegis prove F-0001 --target /path/to/repo --spec witness.json
```

所有 run 產物預設位於目標 repo 的 `out/run-<timestamp>/`；工具呼叫記在 `audit.jsonl`，狀態轉移記在 `journal.sqlite`。
