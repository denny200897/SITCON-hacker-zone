# Aegis 開發與維運

本文涵蓋原始碼建置、測試、部署與維護；架構背景見 [技術架構](TECHNICAL.md)，產物與命令契約見 [介面與資料契約](CONTRACTS.md)。以下 shell 範例以 macOS／Linux 為主，Windows 使用相應 PowerShell 環境變數與 `.exe` 路徑。

## 1. 開發環境與建置

依賴版本由 [go.mod](../go.mod)／[go.sum](../go.sum) 固定。`go.mod` 宣告 Go 1.24.2，現有 release workflow 使用 Go 1.26。主要依賴包括 Cobra、Bubble Tea／Lip Gloss、BurntSushi TOML、jsonschema/v6、Anthropic SDK、go-keyring 與 modernc SQLite。

```sh
go version
go mod download
go build -o ./bin/aegis ./cmd/aegis
./bin/aegis --help
./bin/aegis review --help
```

發布方式的本地建置：

```sh
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o ./bin/aegis ./cmd/aegis
```

CLI 可從任意工作目錄執行，因為 `schemas/*.json` 與 `packs/python-web` 透過 `go:embed` 放進 binary。需檔案路徑的工具會透過 `Materialize` 解出至 cache 的 `assets/<16 hex>/`；key 依資產路徑與內容計算。既有檔案內容不符時會以暫存檔替換。修改 pack／schema 後必須重建 binary 才能更新嵌入資產。

只跑靜態 scan 不需要 Docker。Proof 與 source compile check 需要 Docker daemon、Linux 容器及對應映像；模型流程需要 provider 設定與 key。Semgrep 是外部命令，不會隨 Go binary 一起安裝。

## 2. 設定、憑證與儲存位置

| 項目 | 解析方式 |
| --- | --- |
| User settings | 絕對路徑 `XDG_CONFIG_HOME` 下的 `aegis/settings.toml`；否則 `~/.config/aegis/settings.toml` |
| Repo settings | 階段所解析 repo 根目錄的 `aegis.toml` |
| Model | Repo 設定優先，其次 user；沒有內建模型預設 |
| Budget | 各欄位獨立套用 repo > user > 預設 5／8／3／10；非正值不作為覆寫值 |
| Credentials | `AEGIS_<PROVIDER>_API_KEY` 與相容環境變數 > OS keychain > `credentials.toml` |
| Cache | 絕對路徑 `AEGIS_CACHE_DIR`；否則 `os.UserCacheDir()/aegis` |
| Run 產物 | 掃描目標下 `out/run-*`，或明確 `--run-dir` |

Provider 的大寫環境變數名稱正規化與相容別名以 [credentials.go](../internal/credentials/credentials.go) 為準。`/key set` 優先寫 OS keychain，不可用時退回 `0600` 的 credentials 檔；settings 與 repo TOML 不放金鑰。Cache 路徑不是所有 OS 都是 `~/.cache`。

最小團隊設定可寫成以下形狀，將 `YOUR_MODEL_ID` 換成 provider 可用的模型 ID：

```toml
[providers.team]
type = "anthropic"

[models]
recon = "team/YOUR_MODEL_ID"
reviewer = "team/YOUR_MODEL_ID"
triager = "team/YOUR_MODEL_ID"
prover = "team/YOUR_MODEL_ID"
reporter = "team/YOUR_MODEL_ID"

[budget]
max_env_fixes_per_finding = 5
max_harness_fixes_per_finding = 8
max_hypotheses_per_finding = 3
max_sandbox_minutes_per_finding = 10
```

此時 CI secret 應透過 `AEGIS_TEAM_API_KEY` 注入。若改用 `openai-compat`，還需提供 `base_url`。這裡只描述專案設定契約，不保證任意第三方端點都支援工具與串流能力。

Cache 內主要有 `assets/`、`snapshots/`、`images.json`。Image 解析在 `packAdapter.resolveImage` 先查以原 ref 為 key 的本機 cache override，再接受既有 digest 或 manifest 的 image mapping；這讓 `/doctor` 重建後的新 digest 能覆寫舊 ref。不要只依早期註解中的「digest 優先」文字判讀實際順序。

## 3. 測試層次

文件或低影響修改先驗證連結、命令與相關契約即可；涉及 proof、policy 或儲存格式時須跑對應 Go 測試。

```sh
# 一般套件與契約測試，不包含 tests/e2e 套件
go test . ./cmd/... ./internal/... ./tests/contracts

# 完整套件；E2E 可能存取 Docker 並在必要時建置映像
go test ./...

# 有條件需要時，檢查 race 與靜態問題
go test -race . ./cmd/... ./internal/... ./tests/contracts
go vet ./...
```

| 測試範圍 | 驗證重點 |
| --- | --- |
| `tests/contracts` | Schema 與封閉契約一致性 |
| `internal/orchestrator/policy` | 非法 spec、wiring、秘密、路徑與重複提案 |
| `internal/sandbox` | Docker flags、split network／mount、staging 與回收 |
| `internal/evidence`、`internal/journal` | Canonical hash、bundle、版本與 ID 連續性 |
| `internal/agent`、`internal/llm` | 工具權限、audit、adapter 行為與錯誤處理 |
| `cmd/aegis` | CLI 接線、coverage、角色與完整流程分支 |
| `tests/e2e` | 真容器 SQLi、controlled miss、observer 偽造阻擋與 Prover loop |

單獨執行端到端測試：

```sh
go test ./tests/e2e -v -count=1
```

必須閱讀輸出中的 `PASS`／`SKIP`，不能只看整體 exit 0。Docker 不可用、manifest digest 在本機不存在或不符時，E2E 可能 skip；tag 不存在時 setup 可能建置 pack image。這些測試的 Prover adapter 使用測試替身，不等於已測過使用者的真實 provider 帳戶。

E2E 的映像檢查直接使用測試載入的 manifest ref；不要假設 CLI `images.json` 的 override 會自動傳入測試。映像變更後須核對實際 digest、manifest 與測試 setup 的接線，再宣稱 Docker E2E 已完成。

`AEGIS_E2E_KEEP` 可保留測試 artifact，但使用固定暫存位置，setup 會清掉前次保存內容。除錯時一次只挑一個測試，並在下一次執行前複製要保留的結果：

```sh
AEGIS_E2E_KEEP=1 go test ./tests/e2e -run '^TestM0bSqliProvenE2E$' -v -count=1
```

## 4. CI 使用方式

下列範例假設 binary、Docker、provider 路由與 secret 已由 CI 準備。使用獨立工作目錄與明確 run，方便定位本次產物：

```sh
export AEGIS_CACHE_DIR="$PWD/.aegis/cache"
run_path="$PWD/out/ci-review"
aegis review --target "$PWD" --run-dir "$run_path" --approve-build
```

`out/ci-review` 應在本次工作中尚未使用；若 CI 重用 checkout，改成每次唯一的目錄。非 TTY 預設拒絕未核准建置，`--approve-build` 是對所需 proof image 建置的明確授權；建置與隔離 run 的網路政策不同。

整合流程應先保存 CLI 退出碼，再於成功或失敗時都收集已存在的 run 產物。依 findings 中 `verification`、`severity`、`disposition` 制定團隊阻擋規則；不能只用「沒有 PROVEN」判定安全，因為可能有未支援 proof 或環境失敗的 finding。

機器整合優先收集 `findings.json`、`coverage.json`、`environment.json`（若存在）與 `findings.sarif`。除錯與重驗再保留 journal、整個 evidence bundle 及必要快照。`ai-events.jsonl` 與 `audit.jsonl` 應採受限存取與保存期限，因為可能涉及原碼和工具參數。

## 5. 發布與安裝

[release.yml](../.github/workflows/release.yml) 在 `v*` tag push 或手動 dispatch 時建置。矩陣為 linux／darwin／windows × amd64／arm64，使用 `CGO_ENABLED=0`、`-trimpath`、`-ldflags "-s -w"`，產物為 `aegis-<os>-<arch>`，Windows 加 `.exe`，再附加到 GitHub Release。

目前 workflow 只有建置與附加 release 資產，沒有執行 Go 測試、Docker E2E 或生成獨立簽章／checksum 清單的步驟。發布前應先完成與改動相符的驗證，不要把 release job 成功當成測試全部通過。

[install.sh](../scripts/install.sh) 與 [install.ps1](../scripts/install.ps1) 依平台下載 release binary，支援 `AEGIS_VERSION`、`AEGIS_INSTALL_DIR`、`AEGIS_REPO`。macOS／Linux 安裝器不自動修改 shell 設定；Windows 安裝器處理使用者 PATH。使用者安裝指令與平台細節見 [README](../README.md#安裝方式)。

這是 CLI 的發布流程，沒有伺服器部署、資料庫服務啟動或 Web 資產部署步驟。升級前要保留需要的 run／pack 版本；舊 evidence 是否可重驗取決於相容 schema、checker 與規則，不只取決於新 binary 能否啟動。

## 6. 擴充與修改檢查

### 新增 detector 或 pack

1. 以 [python-web manifest](../packs/python-web/manifest.json) 與 pack schema 為結構依據，定義 detector、sink family、template、oracle、paired touch、payload 與映像。
2. 在原始 pack 目錄新增資產並更新對應 SHA-256；檔案 bytes 與 inline 規則的雜湊方式以 [packs.go](../internal/packs/packs.go) 為準，不要只對 pretty JSON 一律執行相同 hash 命令。
3. 核對 schema ABI、唯一 ID、支援的 capabilities、digest image 與 family／touch 配對。
4. 用 detector fixture、policy 拒收案例、oracle 真／假控制與 replay 驗證功能。
5. 修改嵌入 pack 後重建 binary；修改 image 內容後重建映像並更新需要的 digest 記錄。

`--pack` 可指定目錄，但 CLI 以 `allowCommunity=false` 載入；現有工具沒有開放任意 community pack 的自動安裝或核准旗標。Pack 宣告能力也必須符合 core 支援集合，不能以 manifest 自創可執行 oracle。

### 新增 runtime 或 oracle

只有增加 Semgrep `languages` 或 sink type 不足以新增 proof 能力。需一起完成固定映像、環境檢查、target／driver 啟動方式、可信 observation、三控制實驗、policy 接線、artifact schema、replay 與 coverage 顯示。新增 oracle condition kind 要修改 host checker 的閉集與測試，不能交由模型提供判定程式。

### 修改 schema 或狀態

JSON schema 為資料契約來源，工具定義直接使用它。變更欄位時同步檢查 domain enum、producer、consumer、reporting、contract tests、canonical hash 與舊 bundle 相容性。Journal 版本變更須規劃遷移；現有 opener 遇到不相容版本只會拒絕。

### 新增 provider adapter

實作 `llm.Adapter`，保留 tool call ID、訊息歷史、stop reason、usage、取消與錯誤語意；再接上 settings provider type、credentials 與 console 選單。Provider 差異應留在 adapter，不能讓供應商回傳文字直接決定 proof 終態。現有 adapter 測試可作為 request／response fixture 範例。

## 7. 排錯與資料保存

| 症狀 | 檢查順序與處理 |
| --- | --- |
| `semgrep not found` | 檢查 PATH 與 Reviewer 是否設定；無 Reviewer 時需可執行的適用 detector |
| Model unset／key missing | 在 console 用 `/status`、`/provider list`、`/model list`；核對 provider 名稱與 key 來源 |
| Image 無法解析或不存在 | `/doctor` 查看 Docker 與映像；核對 pack ref、`images.json` 和本機 digest |
| 非互動建置遭拒 | 在已授權的 CI 命令使用 `--approve-build`，或先於互動環境準備映像 |
| `SOURCE_COMPILED` 但 prove 跳過 | 查看 `proof_supported`、`proof_note` 與 coverage；可能沒有對應 oracle |
| `ENV_ERROR`／`NOT_PROVEN` | 先看 environment、verification reason，再看 journal、run evidence、audit；不要只反覆增加預算 |
| Spec 被拒 | 核對 schema、target symbol、family／mode、nonce、路徑、assumptions、wiring 與 secret gate |
| Replay hash 不符 | 檢查 bundle 是否完整、檔案是否被重排／修改、pack 是否一致；從原始備份恢復，不手動改 hash 掩蓋問題 |
| Journal 版本不符 | 保留資料並使用相容 binary，或先做正式遷移；不直接改 `meta` 假裝相容 |
| 找錯 run | 顯式傳 `--run-dir`；預設選擇依目錄名稱排序 |

程序中斷後可先唯讀列出 Aegis 容器與相關資源：

```sh
docker ps -a --filter label=aegis.run_id
docker network ls --filter name=aegis-
docker volume ls --filter name=aegis-
```

清理前核對 run ID、labels 與目前仍在執行的程序，只處理確定屬於已結束 run 的資源。避免以全域 Docker prune 代替定位。Aegis 沒有要求為例行維護清掉全部 Docker 資料。

重驗保存整份 evidence 與相容 pack；斷點繼續驗證另外保留 findings、journal、snapshot。快照包含受測原碼，清除 cache 前確認是否還有 run 需要它。應在正常停止程序後備份 journal，並把模型事件、程式碼快照與報告視為可能含專案敏感資訊的產物。
