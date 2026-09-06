# Aegis

以 AI 探索程式碼風險，以沙箱與可信證據驗證漏洞。

Aegis 是在本機執行的程式碼安全審查 CLI（Code Security Review Agent Harness）。它結合 LLM 的跨檔案分析、靜態掃描與 Docker 沙箱，從本機儲存庫建立快照、找出候選弱點，對支援的漏洞執行機械驗證，最後輸出可閱讀、可供工具處理與可離線重驗的結果。

[官方網站](https://aegis.denny.li) · [下載版本](https://github.com/denny200897/SITCON-hacker-zone/releases) · [使用文件](docs/USAGE.md) · [回報問題](https://github.com/denny200897/SITCON-hacker-zone/issues)

## 目錄

- [產品特點](#產品特點)
- [支援範圍與限制](#支援範圍與限制)
- [安裝方式](#安裝方式)
- [快速開始](#快速開始)
- [設定供應商與模型](#設定供應商與模型)
- [使用方法](#使用方法)
- [報告與證據](#報告與證據)
- [資料與安全邊界](#資料與安全邊界)
- [疑難排解](#疑難排解)
- [開發與貢獻](#開發與貢獻)
- [授權](#授權)

## 產品特點

- **一次完成審查流程**：`aegis review` 串接掃描、環境準備、漏洞驗證、證據重驗與報告產生，不必手動管理各階段產物。
- **跨語言、跨檔案的 AI 審查**：Reviewer 使用唯讀的程式碼讀取、搜尋與 Semgrep 工具，先分批探索，再綜整候選、去重與分析攻擊鏈。候選必須附上可在快照中核對的檔案與行號證據。
- **靜態分析與 AI 互補**：Semgrep 提供確定性的規則候選；AI 可進一步探索認證授權、信任邊界、資料流、競態與業務邏輯，不受 Semgrep 規則清單限制。
- **以觀察結果判定漏洞**：Prover 產生結構化驗證規格（WitnessSpec），交由政策檢查與沙箱執行。只有可信判定器（oracle）與控制實驗通過，才能標示 `PROVEN`；模型自行宣稱成功不算證據。
- **隔離執行與可追溯證據**：使用固定映像、唯讀快照、容器權限與資源限制，保存 evidence bundle、工具稽核紀錄及狀態轉移，並支援離線重驗。
- **自帶 API 金鑰與角色路由**：支援 Anthropic、OpenAI-compatible 端點及 OpenRouter，可為五種角色分別指定供應商與模型。
- **終端互動與自動化兼顧**：提供英文／繁體中文 TUI、選單操作、即時活動串流，以及適合腳本和 CI 的一次性命令。
- **多種報告格式**：輸出 Markdown、JSON 與 SARIF，方便人工閱讀、後續分析與整合安全工具。

## 支援範圍與限制

「能審查程式碼」與「能在沙箱證明漏洞」是兩個不同的能力。

| 能力 | 目前範圍 |
| --- | --- |
| AI 程式碼審查 | 辨識 Python、Go、JavaScript／TypeScript、Java／Kotlin、PHP、Ruby、C#、Rust、Scala、Vue、Svelte，以及常見設定檔、Shell、Dockerfile 等；部分未辨識語言的 UTF-8 原始碼也可納入 |
| 內建靜態規則 | `python-web` pack 的 Python SQL 字串串接規則 |
| 內建實證環境 | Python Web runtime；可進行隔離的原始碼編譯檢查 |
| 內建漏洞判定器 | SQL injection 的 SQL trace／錯誤觀察與 sink-touch 控制 |
| 其他語言或漏洞家族 | 可由 AI 提出 finding，但沒有對應 runtime／oracle 時會保留為尚未機械實證 |

`SOURCE_COMPILED` 只表示原始碼通過編譯檢查，不表示依賴已安裝、應用已啟動或漏洞成立。`NOT_PROVEN` 也不代表安全；請搭配驗證原因、覆蓋範圍與證據判讀。合成見證下的證明，仍需與原應用實際可達性分開看待。

Aegis 適合開發中的安全檢查、修補前的問題調查，以及 CI 中的審查產物生成。完整審查可能產生多次 LLM 呼叫，模型費用由使用者的供應商帳戶負擔。

## 安裝方式

### 環境需求

| 項目 | 何時需要 |
| --- | --- |
| macOS、Linux 或 Windows，amd64／arm64 | 執行 CLI；發布流程包含這六種組合 |
| Docker daemon 與可用的 Linux 容器環境 | 沙箱環境準備與漏洞實證；macOS／Windows 可使用 Docker Desktop |
| 供應商、API 金鑰與模型設定 | AI 審查與自動 Prover |
| `semgrep` 命令 | 選用，用於規則掃描；未設定 AI Reviewer 時，需有適用且可執行的 detector |
| Go 工具鏈與 Git | 僅從原始碼建置時需要；發布流程使用 Go 1.26，`go.mod` 宣告 `go 1.24.2` |

已設定 Reviewer 時，即使 Semgrep 不存在或執行失敗，仍可降級為 AI 審查。只執行靜態 `scan` 不需要 Docker；完整沙箱驗證則需要。

### macOS／Linux

```sh
curl -fsSL https://raw.githubusercontent.com/denny200897/SITCON-hacker-zone/main/scripts/install.sh | sh
```

安裝器依 OS／CPU 從 GitHub Releases 下載執行檔，優先安裝至可寫入的 `/usr/local/bin`，否則使用 `~/.local/bin`。安裝目錄已在 `PATH` 時，可直接在任意目錄執行 `aegis`，不需要切回 Aegis 原始碼目錄。

Shell 安裝器不會自動修改 shell 設定檔；若安裝目錄不在 `PATH`，會顯示加入提示。例如安裝至 `~/.local/bin` 時，在目前終端執行：

```sh
export PATH="$HOME/.local/bin:$PATH"
```

若要讓後續終端也能找到 `aegis`，將這行加入 shell 設定檔（例如 zsh 的 `~/.zshrc` 或 Bash 的 `~/.bashrc`；登入 shell 請使用對應的登入設定檔）。自訂 `AEGIS_INSTALL_DIR` 時，請改成實際安裝目錄。

### Windows（PowerShell）

```powershell
irm https://raw.githubusercontent.com/denny200897/SITCON-hacker-zone/main/scripts/install.ps1 | iex
```

預設安裝至 `%LOCALAPPDATA%\Aegis\bin`，並加入使用者的 `PATH`。必要時重新開啟終端。

### 確認全域指令可用

安裝並完成 `PATH` 設定後，在任意目錄執行：

```sh
aegis --help
```

後續使用方式皆以全域 `aegis` 指令為例；審查目前目錄可執行 `aegis review --target . --watch`，也可用 `--target` 指向其他本機儲存庫。

### 手動安裝與指定版本

也可以從 [Releases](https://github.com/denny200897/SITCON-hacker-zone/releases) 下載對應檔案。macOS／Linux 檔名為 `aegis-<os>-<arch>`，Windows 為 `aegis-windows-<arch>.exe`；將檔案重新命名為 `aegis` 或 `aegis.exe`，放入 `PATH` 中的目錄，並在 macOS／Linux 設定可執行權限。

兩種安裝器皆支援以下環境變數：

| 變數 | 用途 |
| --- | --- |
| `AEGIS_VERSION` | 指定已發布的 tag；未設定時下載最新 release |
| `AEGIS_INSTALL_DIR` | 指定安裝目錄 |
| `AEGIS_REPO` | 指定下載來源，預設為 `denny200897/SITCON-hacker-zone` |

安裝命令會下載並執行遠端腳本；如需先檢查內容，可查看 [Shell 安裝器](scripts/install.sh) 或 [PowerShell 安裝器](scripts/install.ps1)。若尚無對應 release 資產，請改用原始碼建置。

### 從原始碼建置

使用與發布流程一致的 Go 1.26 工具鏈：

```sh
git clone https://github.com/denny200897/SITCON-hacker-zone.git
cd SITCON-hacker-zone
go build -o ./bin/aegis ./cmd/aegis
./bin/aegis --help
```

Windows 可使用 `go build -o ./bin/aegis.exe ./cmd/aegis`。後續範例假設 `aegis` 已在 `PATH`；若尚未安裝，請改成建置出的執行檔路徑。

Schemas 與內建 `python-web` pack 已嵌入執行檔，可從任意工作目錄啟動。發布建置採 `CGO_ENABLED=0`。

## 快速開始

先在想審查的本機儲存庫啟動：

```sh
cd /path/to/your-repository
aegis
```

真實終端會開啟 TUI，可用 `↑`／`↓` 和 `Enter` 選取操作，也能直接輸入指令。預設語言為英文，輸入 `/lang zh` 可切換繁體中文。

以下以名為 `anthropic` 的供應商為例，依序操作：

1. 輸入 `/provider add anthropic`，在詢問類型時選擇 `anthropic`。
2. 輸入 `/key set anthropic`，在隱藏輸入提示中貼上 API 金鑰。
3. 輸入 `/model set all anthropic/<model-id>`，將 `<model-id>` 換成帳戶可使用的實際模型 ID。
4. 輸入 `/status` 與 `/doctor`，查看模型、憑證及 Docker 等環境狀態。
5. 輸入 `/review --target . --watch`，開始完整審查。

首次需要準備 proof image 時，互動終端會顯示建置與網路政策，等待核准。完成後，畫面會列出 run 目錄與報告路徑。輸入 `exit` 離開。

設定完成後，也可直接在 shell 執行：

```sh
aegis review --target /path/to/your-repository --watch
```

## 設定供應商與模型

### 供應商

在互動介面使用 `/provider add <name>` 建立自訂名稱，再選擇類型：

| 類型 | 設定方式 |
| --- | --- |
| `anthropic` | 使用 Anthropic adapter |
| `openai-compat` | 輸入相容 API 的 `base_url`；端點與模型需支援工具呼叫 |
| `openrouter` | 互動捷徑，預設端點為 `https://openrouter.ai/api/v1`，儲存為 `openai-compat` |

模型引用格式為 `<provider-name>/<model-id>`。OpenRouter 等服務的模型 ID 本身可以包含 `/`。可用 `/provider list`、`/model list` 檢查設定。

### 五種角色

| 角色 | 工作 |
| --- | --- |
| `recon` | 初步盤點與審查規劃 |
| `reviewer` | 探索程式碼、提出帶定位證據的候選 |
| `triager` | 整理候選並進行分流 |
| `prover` | 使用工具迴圈產生及調整驗證規格 |
| `reporter` | 根據結果撰寫 Markdown 報告 |

`/model set all <provider>/<model-id>` 可一次設定所有角色；之後可用 `/model set reviewer <provider>/<model-id>` 等命令個別覆寫。未設定 Reporter 時，報告使用確定性模板。

### 專案設定檔

使用者設定預設儲存在 `~/.config/aegis/settings.toml`。目標儲存庫根目錄的 `aegis.toml` 可覆寫對應設定，適合團隊或 CI 固定模型路由與預算。以下的 `YOUR_MODEL_ID` 必須替換成實際模型 ID：

```toml
[providers.anthropic]
type = "anthropic"

[models]
recon = "anthropic/YOUR_MODEL_ID"
reviewer = "anthropic/YOUR_MODEL_ID"
triager = "anthropic/YOUR_MODEL_ID"
prover = "anthropic/YOUR_MODEL_ID"
reporter = "anthropic/YOUR_MODEL_ID"

[budget]
max_env_fixes_per_finding = 5
max_harness_fixes_per_finding = 8
max_hypotheses_per_finding = 3
max_sandbox_minutes_per_finding = 10
```

上述預算值也是預設值，分別限制每個 finding 的環境修復、驗證程式修復、假設嘗試次數與沙箱時間；它們不是整次審查的 API 費用上限。

### API 金鑰

金鑰依下列優先序解析：

1. `AEGIS_<供應商名稱大寫>_API_KEY` 環境變數，名稱中的非英數字元轉為 `_`。
2. 作業系統 keychain。
3. `~/.config/aegis/credentials.toml` 退回檔案。

例如，名為 `anthropic` 的供應商使用 `AEGIS_ANTHROPIC_API_KEY`，名為 `my-router` 的供應商使用 `AEGIS_MY_ROUTER_API_KEY`。CI 請透過平台的 secret 設定注入環境變數。

`/key set` 優先寫入系統 keychain；不可用時會退回檔案。退回檔案是明文 TOML，程式設定其權限為 `0600`，並非加密儲存。請勿將金鑰放入 `aegis.toml`、`settings.toml` 或提交至 Git。

## 使用方法

### 完整審查

```sh
aegis review --target /path/to/repo --watch
```

流程依序為：

```text
SCAN → ENVIRONMENT → PROVE → REPLAY → REPORT
快照與審查 → 環境檢查 → 沙箱實證 → 證據重驗 → 輸出報告
```

`--watch` 顯示審查進度、模型公開說明、工具活動及完成／失敗狀態，不展示模型隱藏的推理過程。TUI 執行審查時會自動開啟活動串流。

| 選項 | 用途 |
| --- | --- |
| `--target <path>` | 指定本機儲存庫，預設為目前目錄 |
| `--target-subdir <path>` | 將審查範圍限縮至目標內的子目錄 |
| `--watch` | 顯示即時活動 |
| `--run-dir <path>` | 為 `review` 指定新的輸出目錄；分階段命令可指向既有 run |
| `--hypotheses <N>` | 覆寫每個 finding 的假設嘗試上限 |
| `--approve-build` | 預先核准本次需要的 proof image 建置，適用於 CI |
| `--pack <path>` | 指定 pack 目錄，預設使用內建 `python-web` |

例如只審查 monorepo 的 API 子目錄：

```sh
aegis review --target /path/to/monorepo --target-subdir services/api --watch
```

### 分階段執行與接續處理

```sh
aegis scan --target /path/to/repo
aegis prove --target /path/to/repo --watch
aegis replay --target /path/to/repo
aegis report --target /path/to/repo
```

`scan` 建立新的 run；後續命令預設使用最新 run。需要處理特定結果時，使用 `--run-dir` 明確指定。以下請將 finding ID 與 `RUN_DIRECTORY` 替換成實際值：

```sh
aegis prove F-0001 --target /path/to/repo --run-dir /path/to/RUN_DIRECTORY --watch
```

省略 finding ID 時，`prove` 會處理該 run 的全部 findings。進階使用者可透過 `--spec witness.json` 提供人工 WitnessSpec，此時必須指定單一 finding，且不呼叫 LLM Prover。

### CI／非互動環境

先安裝 CLI、準備可用的 Docker daemon，在目標 repo 放入已填好模型 ID 的 `aegis.toml`，並透過 CI secrets 注入 API 金鑰，再執行：

```sh
aegis review --target . --approve-build --run-dir ./out/ci-review
```

每次執行請使用新的 run 目錄。非 TTY 環境預設拒絕尚未核准的映像建置，因此需要建置時必須明確傳入 `--approve-build`。可將 run 目錄保留為 CI artifact；SARIF 檔案的上傳需由 CI 另行設定。

若驗證失敗，`review` 仍會嘗試輸出報告，並以非零退出碼標示流程未完整完成。成功退出表示流程完成，不表示儲存庫沒有漏洞；若要依嚴重程度或驗證狀態阻擋合併，需另行解析報告設定政策。

互動介面的 `/review`、`/scan`、`/prove`、`/replay`、`/report` 接受同名 CLI 的參數。其他選項可用 `aegis --help` 或 `aegis <command> --help` 查看。

## 報告與證據

預設產物位於目標儲存庫的 `out/run-<timestamp>/`；使用 `--target-subdir` 時，預設位於該子目錄的 `out/`。實際路徑會在終端列出。

| 產物 | 內容 |
| --- | --- |
| `report.md` | 供人工閱讀的安全審查報告 |
| `findings.json` | 結構化 findings、定位與驗證狀態 |
| `findings.sarif` | SARIF 格式結果 |
| `inventory.json`、`candidates.json`、`triage.json` | 程式碼盤點、候選與分流資料 |
| `coverage.json` | Detector、runtime 與 oracle 的覆蓋範圍 |
| `environment.json` | 有執行環境檢查時的結果 |
| `evidence/` | 有執行實證時產生的證據 bundle |
| `audit.jsonl` | 工具呼叫與政策閘決策 |
| `ai-events.jsonl` | AI 請求、回覆與用量等事件紀錄 |
| `journal.sqlite` | 流程狀態轉移紀錄 |

`replay` 會離線重驗既有 evidence bundle，不需要再次向模型詢問，也不等於重新執行整個應用。沒有候選或缺少實證支援時，對應階段與產物可能略過，報告會保留相關資訊。

## 資料與安全邊界

Aegis 在本機編排流程，但 AI 模式會將審查所需的程式碼與上下文傳送到你設定的模型供應商。請依專案的資料政策選擇端點；本機執行不等於程式碼完全不離開本機。

程式對敏感路徑及已知秘密樣式設有排除、檢查與遮蔽措施，模型操作亦受工具及政策限制。沙箱使用受限制的容器執行，供應商 API 金鑰不注入沙箱。完整邊界與設計理由見 [威脅模型](docs/threat-model.md) 及 [架構決策](docs/adr/)。

Run 產物可能包含原始碼片段、模型請求與敏感弱點資訊，請按原始碼同等機密程度保存。`audit.jsonl` 與 `ai-events.jsonl` 以 `0600` 權限建立；對外分享前仍應檢查內容。快照、內建資產及映像記錄預設使用系統的使用者 cache，可用絕對路徑 `AEGIS_CACHE_DIR` 覆寫。

## 疑難排解

| 問題 | 處理方式 |
| --- | --- |
| `aegis: command not found` | 確認安裝目錄已加入 `PATH`，並重新開啟終端；原始碼建置請使用執行檔路徑 |
| 安裝器下載失敗 | 檢查 Release 是否包含對應 OS／CPU 資產、指定 tag 是否存在；亦可從原始碼建置 |
| 缺少模型或金鑰 | 在互動介面執行 `/provider list`、`/model list`、`/status`；確認模型引用前綴與供應商名稱一致 |
| 模型設定似乎沒生效 | 檢查目標 repo 的 `aegis.toml` 是否覆寫使用者設定 |
| Docker 無法使用 | 啟動 Docker daemon，確認 `docker info` 可執行，再於 Aegis 中執行 `/doctor` |
| CI 拒絕準備 proof image | 確認可接受建置後，傳入 `--approve-build` |
| Semgrep 缺少或失敗 | 確認命令在 `PATH`；已設定 Reviewer 時可使用降級的 AI 審查 |
| `no matching trusted oracle` | Finding 缺少內建實證支援；查看 `coverage.json`，它仍會保留在報告中 |
| 報告存在但流程回報失敗 | 查看終端失敗階段、`environment.json` 與 run 紀錄；報告產生不表示實證成功 |

## 開發與貢獻

歡迎提交可重現的 bug、文件改善、測試，以及 runtime／oracle 支援。較大變更可先透過 [Issue](https://github.com/denny200897/SITCON-hacker-zone/issues) 說明使用情境與預期行為。

### 專案結構

```text
cmd/aegis/                 CLI 入口與角色提示
cmd/aegis-observer-proxy/  可信觀察代理
internal/                 Agent、設定、政策、沙箱、證據與報告實作
packs/python-web/         內建 detector、驗證模板與 oracle
schemas/                  設定及產物的 JSON Schema
tests/                    端到端與對抗測試
fixtures/                 測試用目標程式
scripts/                  跨平台安裝器
docs/                     使用文件、威脅模型與架構決策
SPEC.md                   設計規格
```

### 本機檢查

```sh
go build -o ./bin/aegis ./cmd/aegis
go test ./...
go vet ./...
```

部分端到端測試需要 Docker 與相符的 pack 映像；條件不足時會跳過。檢查容器測試時可使用 `go test -v ./tests/e2e` 查看實際執行／跳過情況。不要將跳過的測試視為完整沙箱驗證通過。

提交 Pull Request 時，請描述問題、變更後的行為及測試結果。修改 Go 程式碼後執行 `gofmt`；變更 pack、schema 或信任邊界時，請同步檢查相關 digest、測試與文件。不要提交 API 金鑰、私人程式碼或未整理的審查產物。

延伸閱讀：[完整使用方式](docs/USAGE.md)、[設計規格](SPEC.md)、[威脅模型](docs/threat-model.md)、[架構決策紀錄](docs/adr/)。設計文件包含階段性規劃，實際支援範圍請以目前程式碼與本 README 的能力說明為準。

## 授權

本專案採用 [MIT License](LICENSE)。
