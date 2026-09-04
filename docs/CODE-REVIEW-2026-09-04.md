# Aegis spec compliance 與程式碼審查（2026-09-04）

## 結論

目前專案**不能判定為已按照完整 `SPEC.md` 完成**，也不應把現有 `PROVEN` 當成可信的安全結論。最重要的原因不是測試數量，而是仍有一條可偽造 trusted oracle 的路徑，以及 CLI 實際流程沒有接上已存在的 agent、設定與多階段元件。

本次判定：

| 範圍 | 判定 | 摘要 |
| --- | --- | --- |
| M0a Trust Kernel | 未通過 | SQL observer 接收 witness 可直接偽造的請求；evidence 內容亦有不實／不完整欄位。 |
| M0b SQLi E2E | 未通過 | 誠實 fixture 可跑不代表敵對 witness 不可偽造；replay 未先驗 evidence chain，亦沒有可驗證的 bundle root hash。 |
| M0c Agent 整合 | 未通過 | `AgentProver` 只存在於 library／測試，正式 `aegis prove` 完全沒有使用；refusal 與 accepted-spec 狀態機也未完整接線。 |
| M0d 產品外殼 | 未通過 | 無參數不會進 console；`/doctor` 正式注入為空設定；`--watch`、`--hypotheses` 沒有效果。 |
| M1 | 部分骨架 | 只有單一 SQLi semgrep 路徑、簡化 triage 與報告；沒有 LLM reviewer、merge/dedup、完整 Injection pack 與實際多假設 CLI 流程。 |
| M2 | 大多未完成 | 只有 SARIF 與部分 internal network 基礎；沒有 SSRF/XSS oracle、tripwire generator、`--ci`。 |
| M3 | 未完成 | 沒有 access-control pack、第二語言 pack、50 fixtures benchmark／eval。 |

## 審查方式與限制

- 審查版本：Git `599238bb55de07faa82406b4a3ba04396faaddc9`，開始時工作樹乾淨。
- 已逐段比對 `SPEC.md`，並追查 CLI → snapshot／inventory → candidates／triage → prover／sandbox／observer → evidence／replay → report 的資料流。
- 所有 JSON 檔均可被 PowerShell JSON parser 解析：PASS。
- `git diff --check`（建立本文件前）：PASS。
- **本環境沒有 `go`、`docker`、`semgrep` 可執行檔**，所以本次無法執行 `go test ./...`、`go vet ./...` 或 Docker E2E。`docs/acceptance-m0a-m0c.md` 記載的是其他環境的歷史結果，不是本次驗證結果。

## 發現清單

### P0-01 — 未驗證的 observer socket 仍允許偽造 `PROVEN`

**影響：產品最核心的 trusted-oracle 保證可被敵對 witness 繞過。**

目前修補把 SQL trace 檔移到 sidecar 擁有的 volume，但沒有驗證「請求確實來自目標程式碼的 sqlite 呼叫」。policy 只要 template 有 `ObserverImage`，就把 run 切到 internal network 並把 `observer:8787` 交給 witness（`internal/orchestrator/policy/policy.go:410-414`）；該位址再以 `AEGIS_OBSERVER_ADDR` 明文注入證明容器（`internal/orchestrator/orchestrator.go:324-338`）。Python shim 也讓不受信任的 witness process 使用此位址（`packs/python-web/sandbox/sitecustomize.py:110-150`）。observer server 對任何能連線者接受 `{op:"execute", sql, params}`，沒有 per-run secret、peer identity 或來源證明，並把所收 SQL 直接記為 trusted trace（`internal/observerproxy/proxy.go:97-151`）。

因此，模型控制的 `generated_files` 可完全不 import／呼叫 `target_symbol`，直接連 observer：negative 傳合法且含 nonce 的 SQL、positive 同樣命中 touch、exploit 傳含 nonce 的錯誤 SQL，即可滿足三控制 run。AST gate 只證明 symbol 在 repo 中存在，不證明本次 trace 是該 symbol 產生。

**修補要求：** observer protocol 必須讓任意 witness 程式無法自行產生可信事件；同時建立「target symbol 從未被呼叫，但 witness 直接打 observer」的真 Docker adversarial test，結果必須不是 `PROVEN`。只保護 trace volume 或只測 stdout 偽造都不足。

### P0-02 — `scan` 綁定的 snapshot 與實際分析內容不是同一份

**影響：finding 可被錯誤地宣稱來自某個 content-addressed snapshot，破壞重現性與 evidence provenance。**

`aegis scan` 先對 live `root` 執行 `inventory.Build`，之後才建立 snapshot（`cmd/aegis/main.go:102-110`）；semgrep 隨後仍掃 live `root`，不是 `snap.Dir`（`cmd/aegis/main.go:142-149`）。使用者或其他程序只要在這段期間修改檔案，inventory、candidate 與 snapshot 就可分別對應不同內容，但輸出仍統一寫入 `snap.ID`。

**修補要求：** 第一個檔案系統動作應是 snapshot；Stage 0–4 一律只讀 `snap.Dir`。新增一個在 snapshot 後修改來源 worktree 的整合測試，確認 candidate／line／hash 仍完全來自 snapshot。

### P0-03 — 正式 CLI 沒有接上 spec 所述的 agent pipeline

**影響：使用者無法透過產品入口取得 spec 所描述的行為；library 測試通過不等於產品完成。**

- `scan` 只執行 manifest 的**第一條** detector（`cmd/aegis/main.go:142-149`），沒有 recon、LLM reviewer、所有 detector 聚合或 ±5 行 merge/dedup。
- `prove` 強制要求人工提供 `--spec`（`cmd/aegis/main.go:286-300`），沒有讀 provider／key／prover model，也完全沒有建構 `AgentProver`。
- `prove` 不載入既有 run 的 finding，預設自造 `F-0001`，並把 reachability 固定為 `D2`（`cmd/aegis/main.go:328-335`）。
- `report` 只讀 `findings.json`；proof 結果沒有回寫 finding 的 verification／evidence ID。

這直接違反 `SPEC.md` §4、§8 與 §12 M1 所述的整體流程。

**修補要求：** 建立真正的 run coordinator，讓 `scan` 的 journal／findings 成為 `prove [F-ID]` 的唯一輸入來源，接上設定解析、credential manager、adapter、tool schema、audit、`AgentProver`，並將終態原子回寫 journal／findings。

### P1-01 — triage／ACD 演算法與 rubric 相反，會產生大量錯判

`triage.Evaluate` 只做「入口是否與 sink 在同一檔案」的比對：同檔 HTTP route 判 `D2`、其他同檔入口判 `D1`；不同檔則直接 `FALSE_POSITIVE`／`UNKNOWN`（`internal/triage/triage.go:22-51`）。它沒有判斷輸入是否流入 sink、預設／非預設配置、exported function 或缺少幾層 wiring，也從不產生 D0/D3。

這與 `SPEC.md` §20.1 不符，而且同檔 route 實際可直達時應可能是 D0，不應固定 D2。scan 又忽略 triage 的 `Verdict`，仍建立 disposition=`OPEN` 的 finding（`cmd/aegis/main.go:168-191`），造成狀態互相矛盾。

**修補要求：** 依 §20.1 四問 rubric 產結構化 verdict；沒有 `file:line` 證據時只能降 UNKNOWN，不能自行標 FALSE_POSITIVE。新增跨檔呼叫鏈、同檔不相關 route、D0/D1/D2/D3 各一 fixture。

### P1-02 — severity、confidence 與 missing_links 是硬編碼假資料

scan 對所有 finding 固定寫 `severity: high`、`confidence: 0.5`，沒有讀 pack 的 impact 或 §20.2/§20.3 公式；missing links 也丟棄 triage 的實際結構，改寫成固定字串（`cmd/aegis/main.go:175-183`）。

**修補要求：** 由 pack `sink_types[].impact` + ACD 矩陣計 severity；依 verification／mode／assumptions／payload variants 計 confidence，並保留逐環節 `file:line` 證據。新增 table-driven tests 照抄 spec 矩陣。

### P1-03 — `/doctor` 的正式 CLI 接線實際只檢查 Docker 與 semgrep

console 注入的是 `doctor.Run(ctx, doctor.Options{})`（`cmd/aegis/main.go:50-65`）。零值 Options 沒有 `PackDirs`、`CachePath`、`Providers`、`ResolveKey`，所以 `/doctor` 不會檢查／構建 pack image、不會記錄 digest，也不會測 provider 連通，與 M0d 驗收勾選內容不符。

另外，若 images cache 有紀錄但本機 image 已不存在，doctor 仍直接標 OK 且不重建（`internal/doctor/doctor.go:268-280`）。fresh install 的本地 build 又要求 `RepoDigests` 非空；常見的未 push 本地 image 會沒有 repo digest，程式自己也承認這條路會失敗（`internal/doctor/doctor.go:320-348`）。

**修補要求：** CLI 需載入 repo/user providers、credential resolver、pack dirs 與標準 cache path；cache 命中必須再以 Docker inspect 驗證本機存在。新增從空 cache／空 image store 開始的 CLI 級測試。

### P1-04 — evidence 寫出的內容不等於實際 run

`executeRun` 收回 artifacts 後，把 `run_result.stdout`、`stderr` 固定寫空字串，`fs_diff.added/modified` 固定寫空陣列，並把 `oracle.nonce_observed` 無條件寫成 `true`（`internal/orchestrator/prove.go:360-393`）。artifact 目錄或單檔讀取失敗也會被靜默忽略（同檔 360-372）。

這雖可能通過目前寬鬆 schema，卻違反 §5.3、§7.1、G5 的「完整且有界輸出／fs-diff／hash」語意，也會讓 evidence 對不存在的觀測作肯定陳述。

**修補要求：** 真實收集 stdout/stderr、truncation flag + full-stream hash、解析真實 fs_diff，`nonce_observed` 由 checker 結果導出。任何 artifact/hash 讀取失敗必須 fail closed 並落 ENV_ERROR evidence。

### P1-05 — replay 沒有驗 evidence chain，bundle 也沒有可驗證的 root

`ReplayBundle` 直接載入 EV 檔與 artifact hash，沒有呼叫 `evidence.VerifyChain`（`internal/orchestrator/replay.go:23-63`）。即使另行呼叫 `VerifyChain`，最後一筆 EV 的內容被改寫後仍可重算成新的尾 hash，因為 bundle 中沒有 manifest 記錄預期 root／tail hash。攻擊者可同步修改最後一筆 evidence 的 oracle 結果與 artifact hashes，replay 只會對被修改後的自洽資料重算。

**修補要求：** bundle manifest 必須列出 EV 順序、每筆 hash 與最終 root，replay 入口先驗 manifest／chain 再驗 artifacts／oracle。新增「改最後一筆 EV」、「刪中間 EV」、「新增偽造 EV」、「修改 artifact 並同步改 EV hash」測試。

### P1-06 — audit 與關鍵 journal 寫入失敗仍 fail-open

`AuditLog.Append` 吞掉 marshal 與 write error，註解甚至明示「不影響工具執行」（`internal/agent/audit.go:77-92`）。`ToolRegistry.Execute` 因此無法知道 audit 是否成功，工具仍會執行。`AgentProver` 的 `verification_updated` 與 `witness_spec_rejected` journal append 也忽略錯誤（`internal/orchestrator/agent_prover.go:348-371,403-408`）。

這違反 §18.1 的「每個 tool call 前政策檢查並記 audit」及 §4 的持久狀態保證。

**修補要求：** Append 回傳 error；安全閘要求 audit 成功後才執行工具。終態 journal 寫入失敗必須讓 Run 回錯，不能回傳看似成功的終態。加入關閉檔案／唯讀目錄／disk-full fault injection 測試。

### P1-07 — 落盤前 secret gate 沒有覆蓋 CLI 與報告路徑

spec 要求所有送 LLM 與所有落盤輸出共用 secret 掃描。現在 scan 將 inventory、semgrep `matched_text`、triage、finding 直接 `os.WriteFile`（`cmd/aegis/main.go:132-219`），reporting 也直接寫 findings／SARIF／Markdown（`internal/reporting/report.go:21-45,48-90,144-178`），沒有 redaction gate。前一個 run 的 `out/` 也不在 `DefaultExcludes`（`internal/inventory/inventory.go:15-23`），重掃 repo 時可能把舊 evidence／audit 再納入 inventory 或候選。

`search_code` 遇到 secret match 時只 `SkipAll`，最後回傳已收集的普通結果，沒有告知呼叫端「因 secret 停止並等待確認」（`internal/agent/tools.go:212-256`）。

**修補要求：** 建立唯一的 write/redaction boundary，所有 JSON、journal payload、audit、report、evidence 走同一路徑；預設排除 Aegis 自己的 `out/`；secret 命中必須回明確的需人工確認狀態，不能靜默截斷。

### P1-08 — report 宣稱 guardrails 存在，但從未生成

程式只產 `findings.json`、SARIF、report.md；沒有 tripwire generator、`semgrep --validate`、原 sink 正向 match 或 CI snippet 實作。報告仍固定列出 `guardrails/` 和 `evidence/`（`internal/reporting/report.go:171-172`），即使目錄不存在；PROVEN finding 也沒有 §4 要求的一鍵重現命令。

**修補要求：** 實作 §2.4／§16 tripwire 驗證後再列入報告；不存在的產物不得宣稱已產生。加入 report artifact manifest 測試。

### P1-09 — build／dependency pipeline 完全未落地

程式內沒有 `pip-compile --generate-hashes`、`pip download --require-hashes`、wheel volume、derived offline image 或 `deps_lock_hash` 的實作。`doctor` 只 build pack 自身 Dockerfile；proof 直接使用 pack image。這與 §17.4 的五步協定不符，對有額外依賴的真實 Python repo 無法可重現地 prove。

**修補要求：** 實作獨立 deps helper、hash-pinned lock/wheel download、`docker build --network none` derived image，並把 lock、wheels manifest、derived digest 綁入 evidence。

### P1-10 — Python-web pack 只真正支援單一 SQLi 形狀

manifest 只有一條 SQL concat detector、兩個 SQL template、兩個 SQL oracle；`cmd.shell`、deserialization、SSRF 只出現在 `sink_types` 名單，沒有對應 detector/template/payload/oracle。SSTI、path traversal、XSS、access control 甚至沒有完整宣告（`packs/python-web/manifest.json:10-120`）。

因此「完整 v1 四類漏洞」與 M1–M3 尚未完成；單純列 sink impact 不算支援該漏洞家族。

### P2-01 — `--watch`、`--hypotheses` 沒有效果，無參數也不進 console

root command 沒有 `RunE`，所以 `aegis` 無參數只顯示 Cobra help，不會進互動模式（`cmd/aegis/main.go:44-47`）。`--watch` 與 `--hypotheses` 雖被解析，最後只用 `_ = watch`／`_ = hypotheses` 消除未使用警告（`cmd/aegis/main.go:80-96,341-344`）。

這直接違反 §8 與 §9.3 的使用者介面。

### P2-02 — accepted WitnessSpec 沒有在 production prover 立即終止 session

`agent.Runtime` 已提供 `StopOnAccepted`，但 `AgentProver` 建構 Runtime 時沒有設為 true（`internal/orchestrator/agent_prover.go:153-155`）。模型提交已核可 spec 後仍可能繼續多輪；若最後耗盡 MaxTurns，Run 先回 error，先前接受的 spec 也不會被執行。

**修補要求：** production prover 明確設 `StopOnAccepted: true`，並加「accepted 後 adapter 繼續 tool_use 直到 MaxTurns」的回歸測試。

### P2-03 — Anthropic refusal 處理鏈未按 spec 實作

adapter 能辨識 `StopRefusal`，但 orchestrator 只把 refusal／max_tokens 計為 env，追加一般錯誤訊息後重試（`internal/orchestrator/agent_prover.go:175-190`）。程式沒有「解敏一次 → server-side fallback beta → ENV_ERROR」的明確狀態機，也沒有任何 fallback API 呼叫。

**修補要求：** 把 refusal policy 放在 AgentRuntime／orchestrator，精確限制一次解敏與一次 fallback，保存每步 provider metadata；openai-compat 採 spec 的顯式降級但不得混同 Anthropic 流程。

### P2-04 — direct mode 沒有依 inventory 啟動真實服務

pack 的 direct template 把 service command 固定成 `python /target/app.py`（`packs/python-web/manifest.json:33-46`），而 §17.8 要求從 inventory 取得 repo 自身入口與啟動方式，無法啟動時回 `direct_mode_unbootable`。正式 CLI 又把所有 prove 固定當 D2，因此 D0/D1 直攻模式實際不可用。

### P2-05 — crash recovery／run resume 尚未實作

雖有 SQLite journal，但 CLI 每次 scan/prove 都自行建立或選擇目錄，沒有從 journal 回放未完成 stage、沒有 checkpoint 狀態機，也沒有啟動時掃描／清理孤兒 run。run 目錄以秒為粒度；同秒兩次執行可能重用同一路徑並覆寫非 append-only 產物（`cmd/aegis/main.go:115-121,309-320`）。`latestRunDir` 只靠目錄名稱字典序（同檔 376-387）。

### P2-06 — 程式碼中保留多個已自行採用的 `ASK` 決策

`SPEC.md` §23.9 要求遇到未覆蓋決策點停止並回報，不能自行選擇。現在程式註解中有多處「ASK」但同時已採用其中一案，例如 openai-compat streaming 降級（`internal/llm/openai_compat.go:15-18`）、doctor build context／cache key／probe model（`internal/doctor/doctor.go:303-418,533-573`）、settings model ref 規則（`internal/settings/settings.go:153-176`）。這些應由人類決策後更新 spec/ADR 並移除 ASK，而不是把未決選項留在 production semantics。

## 建議修補順序

1. 先封鎖 P0-01；在 adversarial test 能重現假 `PROVEN` 前，不接受任何 oracle 修補完成宣稱。
2. 修正 snapshot-first 與正式 CLI coordinator，讓後續測試驗的是實際產品入口而非孤立 library。
3. 修正 evidence 真實性、bundle root／replay、audit/journal fail-closed。
4. 接好 `/doctor`、provider/model/credential 與 AgentProver；讓 `--watch`／budgets 真正生效。
5. 依序完成 deterministic triage/scoring、dependency pipeline、direct mode、report/tripwires。
6. 最後再擴完整 Injection、SSRF、XSS、access-control packs 與 eval corpus。

## 修補後最低驗收測試

- `go test -count=1 ./...`
- `go test -race -count=1 ./...`
- `go vet ./...`
- 乾淨 machine／空 image cache 下執行 `/doctor`，確認 build、digest 記錄、provider probe 都真的發生。
- 從 CLI 執行完整 `scan → prove → report`，不得使用測試專用 adapter 或人工 `--spec`。
- 在 scan 建 snapshot 後修改 worktree，確認所有後續結果仍綁原 snapshot。
- 惡意 witness 直接連 observer、偽造 trace、完全不呼叫 target symbol，必須無法 `PROVEN`。
- 複製 bundle 到另一目錄後離線 replay 兩次；任意修改 EV（含最後一筆）或 artifact 都必須失敗。
- audit／journal／artifact write fault injection 必須 fail closed。
- secrets 出現在 source、semgrep matched text、provider error、report fix suggestion、artifact 各路徑時，預設均不得送出或落盤。

## Spec 本身需要人類確認的矛盾

這些不應由修補 AI 自行猜測：

1. §7.2 說 operator feedback 用 mid-conversation system message，但 §18.3 又固定為 user message 內 `<operator>`；目前程式採後者。建議以後出的 §18.3 為準並同步刪除 §7.2 舊句。
2. §17.3 原文讓 SQL shim 寫 `/aegis/out/sql_trace.jsonl`，與 trusted artifact 不得被 witness 寫入的安全需求衝突。ADR 0004 改成 sidecar，但沒有解決請求來源偽造，也沒有回寫 spec。
3. §23 尾端第 6–9 點在 `SPEC.md:1031-1034` 重複一次，應清理以免機器解析 checklist 時重複。
