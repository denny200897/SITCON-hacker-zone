# M0a～M0c 驗收紀錄

- 驗收日期：2026-09-04（Asia/Taipei）
- 驗收基準：`SPEC.md` §22
- 驗收版本：Git `137971a` 加目前未提交工作樹
- Go：`go1.26.2 darwin/arm64`
- Docker：client `29.5.2`、server `29.4.3`

## 結論

| 里程碑 | 判定 | 摘要 |
| --- | --- | --- |
| M0a | **未通過** | 除原驗收證據缺口外，詳細 code review 發現模型生成的 witness 可偽造 trusted oracle artifact，evidence 亦未符合 schema。 |
| M0b | **未通過** | E2E 測試雖通過，但 evidence 未綁定 artifacts；replay 依賴可變的外部目錄與記憶體結果，不是自包含 bundle replay。 |
| M0c | **未通過** | E2E 測試雖通過，但 secrets 防洩、強制 gate、AgentRuntime 狀態機、AST 驗證及 provider protocol 均有阻斷性缺陷。 |

因此 M0a～M0c 的整體 gate 判定為 **未通過**。目前不得連接真實外部 LLM，也不得把產出的 `PROVEN` 視為可信安全結論。`SPEC.md` §22 規定逐項打勾才准進下一個里程碑；本次通過結果另包含未提交檔案，不能視為 Git `HEAD` 單獨可重現的結果。

> 重要：測試全部通過只代表既有案例成功。後續詳細 code review 發現測試沒有覆蓋惡意 witness、證據自包含性、呼叫端漏接安全閘及 secrets 外洩等信任邊界。本文件後半的 code review 結論優先於單純測試結果。

## 執行結果

以可直接連線本機 Docker daemon 的環境執行：

```text
go test -v ./... -count=1
PASS
ok github.com/aegis-dev/aegis/tests/e2e 16.772s
```

Docker 測試沒有 skip；下列整合測試均實際建立並執行容器：

- `TestSandboxHardeningInspect`
- `TestSandboxStartTimeout`
- `TestSandboxCopyInAndRun`
- `TestSandboxDiffIgnoresMounts`
- `TestSandboxReclaim`
- `TestSandboxStageWitness`
- `TestSandboxReaper`
- `TestM0bSqliProvenE2E`
- `TestM0bStdoutNonceNotEvidence`
- `TestM0bControlledMissRejectsHypothesis`
- `TestM0cProverLoopProvenE2E`
- `TestM0cProverLoopGateRejectionThenProvenE2E`

靜態檢查：

```text
go vet ./...
PASS

git diff --check
PASS
```

## M0a — Trust Kernel（零 LLM）

### 1. 手寫 WitnessSpec 固定 fixture 全管線

**通過。** `TestM0bSqliProvenE2E` 是此條件的超集合：手寫 WitnessSpec 經 policy compiler、真 Docker sandbox、checker、evidence 落檔，最後得到 `PROVEN`。流程使用決定性 harness，沒有 LLM 呼叫。

### 2. Hardening flags 與 Docker inspect

**通過。** 純函式測試逐項鎖定 canonical flags；`TestSandboxHardeningInspect` 亦在真 Docker 上通過，驗證至少包含：

- `cap_drop=ALL`
- read-only rootfs
- `no-new-privileges:true`
- seccomp 接線
- user `65532:65532`
- memory、CPU、PIDs、nofile 限制
- `/tmp`、`/run` tmpfs
- network none
- 唯讀 target mount

### 3. Adversarial tests

**未通過。** 已有並通過：

- 可變 tag／非法 digest 格式拒收：`TestDockerArgsRejectsMutableTag`、`TestRejectMutableTag`、`TestCheckDigest`
- `..` 路徑拒收：`TestDockerArgsRejectsBadInput`、`TestRejectBadGeneratedFiles`
- 絕對路徑 generated_files 拒收：`TestRejectBadGeneratedFiles`
- generated_files 總量超過 256 KiB 拒收：`TestRejectOversizeFiles`

缺口：沒有測試以「格式合法、但與本機實際映像不相符的 digest」建立／執行容器並斷言拒絕。現有 pack `TestRejectHashMismatch` 驗證的是 template、payload、oracle 等檔案內容 hash，不等於映像 digest mismatch。E2E setup 遇到本地映像 digest 不符時會 `Skip`，也不是 adversarial rejection assertion。

### 4. 11 個 schemas 與 contracts tests

**未通過（功能通過、驗收證據不符規定）。** M0a 指定的 11 個 schema 都存在，`TestLoadDirAndValidate` 可載入 registry 並成功解析 evidence → run_result 的 `$ref`。M0c 另新增 `schemas/tools.schema.json`，不影響原 11 個檔案存在。

缺口：專案沒有 `tests/contracts`；目前只有 `internal/schemav/schemav_test.go`，且只用代表性文件驗證部分 schema。該測試註解也寫明 contracts tests 應另放於 `tests/`，但實際不存在。

### 5. Canonical JSON

**通過，附風險註記。** 下列 fixture tests 全部通過：

- 相同物件兩次輸出 byte-equal
- 非 ASCII key 排序
- `json.Number` 字面 round-trip
- `<`、`&` 不轉義
- 無尾換行

目前 production `evidence.Hash` 呼叫點傳入的都是 `map[string]any`，沒有直接 hash struct 的路徑。風險是 `Hash(v any)`／`CanonicalBytes(v any)` 的型別簽名仍允許 struct，現有測試只靠 convention 提醒，沒有在 API 邊界拒絕 struct。

## M0b — 決定性 SQLi E2E

### 1. Fixture 與三控制 run

**通過。** `fixtures/vuln-sqli-001` 的 `UserRepo.find_by_name` 使用 f-string 拼接 SQL；`TestM0bSqliProvenE2E` 斷言 run 順序固定為 negative → positive → exploit，並各自落 evidence。

### 2. 三個 oracle 條件

**通過。** 真容器 E2E 驗證：

- negative 使用不含跳脫字元的 nonce payload，漏洞 oracle 為 false
- positive 命中 `sink.touch.sql/v1`
- exploit 使用 `{{NONCE}}'`，命中 `sqli.error/v1`

### 3. Evidence chain 與 replay ×2

**通過。** `e2eVerifyChainAndReplay` 先執行 `evidence.VerifyChain`，再執行兩次 `orchestrator.ReplayCheck`；三個 M0b E2E 路徑皆呼叫此驗證。

### 4. Stdout 偽造

**通過。** `TestM0bStdoutNonceNotEvidence` 讓 exploit 直接輸出 nonce／假成功文字，但未產生可信 artifact；checker 沒有將 stdout 判為漏洞證據，結果不會是 `PROVEN`。

## M0c — Agent 整合

### 1. Prover tool loop → PROVEN

**通過。** `TestM0cProverLoopProvenE2E` 使用腳本化單一 adapter 驅動真 AgentRuntime tool loop：先 `read_code`，再 `submit_witness_spec`，通過 schema／placeholder gate 後進入 M0b 的真容器三控制 pipeline，最後得到 `PROVEN`。

此 E2E 不呼叫外部付費 provider；Anthropic 與 OpenAI-compatible transport 另以本機 HTTP 測試驗證 request shape、tool use、streaming／finish reason、錯誤分類與 effort fallback。

### 2. 失敗分類與預算

**通過。** 對應測試均通過：

- env 用盡 → `ENV_ERROR`：`TestAgentProverEnvExhausted`
- 三假設否證、fresh-eyes 後 → `HYPOTHESIS_REJECTED`，scope／rationale 同時寫入 journal：`TestAgentProverHypothesesExhausted`
- harness 用盡 → `NOT_PROVEN(harness_budget)` 並保留 attempts：`TestAgentProverHarnessBudget`
- 連續相同失敗簽名 → `NOT_PROVEN(oscillation)`：`TestAgentProverOscillation`
- 不同簽名不誤判振盪：`TestAgentProverOscillationDifferentSig`

### 3. 拒絕路徑

**通過。** `TestAgentProverGateRejections` 涵蓋：

- 重送相同 spec hash → `duplicate_spec`
- 缺三行 preamble → `missing_preamble`
- 缺 `{{NONCE}}` → `missing_nonce_placeholder`

`TestM0cProverLoopGateRejectionThenProvenE2E` 另以真容器流程確認缺 placeholder 的 spec 被拒、寫入 `witness_spec_rejected`、不消耗有效 Prove attempt，之後提交正確 spec 可收斂到 `PROVEN`。

## 工作樹狀態與可重現性

驗收時下列成果尚未提交：

```text
M  go.mod
M  go.sum
M  internal/sandbox/sandbox_test.go
?? docs/adr/0003-m0c-agent-integration.md
?? internal/agent/
?? internal/llm/
?? internal/orchestrator/agent_prover.go
?? internal/orchestrator/agent_prover_test.go
?? schemas/tools.schema.json
?? tests/e2e/m0c_prover_e2e_test.go
```

本文件也是本次新增的未提交檔案。正式封版前應在預定提交內容上再次執行相同指令，並確認乾淨 checkout 可重現結果。

## 修補後驗收

交接後已完成原待辦中的信任邊界修補，並新增 `tests/contracts/contracts_test.go`、合法但不存在 digest 的 `TestCreateRejectsUnknownDigest`，以及 struct canonical input rejection。M0b 已在本機 Docker（Linux arm64 observer binary）實際跑通；trusted observer 與 witness 分離，且 evidence 綁定 artifact hashes。

驗證結果：`go test ./...`、`go vet ./...`、`git diff --check` 均通過。

## 原待辦完成狀態

1. ✅ P0／P1 trust-boundary findings 已修復並有對應測試。
2. ✅ `TestCreateRejectsUnknownDigest` 明確斷言合法格式但不存在的 image digest 被 Docker create 拒絕。
3. ✅ `tests/contracts` 為 11 個 schema 提供 valid fixtures，並驗證 evidence → run_result `$ref`。
4. ✅ 全套 `go test ./...` 與 `go vet ./...` 通過；目前工作樹尚未 commit。
5. ✅ canonical API 在 runtime 拒絕 struct，僅接受 `map[string]any`。

## 詳細 Code Review（2026-09-04）

### 審查結論

這次審查不是只看測試名稱，而是沿四條信任邊界檢查實際資料流：

1. 模型工具權限與路徑／secret 邊界。
2. WitnessSpec、失敗分類與預算狀態機。
3. Docker 隔離、observer／oracle／checker 與 evidence 完整性。
4. LLM adapter 的 streaming、refusal、錯誤與重試行為。

結果包含 3 個阻斷性 P0、4 個 P1，以及數個 P2 問題。這些問題可以在所有現有測試通過時仍然存在。

### P0-1：模型可偽造 trusted oracle artifact

**影響：可製造假的 `PROVEN`，破壞產品最核心的信任聲明。**

模型控制 `generated_files` 內的 witness／exploit 程式；證明容器同時把 `aegis-out-<runID>` 以可寫方式掛載到 `/aegis/out`（`internal/sandbox/flags.go:155-166`）。Pack 的 observer 也把 `sql_trace.jsonl` 寫到同一目錄（`packs/python-web/sandbox/sitecustomize.py:28-51`），host checker 則直接信任並解析該檔案（`internal/oracles/oracles.go:147-198`）。

惡意 witness 可以讀 `/aegis/payload.txt` 得到本輪 nonce，然後自行建立合法 JSONL：

- negative：寫入含 nonce、`error: null` 的 SQL，使漏洞 oracle 為 false；
- positive：相同資料使 paired touch oracle 為 true；
- exploit：payload 含跳脫字元時改寫 `error` 為非 null，使漏洞 oracle 為 true。

這可完整滿足三控制 run 並得到假的 `PROVEN`。Nonce 事前不告知模型並不能防禦，因為模型生成的程式在容器內可以讀到替換後 payload。

**必要修正：** trusted observer 的輸出通道必須與不受信任 witness 隔離，witness 不得寫 oracle 所信任的 artifact。需新增「偽造 `sql_trace.jsonl` 仍不得 PROVEN」的真容器 adversarial test；只測 stdout 偽造不足。

### P0-2：Evidence 不符合 schema，且沒有綁定真正 artifacts

**影響：evidence manifest 不是 SPEC 宣稱的機讀契約，hash 鏈無法證明實際證據未被修改。**

`internal/orchestrator/prove.go:328-343` 寫出的文件以 `kind: "run_result"`、`kind_label`、`artifacts_dir` 等自訂欄位組成；但 `schemas/evidence.schema.json:7-64` 要求：

- `kind` 為 `negative | positive | exploit`；
- `repo_tree_hash`、`pack`、`runner_version`、`prompt_version`；
- `run_request_hash`、完整 `run_result`、`oracle`；
- `created_by` 與 `verified_by`。

Production evidence 寫入沒有 schema validation，因此 schema-invalid 文件仍會落盤並讓測試通過。

此外，`internal/evidence/store.go:68-96` 只 hash evidence JSON；實際 `sql_trace.jsonl`、`run.log`、`fs_diff.txt` 等 artifacts 沒有內容 hash 綁入 evidence。事後修改 artifact 不會破壞 `VerifyChain`。

**必要修正：** evidence 必須以 schema 真源組裝並在落盤前驗證；每個 artifact 的相對路徑、hash、大小應被 run_result／manifest 綁定，oracle 結果與 evidence refs 也必須落入同一條可信鏈。

### P0-3：Repo secrets 可送往外部 LLM，或先寫入 audit

**影響：接真實 provider 時可能洩漏使用者原始碼中的金鑰與密碼。**

- `read_code` 直接讀檔回傳，沒有 secret scan（`internal/agent/tools.go:123-164`）。
- `search_code` 把命中原文直接回傳，沒有 secret scan（`internal/agent/tools.go:167-230`）。
- 初始 `Finding.Context` 未掃描即放進 LLM prompt（`internal/orchestrator/agent_prover.go:395-406`）。
- operator hints 只遮蔽 nonce，沒有使用 `internal/redaction` 掃 secrets（`internal/orchestrator/agent_prover.go:465-509`）。
- `audit.jsonl` 記錄完整 tool args；模型提交的 WitnessSpec 會在 policy secret scan 前落盤（`internal/agent/audit.go:77-92`、`internal/agent/tools.go:300-312`）。

**必要修正：** 所有送 LLM 與落盤資料必須共用 `internal/redaction` 的封閉規則；repo secret 命中時預設停止並要求確認，而不是單純遮蔽後繼續。Audit 也不得在 secret scan 前保存原始提交內容。

### P1-1：強制安全閘 fail-open

`AgentProver.ValidateSpec` 為 nil 時直接跳過 schema 驗證（`internal/orchestrator/agent_prover.go:98-100, 361-369`）；程式只用註解要求正式接線不得為 nil。

Audit logger 同樣允許為 nil，且 marshal／write failure 全部靜默忽略（`internal/agent/audit.go:77-92`）。這違反 SPEC §18.1「每個 tool call 前政策檢查並記 audit」的強制要求。

**必要修正：** `AgentProver.Run` 啟動時必須檢查 schema validator、audit logger、tool definitions、journal 等必要元件；缺任何一項立即 fail-closed。Audit append 應回傳錯誤並決定是否阻止工具執行。

### P1-2：Replay 不是自包含 bundle replay

`internal/orchestrator/replay.go:20-57` 同時依賴 evidence 外的三種狀態：

- evidence 中保存的絕對 `artifacts_dir`；
- 該目錄下可被事後修改的檔案；
- 呼叫端傳入、只存在記憶體的原始 `*ProveResult`。

現有 `e2eVerifyChainAndReplay` 只是對同一組檔案連續呼叫 checker 兩次（`tests/e2e/sqli_e2e_test.go:348-359`），沒有從 bundle 獨立重建結果，也沒有重新執行三控制 run 或比較兩次 evidence hash。

**必要修正：** replay 輸入只能是 bundle；不得需要原始 in-memory result 或絕對外部路徑。測試應複製 bundle 至另一目錄後離線驗證，並加入 artifact tamper detection。

### P1-3：AgentRuntime 歷史與提交狀態機錯誤

`Runtime.Run` 回傳的 history 已包含輸入 messages（`internal/agent/runtime.go:54-56`），但 AgentProver 在繼續下一輪時把它 append 到原本的 `msgs`（`internal/orchestrator/agent_prover.go:205-206, 237-238, 289-291`）。這會重複初始與既有對話，並隨多輪執行持續膨脹 context。

另外，spec 核可後 Runtime 沒有停止。模型可以在同一 assistant response 放多個 `submit_witness_spec`，或在收到 `accepted` 後繼續提交；`pendingSpec` 會被最後一份覆蓋，但多份 spec 都已被記為 accepted／seen。

**必要修正：** 明確定義 Runtime 回傳的是增量或完整 history，呼叫端只能擇一使用；第一份 spec 核可後應終止本次 session 的 tool 執行，或拒絕該回合的其餘 submit。

### P1-4：AST check 只是字串搜尋

`internal/orchestrator/orchestrator.go:151-199` 使用 `strings.Contains("class "+seg)`／`strings.Contains("def "+seg)` 判定 symbol 存在。註解、字串常數、不相關 scope 或名稱前綴都可能造成假命中；package module path 也沒有完整解析。

這不符合 SPEC §17.9-2 要求的 digest-pinned AST helper container，且原始註解寫「M0c 升級」，目前 M0c 仍未實作。

### P2-1：Provider protocol 沒有按 SPEC 接線

- `AgentProver.chatRequest` 沒有設定 `Stream: true`，所以 prover 不會走 Anthropic streaming（`internal/orchestrator/agent_prover.go:409-418`）。
- `StopRefusal`／`StopMaxTokens` 會被當成普通 session 終止，最後走 `no_spec_submitted` harness 分類，而不是 refusal 解敏重試／fallback／`ENV_ERROR`。
- OpenAI-compatible adapter 對 429／5xx 沒有退避重試。
- Schema／解析失敗使用整體 32-turn tool loop 上限，不是 SPEC §18.3 的最多兩次重試。

### P2-2：Sandbox helper hardening 與取消不完整

Artifacts reclaim helper 只有 cap-drop、no-new-privileges、read-only、non-root、network none；缺 seccomp、memory、CPU、PIDs、nofile 等限制（`internal/sandbox/sandbox.go:278-297`），與「套用相同 hardening」的規格不符。

`cpTarStdin` 使用 `exec.Command`，沒有 context 或 timeout（`internal/sandbox/stage.go:142-166`）。`Runner.Start` 也建立自己的 background timeout，不接收外層 `Prove(ctx)` 的取消，因此使用者取消不會立即終止 Docker 工作。

### P2-3：Evidence store 並非 append-only

`Store.Write` 使用 `os.WriteFile`（`internal/evidence/store.go:68-96`）：

- 既有 `EV-####.json` 可以被覆蓋；
- `id` 沒有格式驗證；
- 沒有使用 exclusive create；
- `NewStore` 只 hash 最後一筆，沒有先驗整條既有 chain。

這與檔頭宣稱的 append-only 語意不符。

### 為何所有測試仍然通過

現有測試主要使用誠實 fixture 與合作式 script adapter：

- witness 不會主動偽造 observer artifact；
- script adapter 每次只提交預期數量的 spec；
- M0c E2E 明確注入 schema validator 與 audit logger，所以沒測到漏接時的 fail-open；
- replay 測試把原始 `ProveResult` 留在記憶體並重用同一 artifact 目錄；
- schema tests 驗證手寫的合法範例，而不是 production 實際落盤的 evidence。

因此「測試全部通過」與上述缺陷並不矛盾；缺的是針對敵對模型、接線錯誤與 evidence tampering 的測試。

### 修復優先序

1. 隔離 trusted observer output，先堵住偽造 `PROVEN`。
2. 重做 evidence manifest／artifact hashing／self-contained replay。
3. 在任何真實 provider 接線前完成 repo secret gate 與落盤 redaction。
4. 將 schema validator、audit、journal 改為 fail-closed。
5. 修正 Runtime history 與單次 submit 狀態機。
6. 實作真正 AST helper，再補 provider protocol 與 sandbox helper hardening。
7. 每一項修復都先加入可重現原缺陷的 adversarial test，確認測試修復前失敗、修復後通過。
