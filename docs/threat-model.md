# Aegis 威脅模型（Threat Model）

> 依 SPEC §15：本文件在 M0a 前撰寫。§7.1 hardening profile 與 policy compiler 的**每一條規則**都必須能回溯到此處的威脅項（T-*）。
> 範圍：Aegis 是一個針對**使用者自有程式碼**的資安審查工具，於本機沙箱內驗證漏洞。非目標見 SPEC §1.2。

## 1. 資產與信任邊界

| 資產 | 所在 | 信任層級 |
|------|------|----------|
| 使用者 repo 內容 | host / snapshot | 不可信（資料，非指令） |
| 目標 repo 的**執行**（直攻模式） | 沙箱容器 | 不可信程式碼 |
| sink pack 內容物（oracle／模板／payload） | pack 目錄 | 受信任（隨版簽章，`trust_level: bundled`） |
| prover 產出（WitnessSpec／exploit） | LLM 輸出 | **不可信** |
| LLM API 金鑰 | keychain / env | 機密，永不離開 host |
| evidence bundle | `out/run-*/evidence/` | 完整性受 hash 鏈保護，機密性等同 repo |
| 沙箱容器 | Docker | 不可信執行環境 |

信任邊界：模型宣稱一律在信任域外；pack oracle 在信任域內；沙箱對 host 是邊界；repo 內容對所有 LLM 角色是資料。

## 2. 威脅項（Threats）與對策回溯

### T1 — 模型幻覺／欺騙：宣稱漏洞存在但無法證明
- **對策**：PROVEN 只能由 trusted oracle 機械判定（SPEC §2.3，不變式 2）；exploit stdout 永不作為成功證據；nonce 由 runner 產生、事前不告知 prover（§17.2）→ 實作項：`oracles/checker`、policy compiler nonce 替換。
- **回溯**：§17.9-4（payload 必含 `{{NONCE}}`）、§18.2（回饋不含 nonce）。

### T2 — 模型越權執行：要求沙箱做未授權的事
- **對策**：prover 只能輸出 WitnessSpec；RunRequest 全由 policy compiler 組裝（不變式 1）。閉集驗證 §17.9（1–7）→ 實作項：`orchestrator/policy`。
- **回溯**：映像只收 digest（§7.1、T5）；`generated_files` 鍵格式／大小限制（T7）；金鑰樣式掃描（T9）。

### T3 — 沙箱逃逸／容器攻擊 host
- **對策**：§7.1 hardening profile 全套（`--cap-drop ALL`、`no-new-privileges`、seccomp、non-root 65532、ro rootfs、限定 tmpfs、pids/mem/cpu/ulimit 上限）→ 實作項：`sandbox` runner，每條 flag 有 unit test（§22 M0a）。
- **回溯**：禁止 Docker socket 掛載、host PID/IPC、devices、`--privileged`；掛載 realpath canonicalization + symlink 防護（T8）。

### T4 — 供應鏈：映像或依賴被替換
- **對策**：映像僅接受 `@sha256:` digest（可變 tag 拒絕，§17.10 解析序）；依賴經 deps helper 以 `pip download --require-hashes` 驗 hash 後離線安裝（§17.4）；build 永遠 `--network none`。
- **回溯**：policy compiler digest allowlist（§5.2 run_request.image）。

### T5 — 惡意 WitnessSpec：`..` 穿越、絕對路徑、超大檔、壞映像引用
- **對策**：§17.9-3（鍵必為 `witness/<name>`、無 `..`、無絕對路徑、≤8 檔、≤256KiB）；§17.9-2（target_symbol AST 靜態驗證，只 parse 不執行）；§17.9-1（template/oracle 必在 pack manifest）。
- **實作項**：`orchestrator/policy` 驗證閉集 + `tests/adversarial`。

### T6 — Prompt injection：被掃 repo 內藏指令
- **對策**：repo=資料原則（system prompt 開頭宣告）；路徑政策 exclude 清單（`.env`、私鑰、`.git`…）；資料最小化（per-role 範圍）；tool call audit log；operator channel；注入掃描僅輔助標註，不作安全邊界（§7.2）。
- **實作項**：`inventory` 路徑政策、`agents` prompts、`orchestrator` audit log。

### T7 — 秘密外洩（雙向）
- **repo secrets 送 LLM**：送 LLM 前掃封閉樣式清單（`internal/redaction/patterns.go`，RE2、無 lookahead／backreference），命中即停（§7.2）。
- **API 金鑰外洩**：keychain 儲存、settings/credentials 0600、`/provider list` 只顯示有無、落盤前 redaction、沙箱內零金鑰（注入檔案先過金鑰掃描，§17.9-5）。
- **實作項**：`redaction`（單一真源）、`providers/credentials`、policy compiler `secret_in_spec`。

### T8 — 掛載逃逸：snapshot 外檔案經 symlink 進沙箱
- **對策**：snapshot 複製以 `Lstat` 判定、symlink 原樣重鏰不跟隨（§16 Snapshot 實作）；掛載前 realpath canonicalization、拒絕指向 snapshot 外（§7.1）。
- **實作項**：`orchestrator/snapshot`、`sandbox` mount 驗證。

### T9 — oracle 誤觸發／判別力不足
- **對策**：negative run 驗證 oracle 判別力（良性 payload 不得觸發，§17.7）；每個 oracle 家族必附 paired touch rule（pack ABI 拒載條件）；positive control 通過後的 miss 才計反證（§9.2）；失敗分類樹 §19 第 4 點（negative=true → harness，標記 oracle 待檢修）。

### T10 — LLM 半途放棄／振盪（假陰性）
- **對策**：放棄權在 orchestrator——失敗分類制預算（§9.1）、振盪偵測（失敗簽名相同 ×2，§9.3）、fresh-eyes 最後一輪；NOT_PROVEN ≠ 丟棄。
- **實作項**：`orchestrator/budget`、prover 迴圈。

### T11 — 成本／時間失控
- **對策**：沙箱 wall-clock 上限（預設 60s/run、每 finding 10 分鐘）、exit 124 逾時分類、reaper 清理孤兒；token 預設不設限（BYOK，非安全項）。

### T12 — 工具遭誤用於他人系統
- **對策**：僅本地沙箱、目標 repo 需本機存在、文件聲明（§7.3）；不提供橫向移動／持久化內容；報告 payload 以 canary 為主。

## 3. STRATE 摘要

| 類別 | 要點 |
|------|------|
| Spoofing | nonce 由 runner 產生且事前保密 → exploit 無法預錄成功證據（T1） |
| Tampering | evidence 以 canonical JSON + sha256 鏈結；本機 hash 證明「內容未變」不證明「不可變」（§5.3 誠實語意） |
| Repudiation | 所有 LLM tool call 經政策檢查並記 audit log（T6）；journal event 閉集（§21.3） |
| Information disclosure | secrets 雙向防線（T7）；回饋頻寬有界（§18.2） |
| Denial of service | 沙箱資源上限、逾時、pids-limit（T11） |
| Elevation of privilege | 容器 non-root + cap-drop ALL（T3）；角色工具白名單（無 shell）（T2） |