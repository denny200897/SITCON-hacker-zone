# ADR 0003：M0c Agent 整合的實作決策

日期：2026-09-04
狀態：已採用
關聯：SPEC.md §18、§9.3、§21.3、§23

## 背景

M0c 將決定性三控制 run（M0b）接上 AgentRuntime，形成 prover 迴圈：多假設迭代、
§9.3 停止條件、§18.2 回饋協定。SPEC 未覆蓋的細節在此記錄決策。

## 決策

### 1. audit log 為獨立 JSONL 串流（`<runDir>/audit.jsonl`）

§21.3 的 journal 事件型別是 17 型閉集，新增型別需 bump `schema_version`
（級聯影響 evidence/journal schema）。per-turn 工具閘的稽核（§18.1）以獨立
`audit.jsonl`（0600、逐行 JSON、role/tool/args/decision/reason）承載，
不佔用 journal 事件閉集。`allowed|denied|error` 三值為閉集。

### 2. session 結束但未提交 spec → harness 分類

§19 決策樹沒有「模型未提交 spec」的形狀。決策：歸 harness（模型職責未完成，
屬「witness 接線/流程」類），扣 harness 計數、以 operator 回饋提示重交。
非 env（transport 層正常）也非 controlled_miss（無 spec 即無假設可否證）。

### 3. 「無後續假設」以固定文字標記偵測

§9.3 允許 prover「以結構化輸出明示『無後續假設』→ HYPOTHESIS_REJECTED」。
v1 工具白名單（§18.1）prover 只有 `submit_witness_spec` 一個提交工具，加第二個
結構化工具偏離白名單閉集；改以 session 終態文字包含固定標記
`無後續假設` 偵測（僅在有過 operator 回饋之後的 session 終態生效，
避免首輪誤觸發）。此為工具面等價替代，行為契約（立即終態、scope 落檔）與
spec 相同。

### 4. 三行 preamble 的格式

§18.2 要求「先輸出三行（上輪學到什麼／這輪改什麼／預期觀察到什麼）」。
決策以行首前綴偵測：`學到：`／`改：`／`預期：`（全半形冒號皆可），
三類各至少一行才過閘；驗不到 → `missing_preamble` 拒收。
「學到」行同時是 HYPOTHESIS_REJECTED rationale 的素材（§9.3）。

### 5. fresh-eyes 的 session 重建語義

§9.3 fresh-eyes：「開全新 session、不帶先前失敗敘事、最多 1 個新假設、
不計入 hypotheses、之後不論結果進終態」。實作：
- 對話歷史整段重建（只剩 finding 原始資料 + 一句 dry 說明）；
- spec 去重集合重置（fresh 空間允許任何新假設）；
- `feedbackSeen` 重置（fresh 輪提交不需 preamble）；
- 進行中標記 `freshRound`：任何非 PROVEN 結果（含 transport 失敗、未提交、
  controlled_miss）直接進觸發時的終態（HYPOTHESIS_REJECTED），不再扣任何計數器。

### 6. 振盪失敗簽名的計算素材

§9.3 簽名 = exit code ＋ stderr sha256。沙箱 artifacts 中全程 stderr/stdout
集中在 `run.log`（pack entrypoint 契約）；且 trace（sql_trace.jsonl 等）與
run.log 可能含 nonce——兩輪 nonce 必不同，直接雜湊會讓同型失敗永遠不同簽名、
振盪偵測失效。決策：先將該輪所有 run 的 nonce 以 `@@NONCE@@` 紅線後再雜湊。
同一紅線套用於 §18.2 回饋的 tails（nonce 不進回饋）。

### 7. AgentRuntime.Run 回傳完整對話歷史

prover 迴圈每輪之間以 operator 訊息接續 session；Runtime 內部的 tool 往返
（assistant tool_use → tool_result）必須保留在歷史中，否則跨輪上下文斷裂。
`Run` 簽名改為回傳 `(Response, []Message, error)`。

### 8. 預算分層

決定性 harness（`Prover.Prove`）維持 ADR 0002 的單次預算語意；§9.3 的
env/harness/hypotheses 計數器全部由 AgentProver 迴圈級持有與扣抵
（`budget.OnFailure`）。`ProveFunc` 為注入點：正式接線傳 `(*Prover).Prove`，
單元測試傳假實作（不起 docker 即可測滿 §22 的分類/拒絕路徑）。

### 9. anthropic SDK 版本

升級 anthropic-sdk-go v1.4.0 → v1.70.1（OfAdaptive／OutputConfig.Effort／
StopDetails 在 v1.4.0 缺漏）。§18.3 註明「欄位名以官方 SDK 為準，有出入記 ADR」：
- `OutputConfigParam.Effort` 與 spec 一致，無出入。
- 工具 schema 原樣傳遞：`ToolInputSchemaParam` 的 UnmarshalJSON 會丟棄未知鍵
  且 ExtraFields 序列化順序不穩（實測 5 種排列）——與 §18.3「工具定義順序、
  system 文字逐 byte 穩定」衝突。改用 `packages/param` 的
  `param.SetJSON(schemaBytes, &schema)` 把 schema bytes 原樣嵌入
  `ToolParam.InputSchema`（驗證 byte-identical）。非 struct-tag 生成，與
  §23-11 一致（真源仍在 schemas/）。
- tool_use 輸入取 `ContentBlockUnion.Input`（json.RawMessage），等價於 spec 的
  `ToolUseBlock.JSON.Input.Raw()`。
- thinking 是否啟用以 model id 的 5 系列判定（§18.3「5 系列一律」）；4 系列不帶
  thinking 欄位（§23-5 禁 budget 形式，故 4 系列不啟用 thinking）。

### 10. openai-compat 的降級面（§3.2）

- 串流：§18.3 串流要求僅定義於 anthropic 面；openai-compat v1 一律
  `stream:false`（降級路徑，檔頭有 ASK 回報註記）。
- `ToolResult.IsError` 在 OpenAI wire 無表示：內容原樣回傳，旗標丟棄（spec 未
  定義映射）。
- effort 能力探測：HTTP 400 且 body 提及 reasoning → 去除 `reasoning_effort`
  重試一次並記憶（atomic.Bool）；其他 400 不降級。
- finish reason 映射閉集：tool_calls→tool_use、stop→end_turn、length→max_tokens、
  其餘（含空回應）→ other／refusal("empty_response")。
- 錯誤只以 HTTP 狀態分類（`*llm.Error{StatusCode, Body}`，4xx 不重試 →
  ENV_ERROR 歸類由呼叫端處理）。