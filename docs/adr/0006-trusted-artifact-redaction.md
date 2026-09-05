# ADR 0006：trusted artifact 落盤前的秘密遮蔽語意（span 遮蔽後落盤）

## 狀態

Accepted（ASK 已由人類決策，2026-09-05——SPEC §23.9 決策流程）

## 背景

§7.2 封閉樣式清單的 `kv_secret` 樣式
（`(?i)(api_?key|secret|password|token)\s*[=:]\s*\S{8,}`）對 trusted artifact
存在結構性誤報：error-based SQLi 的 sqlite 錯誤訊息必然含有
`unrecognized token: "<nonce>'"`——nonce（32 hex）的形狀本就與金鑰相同，
`token:` 接非空白 8+ 字元即命中。

原實作（外部審查 P1-07 修補後）的 artifact gate 在命中時**整檔拒收**、run 以
ENV_ERROR 失敗。此語意下 error-based SQLi 的 vuln oracle
（`nonce_statement_errored`）**永遠無法成立**——trace 中的 nonce 與誤報命中
同段文字，證據與誤報一起消失。實測：`TestM0bSqliProvenE2E` 的 exploit run
穩定命中（R-0003，`secret pattern in artifact sql_trace.jsonl (persistence
denied)`）。

§7.2 原文僅述「落盤（log、evidence、report）前掃 secrets 再寫入」，未定義命中
後的處理語意（擋下／遮蔽／丟檔）；審查 P1-07 要求「不可靜默截斷」。

## 決策

trusted artifact（observer／entrypoint 產出、由 orchestrator 收回的檔案）落盤
採 **span 級遮蔽後照常落盤**，不作靜默處理：

1. 命中樣式的完整匹配段（含 `private_key` 的跨行段）以 `***REDACTED***`
   蓋掉（`redaction.Mask`），其餘內容原樣保留。
2. 命中樣式名稱清單記入 evidence 的
   `run_result.artifact_redactions`（檔名 → 樣式名陣列；schema 新增 optional
   欄位，閉集守恆），artifact hash 以**遮蔽後內容**計算——replay 驗的即是
   遮蔽後的鏈，自洽。
3. 誤報不吞掉 oracle 證據：遮蔽只蓋命中段，`sql` 欄位的 nonce 保留，checker
   照常判讀。

### ASK 記錄（三案，人類選一）

- **（採用）遮蔽後落盤**：證據保留、誤報可收斂；代價是命中段內容不可回復
  （若為真實洩漏，內容已移除——可接受，樣式名仍記錄在案）。
- 改 `kv_secret` 樣式：樣式清單為 §7.2 逐字封閉清單，改樣式＝改 SPEC 文字；
  且 nonce 與真實 secret 形狀相同，任何形狀規則都無法兩全。
- 維持拒收＋丟檔：fail-closed 最嚴格，但 error-based SQLi 永遠無法 PROVEN，
  e2e 的 PROVEN 驗證需放棄此形狀。

## 取捨與殘餘風險

- **遮蔽是保守的**：命中即遮，寧可誤遮不誤放；真實洩漏（如錯誤訊息含 DB
  密碼）同樣被蓋掉——secret 內容不落盤的保證不變，但「證據完整性」對該段
  讓位。
- **範圍僅 trusted artifact 檔案**：`stdout`／`stderr` 的命中維持「run 拒收」
  （prove.go 既有語意）；容器 T 資訊性 logs 維持「命中即不落檔、不中斷
  run」；`redaction.WriteFile` 對非 artifact 產物（report／findings／
  console）維持 default-deny。三種落盤面各自的語意在 §7.2 原文下各有其
  意義，本 ADR 只放寬 oracle 證據檔案——放寬 stdout／stderr 會讓容器輸出
  的潛在洩漏以遮蔽形式進 evidence 而無人複核，暫不採。
- **遮蔽破壞 oracle 的可能**：若 nonce 落在命中段內（本例不會——命中在
  `error` 欄位、nonce 在 `sql` 欄位），遮蔽會使 oracle 缺證據 → run 誠實地
  不成立（fail-closed 於證據面），prover 可重試其他 payload。

## 驗收

- `internal/redaction/redaction_test.go`：`TestMaskSpanRedaction`（真實誤報
  場景：error 欄位遮蔽、sql 欄位 nonce 保留、遮蔽後不再命中）、
  `TestMaskPrivateKeyDownToEnd`（跨行段整段蓋掉）、`TestMaskNoHit`。
- `tests/e2e/sqli_e2e_test.go` `TestM0bSqliProvenE2E`：exploit run 的
  sql_trace.jsonl 經遮蔽後 vuln oracle 仍命中，PROVEN 收斂（真 Docker）。
- evidence schema 驗證接受新欄位（`schemav` 對 evidence 文件照常驗證）。