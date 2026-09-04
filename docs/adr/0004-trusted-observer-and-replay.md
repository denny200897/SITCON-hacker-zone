# ADR 0004：Trusted observer boundary、fail-closed 與 self-contained replay

## 狀態

Accepted（M0 修補決策，2026-09-04）

## 背景

Witness 程式與原本的 SQL trace shim 若同時能寫入 `/aegis/out`，模型產生的
witness 可以偽造 `sql_trace.jsonl`，造成 checker 把非漏洞輸入判成 PROVEN。另
外，replay 若依賴原始程序的 `ProveResult` 或 evidence 內的 host 絕對路徑，便
不能在新程序中獨立驗證。

## 決策

1. trusted observer 必須是獨立的 Go 程序／容器，使用 digest-pinned image，並
   持有唯一可寫的 trusted output volume。Witness 容器不得掛載該 volume 的可寫
   路徑，也不得控制 observer 的資料庫或 trace protocol；SQL 由 proxy 實際執行，
   trace 由 proxy 落盤。
2. harness 只接受 observer 收回的 artifact；stdout、stderr、witness 自行寫入
   的檔案都不能成為 oracle 證據。artifact hash 會寫入 evidence，落盤使用
   `O_EXCL`。
3. replay 的規範入口是 `orchestrator.ReplayBundle(pack, runDir)`。它由 evidence
   讀出 run、nonce、oracle、固定相對 artifact 路徑與 hash，不依賴記憶體結果或
   host 絕對路徑；舊 `ReplayCheck` 僅作相容性包裝並額外比對原始結果。
4. 缺少 schema validator、journal 或 audit logger 時，agent 直接 fail-closed；
   provider refusal／max-token 只能分類為環境失敗並依預算處理。

## 取捨與殘餘風險

獨立 proxy 增加一個受 hardening、digest、lifecycle 管理的元件，但這是避免同
uid witness 偽造 observer 輸出的必要信任邊界。M0 的既有 Python shim 只能作為
相容性／開發 fixture；在 proxy 接線完成前不得把它當成 production trusted
observer，也不得以其輸出宣稱外部可利用性。
