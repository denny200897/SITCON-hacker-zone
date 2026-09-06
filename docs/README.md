# Aegis 文件索引

一般使用者從 [使用指南](USAGE.md) 開始；開發者與維護者可依序閱讀技術架構、資料契約與維運文件。

| 文件 | 內容與用途 |
| --- | --- |
| [專案 README](../README.md) | 安裝、產品能力、快速開始 |
| [使用指南](USAGE.md) | 互動操作、模型設定、CLI 工作流程 |
| [技術架構](TECHNICAL.md) | 模組職責、掃描與驗證流程、LLM 工具、信任邊界 |
| [介面與資料契約](CONTRACTS.md) | CLI 參數、狀態、WitnessSpec、證據、SQLite journal |
| [開發與維運](DEVELOPMENT.md) | 建置、設定、測試、CI、發布、擴充與排錯 |
| [設計規格](../SPEC.md) | 設計目標、不變式、階段性驗收要求 |
| [威脅模型](threat-model.md) | 攻擊面、防線與殘餘風險 |
| [M0a–M0c 驗收](acceptance-m0a-m0c.md) | 早期里程碑的驗收方式 |

## 架構決策紀錄

- [0001：M0a trust kernel](adr/0001-m0a-trust-kernel.md)
- [0002：M0b E2E](adr/0002-m0b-e2e.md)
- [0003：M0c agent integration](adr/0003-m0c-agent-integration.md)
- [0004：trusted observer 與 replay](adr/0004-trusted-observer-and-replay.md)
- [0005：雙容器信任邊界](adr/0005-split-container-trust-boundary.md)
- [0006：trusted artifact 遮蔽](adr/0006-trusted-artifact-redaction.md)

## 文件版本與判讀

技術架構、契約與維運文件於 2026-09-06 依基準 commit `9b357f9` 的程式碼整理。它們描述目前實作；`SPEC.md` 同時包含設計要求與後續階段，不能把所有規格條目視為已交付能力。JSON 欄位限制以 [schemas](../schemas) 與呼叫端驗證為準，執行行為以原始碼與測試為準。

`HANDOFF-*`、`CODE-REVIEW-*`、`REVIEW-*` 是特定日期的交接或審查紀錄，保留當時脈絡，不代表目前所有問題仍存在或都已修復。後續修改應同步更新相關技術文件；涉及信任邊界的決策則另寫 ADR。
