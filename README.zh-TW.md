# Aegis

> **Don’t just find the vulnerability. Prove it.**

Aegis 是一個 **AI-assisted Code Security Review Agent Harness**，目標不是只告訴開發者「這裡可能有漏洞」，而是進一步判斷漏洞距離可利用有多遠，並在隔離 Sandbox 中建立最小化 Witness 驗證可利用性。

## 核心特色

- **AI Code Review** — 結合 Semgrep 與 LLM 找出高風險程式碼
- **Attack-Chain Distance (ACD)** — 將漏洞分為 D0～D3，量化距離真正攻擊鏈的距離
- **MVP Witness** — 對目前沒有完整攻擊入口的漏洞，建立最小化驗證環境
- **Trusted Oracle** — 不相信 LLM 自己宣稱「Exploit 成功」，由可驗證的 Side Effect 判定
- **Hardened Sandbox** — Docker 隔離執行 Proof，限制 Network、Filesystem、Privilege 與 Resource
- **Evidence Bundle** — 保存可重現的 Proof、Artifact、Hash 與環境資訊
- **Tripwires** — 將發現轉換成 Semgrep / CI Guardrails，避免漏洞再次出現

## ACD

| Level | 意義 |
|---|---|
| **D0** | 已存在輸入入口，可直接到達 Sink |
| **D1** | 已有入口，但需要特定參數 / 路由 / 設定 |
| **D2** | 需要少量 Wiring 才能接上攻擊入口 |
| **D3** | 需要新增產品功能才能形成攻擊鏈 |

> **ACD ≠ Severity**：漏洞嚴重度仍會綜合 Impact、Confidence 與 Reachability 判定。

## Proof Flow

```text
Source Code
    ↓
Semgrep + AI Review
    ↓
Triage + ACD
    ↓
MVP Witness
    ↓
Policy Compiler
    ↓
Hardened Docker Sandbox
    ↓
Trusted Oracle
    ↓
PROVEN / NOT_PROVEN
    ↓
Evidence + Report + Tripwire
```


## 設計原則

**Find → Measure → Prove → Prevent**

Aegis 不只是「漏洞掃描器」，而是一套從 **發現漏洞、分析攻擊鏈、驗證可利用性，到產生防護規則** 的安全審查流程。

詳細技術設計請參考 [`ARCHITECTURE.zh-TW.md`](ARCHITECTURE.zh-TW.md) 與 [`SPEC.md`](SPEC.md)。


##  使用方法
進到該專案，開啟終端機輸入aegis