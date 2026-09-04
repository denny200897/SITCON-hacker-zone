#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ast_check.py —— SPEC §17.9-2 target_symbol AST 靜態解析 helper（pack 能力 ast_helper）。

由 orchestrator 以 digest-pinned 容器執行（§17.1 hardening 全套：--read-only、
--network none、--cap-drop ALL、non-root 65532、seccomp；snapshot 唯讀掛 /target）。
**只 parse、不 import、不執行任何目標碼**（§17.9-2）。

符號路徑語意（scope-aware，取代 orchestrator 舊版文字層 strings.Contains——P1-4）：
  module[.Class][.NestedClass][.method][.nested] ——
  - module 段對應 snapshot 內的 .py 檔（pkg.mod 或 pkg/__init__.py 套件形式）
  - 其餘各段以 Python ast 的真實 scope 解析：class 本體成員、巢狀 def／class、
    指派（Assign／AnnAssign）目標名；註解、字串常數、名稱前綴、不相關 scope
    一律不會命中

契約（與 orchestrator.ASTChecker 對應）：
  - argv：--root <snapshot 掛載點> --symbol <符號路徑> --out <verdict 檔>
  - verdict 以 canonical JSON（sort_keys、緊湊分隔符、無 ASCII 轉義）寫入 --out
    ——判定只落 artifact 檔；stdout 僅是 gate plumbing，**不作為證據**（§23-3）
  - exit 0：符號解析命中；exit 1：未命中或符號非法；exit 2：parse／內部錯誤
    （host 端以 out 檔為唯一判定來源，exit code 僅供診斷）
"""

import argparse
import ast
import json
from pathlib import Path

# scope 內會「往下展開子敘述」的複合敘述：其子敘述在 runtime 仍綁定於本 scope
#（class／module 本體層級），故解析時納入；函式本體是子 scope，不在本層展開。
_COMPOUND = (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)


def _compound_children(stmt):
    """取得複合敘述的所有子敘述（body／orelse／finalbody／except handlers）。"""
    kids = []
    for attr in ("body", "orelse", "finalbody"):
        kids.extend(getattr(stmt, attr, None) or [])
    if isinstance(stmt, ast.Try):
        for handler in stmt.handlers:
            kids.extend(handler.body)
    return kids


def find_binding(stmts, name):
    """在給定 scope 的直接敘述中找出名為 name 的綁定（def／class／指派目標）。

    scope-aware 規則（§17.9-2）：
      - module／class 本體的直接敘述屬於本 scope
      - if／try／with／for／while 的子敘述在 runtime 仍綁定於本 scope，納入
      - 函式本體是子 scope，不在本層展開（由 resolve 遞迴進入）
    """
    hits = []
    for s in stmts:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if s.name == name:
                hits.append(s)
        elif isinstance(s, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == name for t in s.targets):
                hits.append(s)
        elif isinstance(s, ast.AnnAssign):
            if isinstance(s.target, ast.Name) and s.target.id == name:
                hits.append(s)
        elif isinstance(s, _COMPOUND):
            hits.extend(find_binding(_compound_children(s), name))
    return hits


def resolve(stmts, segs):
    """以 scope 遞迴解析 segs；命中回定義節點，未命中回 None。"""
    for node in find_binding(stmts, segs[0]):
        if len(segs) == 1:
            return node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            got = resolve(node.body, segs[1:])
            if got is not None:
                return got
    return None


def _kind_of(node):
    """verdict 的 kind 標籤（閉集）。"""
    if isinstance(node, ast.ClassDef):
        return "class"
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "function"
    return "assignment"


def main():
    ap = argparse.ArgumentParser(description="§17.9-2 target_symbol AST 靜態解析 helper")
    ap.add_argument("--root", required=True, help="snapshot 掛載點（唯讀，容器內 /target）")
    ap.add_argument("--symbol", required=True, help="符號路徑 module[.Class][.method]")
    ap.add_argument("--out", required=True, help="verdict JSON 輸出檔（canonical）")
    args = ap.parse_args()

    def emit(verdict, code):
        # canonical JSON：sort_keys + 緊湊分隔符 + 不轉義非 ASCII（§23-3、§5 canonical 慣例）
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(verdict, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return code

    symbol = args.symbol
    segs = symbol.split(".")
    if symbol == "" or any(seg == "" for seg in segs):
        return emit({"ok": False, "symbol": symbol,
                     "reason": "bad_symbol", "detail": "符號路徑含空段"}, 1)
    if not all(seg.isidentifier() for seg in segs):
        # 非 identifier 段一律拒收：同時封死以符號段夾帶「/」「..」等路徑字元。
        return emit({"ok": False, "symbol": symbol,
                     "reason": "bad_symbol", "detail": "符號段須為 Python 識別字"}, 1)

    # module 段對映檔案：由最長前綴往回試（pkg/mod.py 檔案形式、pkg/__init__.py 套件形式）。
    root = Path(args.root)
    module_path = None
    module_name = None
    rest = None
    for k in range(len(segs), 0, -1):
        base = root
        for part in segs[:k]:
            base = base / part
        for cand in (base.parent / (base.name + ".py"), base / "__init__.py"):
            if cand.is_file():
                module_path = cand
                module_name = ".".join(segs[:k])
                rest = segs[k:]
                break
        if module_path is not None:
            break
    if module_path is None:
        return emit({"ok": False, "symbol": symbol,
                     "reason": "module_not_found",
                     "detail": "module %r 在 snapshot 中不存在" % segs[0]}, 1)

    # 只 parse、不 import、不執行（§17.9-2）。
    try:
        tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
        return emit({"ok": False, "symbol": symbol,
                     "reason": "parse_error", "detail": str(exc)[:500]}, 2)

    if not rest:
        # 純 module 符號：module 檔存在即命中。
        return emit({"ok": True, "symbol": symbol, "module": module_name,
                     "path": [], "kind": "module", "line": 1}, 0)

    node = resolve(tree.body, rest)
    if node is None:
        return emit({"ok": False, "symbol": symbol, "module": module_name,
                     "reason": "symbol_not_found",
                     "detail": "符號 %r 在 module %r 中未以 AST 解析到" % (".".join(rest), module_name)}, 1)

    return emit({"ok": True, "symbol": symbol, "module": module_name,
                 "path": rest, "kind": _kind_of(node), "line": getattr(node, "lineno", 1)}, 0)


if __name__ == "__main__":
    raise SystemExit(main())