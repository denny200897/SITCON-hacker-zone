"""Aegis SQL trace shim（pack 內容物；SPEC §17.3）。

以 PYTHONPATH=/aegis/pack 注入，sitecustomize 自動載入本檔。
Python 3.12 的 sqlite3.Cursor／Connection 為不可變 C 型別，無法直接 setattr
（實測 TypeError: cannot set 'execute' attribute of immutable type）；因此
改以 connect factory 子類別達成同一觀測面：sqlite3.connect 回傳
TracedConnection，其 cursor() 與 execute() 回 TracedCursor，把每次 execute
的完整 SQL 與參數寫到 /aegis/out/sql_trace.jsonl（observer 只收集，
不做任何成敗判定）。

Trace entry 欄位閉集（§17.3）：{"ts", "sql", "params", "error", "rows"}。
- rows 在 execute 時未知（cursor 尚未 fetch）；呼叫端實際 fetch 時補寫一筆
  帶 rows 的條目。rowcount_at_least oracle 掃描任何 rows >= threshold 的條目。
- 例外訊息正是 error-based oracle 的觀測對象：execute 拋例外時 error 記
  "類別: 訊息"，再原樣 raise（不改變呼叫端可見行為）。
- check_same_thread=False 為 witness 接線（wiring）的一部分：Flask 開發伺服器
  以多執行緒派發請求，目標 repo 的 connect 呼叫無法改動，由 shim 統一提供；
  這不改變 SQL 語意，也不影響 oracle 判定。

直攻與見證模式用同一個 shim；絕不修改目標 repo 或 witness 之外的任何檔案。
"""
import json
import os
import socket
import sqlite3
import threading
import time

_TRACE_PATH = os.environ.get("AEGIS_SQL_TRACE", "/aegis/out/sql_trace.jsonl")
_TRACE_LOCK = threading.Lock()


def _params_repr(params):
    if isinstance(params, (tuple, list)):
        return [repr(p) for p in params]
    if isinstance(params, dict):
        return {k: repr(v) for k, v in params.items()}
    return repr(params)


def _write(entry):
    try:
        with _TRACE_LOCK:
            with open(_TRACE_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 — shim 絕不能讓被觀測程式崩潰
        pass


def _log(sql, params, error, rows):
    _write({"ts": time.time(), "sql": sql, "params": _params_repr(params),
            "error": error, "rows": rows})


class TracedCursor(sqlite3.Cursor):
    """execute 路徑觀測：記 SQL／params／error，fetch 時補 rows。"""

    def execute(self, sql, params=()):
        try:
            result = super().execute(sql, params)
        except Exception as exc:  # noqa: BLE001
            _log(sql, params, f"{type(exc).__name__}: {exc}", None)
            raise
        self._last_aegis_sql = sql
        _log(sql, params, None, None)
        return result

    def executemany(self, sql, seq):
        try:
            return super().executemany(sql, seq)
        except Exception as exc:  # noqa: BLE001
            _log(sql, "<executemany>", f"{type(exc).__name__}: {exc}", None)
            raise

    def _rows_of(self, result, single):
        rows = (1 if result is not None else 0) if single else (
            len(result) if hasattr(result, "__len__") else None)
        sql = getattr(self, "_last_aegis_sql", None)
        if sql is not None:
            _write({"ts": time.time(), "sql": sql, "params": "<fetch>",
                    "error": None, "rows": rows})

    def fetchall(self):
        result = super().fetchall()
        self._rows_of(result, single=False)
        return result

    def fetchone(self):
        result = super().fetchone()
        self._rows_of(result, single=True)
        return result


class TracedConnection(sqlite3.Connection):
    """cursor／execute 一律回 TracedCursor，讓 SQL 觀測點生效。"""

    def cursor(self, *args, **kwargs):
        kwargs.setdefault("factory", TracedCursor)
        return super().cursor(*args, **kwargs)

    def execute(self, sql, params=()):
        cur = self.cursor()
        return cur.execute(sql, params)

    def executemany(self, sql, seq):
        cur = self.cursor()
        return cur.executemany(sql, seq)


def install():
    observer_addr = os.environ.get("AEGIS_OBSERVER_ADDR", "")
    if observer_addr:
        host, port = observer_addr.rsplit(":", 1)
        port = int(port)

        class ProxyCursor:
            def __init__(self, result):
                self._rows = result.get("rows", [])
                self._index = 0

            def fetchall(self):
                out = self._rows[self._index:]
                self._index = len(self._rows)
                return [tuple(row) for row in out]

            def fetchone(self):
                if self._index >= len(self._rows):
                    return None
                row = tuple(self._rows[self._index])
                self._index += 1
                return row

        class ProxyConnection:
            def __init__(self):
                self._closed = False

            def _request(self, sql, params=()):
                req = json.dumps({"op": "execute", "sql": sql,
                                  "params": list(params) if isinstance(params, (tuple, list)) else []})
                with socket.create_connection((host, port), timeout=10) as sock:
                    sock.sendall((req + "\n").encode("utf-8"))
                    data = b""
                    while not data.endswith(b"\n"):
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                result = json.loads(data.decode("utf-8"))
                if not result.get("ok"):
                    raise sqlite3.DatabaseError(result.get("error", "observer error"))
                return result

            def execute(self, sql, params=()):
                return ProxyCursor(self._request(sql, params))

            def executemany(self, sql, seq):
                last = ProxyCursor({"rows": []})
                for params in seq:
                    last = self.execute(sql, params)
                return last

            def commit(self):
                return None

            def rollback(self):
                return None

            def close(self):
                self._closed = True

            def cursor(self, *args, **kwargs):
                return self

        sqlite3.connect = lambda database, *args, **kwargs: ProxyConnection()
        return

    original_connect = sqlite3.connect

    def connect(database, *args, **kwargs):
        kwargs.setdefault("factory", TracedConnection)
        kwargs.setdefault("check_same_thread", False)
        return original_connect(database, *args, **kwargs)

    sqlite3.connect = connect


install()
