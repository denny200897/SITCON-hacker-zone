# fixture: vuln-sqli-001 —— SPEC §22 M0b
# Flask + sqlite；UserRepo.find_by_name 以 f-string 拼接（error-based SQLi）。
# 這是被審查的目標程式碼（沙箱內執行、唯讀掛載）。
import sqlite3

from flask import Flask, request

app = Flask(__name__)

DB_PATH = "/aegis/out/app.sqlite3"


class UserRepo:
    def __init__(self, db_path=DB_PATH):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
        )
        self.conn.commit()

    def find_by_name(self, name):
        # f-string 拼接（sink）：name 未參數化
        cur = self.conn.execute(f"SELECT id, name FROM users WHERE name = '{name}'")
        return cur.fetchall()

    def seed(self, names):
        for n in names:
            self.conn.execute("INSERT INTO users (name) VALUES (?)", (n,))
        self.conn.commit()


@app.route("/healthz")
def healthz():
    return {"ok": True}


@app.route("/users/<name>", methods=["GET"])
def get_user(name):
    repo = UserRepo()
    rows = repo.find_by_name(name)
    return {"users": [r[1] for r in rows]}


if __name__ == "__main__":
    repo = UserRepo()
    repo.seed(["alice", "bob"])
    app.run(host="127.0.0.1", port=8000)