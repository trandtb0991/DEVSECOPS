import os
import re
import sqlite3
import subprocess

import yaml
from flask import Flask, abort, request

app = Flask(__name__)

# Khong dua secret thuc vao ma nguon.
API_TOKEN = os.environ.get("API_TOKEN", "")
DB_PATH = os.environ.get("DB_PATH", "/tmp/devsecops_lab.db")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


@app.route("/health")
def health():
    return "ok"


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)
        rows = conn.execute(
            "SELECT * FROM users WHERE name = ?", (name,)
        ).fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not HOST_RE.fullmatch(host):
        abort(400)
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return "Ping timed out", 504
    except subprocess.CalledProcessError:
        return "Ping failed", 502
    except FileNotFoundError:
        return "Ping command not installed", 500
    return result.stdout, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/config", methods=["POST"])
def load_config():
    return str(yaml.safe_load(request.data))


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=False)
