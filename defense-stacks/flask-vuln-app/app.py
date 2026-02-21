import json
import os
import sqlite3
import subprocess

import jinja2
from flask import Flask, redirect, request

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-aegis-test"
app.config["DEBUG"] = True

DB_PATH = ":memory:"
_db_conn = None


def get_db():
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(DB_PATH)
        _db_conn.row_factory = sqlite3.Row
        _db_conn.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)"
        )
        _db_conn.execute(
            "INSERT INTO users (username, email, role) VALUES "
            "('admin', 'admin@example.com', 'admin')"
        )
        _db_conn.execute(
            "INSERT INTO users (username, email, role) VALUES "
            "('alice', 'alice@example.com', 'user')"
        )
        _db_conn.execute(
            "INSERT INTO users (username, email, role) VALUES "
            "('bob', 'bob@example.com', 'user')"
        )
        _db_conn.commit()
    return _db_conn


@app.route("/health")
def health():
    return json.dumps({"status": "ok"}), 200, {"Content-Type": "application/json"}


@app.route("/api/users")
def get_users():
    """SQL Injection: string concatenation into SQL query."""
    user_id = request.args.get("id", "")
    db = get_db()
    query = "SELECT * FROM users WHERE id = " + user_id
    try:
        cursor = db.execute(query)
        rows = [dict(row) for row in cursor.fetchall()]
        return json.dumps(rows), 200, {"Content-Type": "application/json"}
    except Exception as exc:
        return json.dumps({"error": str(exc)}), 500, {"Content-Type": "application/json"}


@app.route("/api/search")
def search():
    """Cross-Site Scripting: reflected user input without escaping."""
    query = request.args.get("q", "")
    html = "<html><body><h1>Search results for: " + query + "</h1></body></html>"
    return html, 200, {"Content-Type": "text/html"}


@app.route("/api/exec", methods=["POST"])
def exec_cmd():
    """Command Injection: user input passed to shell."""
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return json.dumps({"output": output.decode("utf-8", errors="replace")}), 200, {
            "Content-Type": "application/json"
        }
    except subprocess.CalledProcessError as exc:
        return json.dumps({"error": exc.output.decode("utf-8", errors="replace")}), 500, {
            "Content-Type": "application/json"
        }
    except Exception as exc:
        return json.dumps({"error": str(exc)}), 500, {"Content-Type": "application/json"}


@app.route("/api/files")
def read_file():
    """Path Traversal: user-controlled path passed to open()."""
    file_path = request.args.get("path", "")
    try:
        with open(file_path) as f:
            content = f.read()
        return content, 200, {"Content-Type": "text/plain"}
    except Exception as exc:
        return json.dumps({"error": str(exc)}), 404, {"Content-Type": "application/json"}


@app.route("/api/render")
def render_template_injection():
    """SSTI: user input rendered as Jinja2 template."""
    template_str = request.args.get("template", "")
    try:
        rendered = jinja2.Template(template_str).render()
        return rendered, 200, {"Content-Type": "text/html"}
    except Exception as exc:
        return json.dumps({"error": str(exc)}), 500, {"Content-Type": "application/json"}


@app.route("/api/config")
def config():
    """Security Misconfiguration: debug mode and secret key exposed."""
    return json.dumps({
        "debug": app.config["DEBUG"],
        "secret_key": app.secret_key,
        "env": dict(os.environ),
    }), 200, {"Content-Type": "application/json"}


@app.route("/api/redirect")
def open_redirect():
    """Open Redirect: user-controlled redirect target."""
    url = request.args.get("url", "/")
    return redirect(url)


if __name__ == "__main__":
    get_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
