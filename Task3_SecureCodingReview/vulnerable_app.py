"""
CodeAlpha_SecureCodeReview — sample application under audit.

This is a small Flask app for a fictional "user notes" service.
It intentionally contains several common vulnerabilities so that
a secure code review can be demonstrated against it.

See security_review.md for the full audit and the fixed 
version at (secure_app.py) for corrected code.
"""

import sqlite3
import subprocess
import hashlib
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)


# VULNERABILITY 1: Hardcoded secret key 
app.secret_key = "supersecret123"

DB_PATH = "notes.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route("/", methods=["GET"])
def home():
    return """
    <h1>CodeAlpha Notes App (vulnerable version ; for audit only)</h1>
    <p>Do not deploy this. See security_review.md and secure_app.py.</p>
    <ul>
        <li>POST /register   >> form fields: username, password</li>
        <li>POST /login   >> form fields: username, password</li>
        <li>GET /note?content=...   >> displays a note (NOT escaped, XSS demo)</li>
        <li>GET /ping?host=...  >> pings a host (NOT validated, command injection demo)</li>
        <li>GET /debug   >> leaks environment variables (do not expose in real apps)</li>
    </ul>
    """


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()

    # VULNERABILITY 2: SQL Injection 
    # User input is concatenated directly into the SQL string.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return "Login successful"
    return "Login failed"


@app.route("/note", methods=["GET"])
def show_note():
    note_content = request.args.get("content", "")

    # VULNERABILITY 3: Reflected XSS 
    # User input is rendered directly into HTML without escaping.
    template = f"<h1>My note</h1><p>{note_content}</p>"
    return render_template_string(template)


@app.route("/ping", methods=["GET"])
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    # VULNERABILITY 4: OS Command Injection 
    # User-controlled input is passed straight too the shell.
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout


def hash_password(password):
    # VULNERABILITY 5: Weak hashing algorithm (MD5, no salt)
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # (VULNERABILITY 5)
    hashed = hash_password(password)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')"
    )
    conn.commit()
    return "Registered"


@app.route("/debug")
def debug_info():
    # VULNERABILITY 6: Sensitive information disclosure
    return {
        "env": dict(os.environ),
        "db_path": DB_PATH,
        "secret_key": app.secret_key,
    }


if __name__ == "__main__":
    # VULNERABILITY 7: Debug mode enabled + bound to all interfaces
    app.run(host="0.0.0.0", debug=True)