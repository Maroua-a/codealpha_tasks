"""
CodeAlpha_SecureCodeReview — remediated version.

This file shows the corrected code for each vulnerability found
in vulnerable_app.py. 

See secure_code_review.md for the full
explanation of each finding.
"""

import sqlite3
import subprocess
import shlex
import os

from flask import Flask, request, render_template_string
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# FIX 1: Load secret key from environment, never hardcode it.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set")

DB_PATH = os.environ.get("DB_PATH", "notes.db")


def get_db():
    return sqlite3.connect(DB_PATH)

@app.route("/", methods=["GET"])
def home():
    return """
    <h1>CodeAlpha Secure Notes App</h1>
    <p>This is the remediated (secure) version of the app audited in security_review.md.</p>
    <ul>
        <li>POST /login   >> form fields: username, password</li>
        <li>GET /note?content=...   >> displays a note (input is escaped)</li>
        <li>GET /ping?host=...  >> pings a host (input is validated)</li>
        <li>POST /register   >> form fields: username, password</li>
    </ul>
    """


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()

    # FIX 2: Parameterized query prevents SQL injection.
    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()

    # FIX 5: Verify against a salted hash (see register()).
    if row and check_password_hash(row[0], password):
        return "Login successful"
    return "Login failed"


@app.route("/note", methods=["GET"])
def show_note():
    note_content = request.args.get("content", "")

    # FIX 3: Escape user input before rendering as HTML.
    template = f"<h1>My note</h1><p>{escape(note_content)}</p>"
    return render_template_string(template)


ALLOWED_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789.-")


@app.route("/ping", methods=["GET"])
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    # FIX 4: Strict allow-list validation + no shell=True,
    # and pass arguments as a list so nothing reaches a shell.
    if not host or not set(host.lower()) <= ALLOWED_HOST_CHARS:
        return "Invalid host", 400

    result = subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        timeout=5,
    )
    return result.stdout


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # FIX 5: Strong, salted password hashing (PBKDF2 via Werkzeug)
    password_hash = generate_password_hash(password)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    return "Registered"


# FIX 6: /debug route removed entirely — never expose environmentt
# variables, secrets, or internal paths over HTTP, even in dev


if __name__ == "__main__":
    # FIX 7: Debug mode and bind address controlled by environment,
    # defaulting to safe values. Never run debug=True in production.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", debug=debug_mode)