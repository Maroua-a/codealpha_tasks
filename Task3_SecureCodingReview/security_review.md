# Secure Code Review Report

**Application audited:** `vulnerable_app.py` — a small Flask application for a fictional user notes service.
**Language / stack:** Python 3, Flask, SQLite
**Method:** Manual code review + static analysis using Bandit
**Reviewer:** Kachroud Maroua
**Date:** August 2026

---


## 1. Executive Summary

The application was reviewed manually, line by line, and also scanned with the Bandit security tool.

The review found **7 security vulnerabilities**. The vulnerabilities range from Medium to Critical risk.

The most serious problems are:

- SQL Injection
- OS Command Injection
- Hardcoded Secret Key

These problems could allow an attacker to access data, bypass security controls, or execute commands on the server.

A corrected version of the application is provided in `secure_app.py`.

| # | Vulnerability | Severity | CWE |

| 1 | Hardcoded secret key | High | CWE-798 |
| 2 | SQL Injection | Critical | CWE-89 |
| 3 | Reflected XSS | High | CWE-79 |
| 4 | OS Command Injection | Critical | CWE-78 |
| 5 | Weak password hashing (MD5, no salt) | High | CWE-916 |
| 6 | Sensitive information disclosure (`/debug`) | High | CWE-215 |
| 7 | Debug mode + insecure bind address | Medium | CWE-489 |

---

## 2. Static Analysis
Bandit was used as a static analysis tool.

The following commands were used:
pip install bandit
bandit -r vulnerable_app.py

Bandit detected several security problems in the application, including:
- use of subprocess with shell=True
- use of MD5 for password hashing
- hardcoded secret key
- possible SQL injection
- Flask debug mode
- binding the application to all network interfaces

Bandit did not detect every vulnerability found during the manual review. This shows why both manual code review and static analysis are useful.


---
## 3. Detailed Findings

### 3.1 SQL Injection ; `login()` and `register()` (Severity: Critical)
**Location:** 
`query = f"SELECT * FROM users WHERE username = '{username}'..."`
**Issue:** User-supplied `username`/`password` are concatenated directly into
SQL strings. An attacker can submit `username = "' OR '1'='1"` to bypass
authentication entirely, or extract/alter arbitrary data.
**Impact:** 
An attacker could:
bypass authentication
access data they should not access
modify database information
possibly delete data
**Fix:** Use parameterized SQL queries instead of building SQL commands with user input.
(`cursor.execute("... WHERE username = ?", (username,))`).
The ? keeps the user input separate from the SQL command.
see secure_app.py.

### 3.2 OS Command Injection :  `ping_host()` (Critical)
**Location:** 
`result = subprocess.run(f"ping -c 1 {host}", shell=True, ...)`
**Issue:** The ``host` value comes from the user and is directly included in a system command.
The application also uses:
shell=True
This means the input can be interpreted by the operating system shell.
**Impact:** An attacker could potentially execute unauthorized commands on the server.
This can lead to Full remote code execution and compromise of the server.
**Fix:** Never use `shell=True` with user input. Validate host against a
strict allow-list of characters, and pass arguments as a list to
`subprocess.run` so nothing is interpreted by a shell.

### 3.3 Hardcoded Secret Key (High)
**Location:** `app.secret_key = "supersecret123"`
**Issue:** The Flask secret key is directly written inside the source code.
If the source code is shared or uploaded to GitHub, anyone who can read the code can also see the secret key.
The secret key is used by Flask to protect session data.
**Impact:** A stolen secret key could allow an attacker to attack application sessions and increase their privileges.
**Fix:** Load the key from an environment variable or a secrets manager;
Example:
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

### 3.4 Reflected XSS : `show_note()` (High)
**Location:** `template = f"<h1>Your note</h1><p>{note_content}</p>"`
**Issue:** User input from the `content` query parameter is inserted into
HTML without escaping, This means that malicious HTML or JavaScript could be inserted into the page.
**Impact:** A malicious link could cause JavaScript to run in another user's browser.
This could be used for: phishing, changing page content, performing actions as the victim
**Fix:** Escape user input before putting it into HTML.


### 3.5 Weak Password Hashing (High)
**Location:** `hashlib.md5(password.encode()).hexdigest()`
**Issue:** The application uses MD5 to hash passwords.
MD5 is not suitable for storing passwords because it is too fast and is not designed for secure password storage.
**Impact:** Mass password compromise if the database leaks.
**Fix:** Use a password hashing function designed specifically for passwords.
The secure version uses Werkzeug: `generate_password_hash(password)`
This provides a much safer way to store and verify passwords.

### 3.6 Sensitive Information Disclosure : `/debug` (High)
**Location:** `debug_info()` returns `os.environ`, the DB path, and the
secret key as JSON, with no authentication.
**Issue:** Any unauthenticated visitor can retrieve environment variables
(which often contain other secrets, like API keys or DB credentials),
internal file paths, and the Flask secret key.
**Impact:** An attacker could obtain secrets, credentials, internal paths, or other information about the application.
This information could then be used for further attacks.
**Fix:** The best solution is to remove this endpoint from the deployed application.
The /debug route was removed from secure_app.py.

### 3.7 Debug Mode Enabled + Bind to All Interfaces (Medium)
**Location:** `app.run(host="0.0.0.0", debug=True)`
**Issue:** The application runs with: `debug=True` Debug mode should not be enabled in production. The application also uses: `0.0.0.0`. This makes the development server listen on all network interfaces instead of only the local machine.
**Impact:** Debug mode can expose sensitive debugging information and can create serious security risks.
Binding to all interfaces also increases network exposure.
**Fix:** Default `debug` to `False`, control it via an environment
variable for local dev only, and bind to `127.0.0.1` unless the app is
meant to be reachable externally (in which case use a production WSGI
server, not Flask's built-in dev server).

---

## 4. How to Run the Secure Version

Unlike vulnerable_app.py, secure_app.py will not start without a FLASK_SECRET_KEY environment variable — this is intentional (see Fix 1 in Section 3.3): the app refuses to run with a missing/hardcoded secret instead of falling back to an insecure default.

Before running, generate a random key and export it:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
# PowerShell:
$env:FLASK_SECRET_KEY = "<paste generated key here>"
# Linux/Mac:
export FLASK_SECRET_KEY="<paste generated key here>"

python secure_app.py
```

This variable only persists for the current terminal session and must be set again each time a new terminal is opened.

---

## 5. Recommendations Summary

1. **Never build SQL with string formatting/concatenation** — always use
   parameterized queries or an ORM.
2. **Never pass user input to a shell** — avoid `shell=True`; validate and
   use list-form `subprocess` calls.
3. **Keep secrets out of source code** — use environment variables or a
   secrets manager, and add `.env` / config files to `.gitignore`.
4. **Escape all user-controlled output** rendered as HTML, or rely on an
   auto-escaping template engine.
5. **Hash passwords with a dedicated algorithm** (bcrypt, scrypt, Argon2,
   or PBKDF2) — never MD5/SHA1 alone.
6. **Remove debug/diagnostic endpoints** before deployment, and never run
   with `debug=True` in production.
7. **Run static analysis regularly** (`bandit`, `semgrep`) as part of CI,
   so these classes of bugs are caught before merge.

---

## 6. Files
`vulnerable_app.py` — the original application containing the security vulnerabilities.
`secure_app.py` — the corrected version of the application.
`security_review.md` — this report.
`requirements.txt` — Python packages required for the project.