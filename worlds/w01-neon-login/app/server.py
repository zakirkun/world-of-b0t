"""
Neon Login :: World Of B0t challenge 01
Category: Web | Difficulty: easy | Vuln: SQL injection auth bypass
"""
import os
import sqlite3
import html

from flask import Flask, request, session, redirect, url_for, g

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB = "/tmp/neon.db"
FLAG = os.environ.get("W0B_FLAG", "hex4b0t{missing_flag}")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            secret TEXT
        );
        """
    )
    # The flag lives in the admin's "secret" column, reachable only via SQLi.
    conn.execute(
        "INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)",
        ("admin", "N3on_Gr1d_Adm1n!", "admin", FLAG),
    )
    conn.execute(
        "INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)",
        ("guest", "guest", "user", "nothing here"),
    )
    conn.commit()
    conn.close()


@app.teardown_appcontext
def close(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: string interpolation into SQL.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            row = db().execute(query).fetchone()
        except sqlite3.Error as e:
            row = None
            error = f"SQL error: {e}"

        if row:
            session["user"] = row["username"]
            session["role"] = row["role"]
            return redirect(url_for("dashboard"))
        if not error:
            error = "Access denied."

    return render_login(error)


@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_dashboard(session.get("user"), session.get("role"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="lab" content="w01">
<title>NEON LOGIN</title>
<style>
 body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#05050c;
   color:#cfefff;font:14px/1.5 "SF Mono",Consolas,monospace}}
 .box{{width:min(420px,92vw);padding:34px;border:1px solid #10384a;border-radius:14px;
   background:linear-gradient(180deg,#0a0a16,#07070f);
   box-shadow:0 0 40px rgba(0,240,255,.12),inset 0 0 60px rgba(0,240,255,.03)}}
 h1{{margin:0 0 4px;font-size:24px;letter-spacing:4px;color:#00f0ff;
   text-shadow:0 0 12px rgba(0,240,255,.7)}}
 .sub{{color:#5d7285;font-size:11px;letter-spacing:2px;margin-bottom:22px}}
 label{{display:block;font-size:11px;letter-spacing:1.5px;color:#5d7285;margin:14px 0 6px}}
 input{{width:100%;padding:11px 12px;border-radius:6px;background:#050510;color:#cfefff;
   border:1px solid #16324a;box-sizing:border-box}}
 input:focus{{outline:none;border-color:#00f0ff;box-shadow:0 0 0 3px rgba(0,240,255,.12)}}
 button{{width:100%;margin-top:20px;padding:12px;border-radius:6px;cursor:pointer;
   background:rgba(0,240,255,.1);border:1px solid #00f0ff;color:#00f0ff;
   letter-spacing:2px;font:inherit}}
 button:hover{{background:rgba(0,240,255,.2);box-shadow:0 0 18px rgba(0,240,255,.4)}}
 .err{{margin-top:16px;color:#ff2e97;font-size:12px;white-space:pre-wrap}}
 .hint{{margin-top:22px;color:#3d4d5c;font-size:11px;line-height:1.7}}
 code{{color:#ffe600}}
 .flag{{margin-top:18px;padding:14px;border:1px dashed #39ff88;border-radius:8px;
   color:#39ff88;word-break:break-all;background:rgba(57,255,136,.05)}}
 a{{color:#00f0ff}}
</style></head><body><div class="box">{body}</div></body></html>"""


def render_login(error):
    body = f"""
    <h1>NEON LOGIN</h1>
    <div class="sub">// world of b0t :: w01</div>
    <form method="post">
      <label>OPERATOR</label>
      <input name="username" autocomplete="off" spellcheck="false" autofocus>
      <label>PASSKEY</label>
      <input name="password" type="password" autocomplete="off">
      <button type="submit">AUTHENTICATE</button>
    </form>
    {f'<div class="err">{html.escape(error)}</div>' if error else ''}
    <div class="hint">
      guest / guest is a valid account.<br>
      The vault holds <code>secret</code>. Admin keeps it.
    </div>
    """
    return PAGE.format(body=body)


def render_dashboard(user, role):
    if role == "admin":
        row = None
        try:
            row = db().execute("SELECT secret FROM users WHERE role = 'admin'").fetchone()
        except sqlite3.Error:
            pass
        secret = row["secret"] if row else "unavailable"
        inner = f'<div class="flag">{html.escape(str(secret))}</div>'
    else:
        inner = (
            '<div class="hint">Cleared as a standard operator.<br>'
            "The vault is sealed to non-admin roles.</div>"
        )

    body = f"""
    <h1>GRID ACCESS</h1>
    <div class="sub">// authenticated as {html.escape(str(user))} [{html.escape(str(role))}]</div>
    {inner}
    <div class="hint"><a href="/logout">terminate session</a></div>
    """
    return PAGE.format(body=body)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
