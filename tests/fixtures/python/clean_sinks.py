import os
import sqlite3
import ldap
from urllib.request import urlopen
from flask import Flask, request, redirect

app = Flask(__name__)
conn = sqlite3.connect("db.sqlite3")
cur = conn.cursor()
ldap_conn = ldap.initialize("ldap://localhost")


@app.route("/search")
def search():
    name = request.args.get("name")
    # parameterized query — the tainted value never touches the SQL string
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # safe: SQL Injection
    return "ok"


@app.route("/ping")
def ping():
    # fixed, non-tainted argument
    os.system("echo hello")  # safe: Command Injection
    return "ok"


@app.route("/go")
def go():
    # same-origin relative redirect — not an open redirect
    return redirect("/dashboard")  # safe: Open Redirect


@app.route("/calc")
def calc():
    # NOTE: eval() is intentionally flagged ("possible" confidence) by a
    # generic regex regardless of whether the argument is tainted today —
    # not tested as a false-positive case here, that's by design.
    return str(eval("1 + 1"))


@app.route("/ldap_safe")
def ldap_safe():
    # fixed, non-tainted filter string
    ldap_conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=admin)")  # safe: LDAP Injection


@app.route("/proxy_safe")
def proxy_safe():
    # fixed, non-tainted URL
    return urlopen("https://api.example.com/status").read()  # safe: SSRF (Server-Side Request Forgery)
