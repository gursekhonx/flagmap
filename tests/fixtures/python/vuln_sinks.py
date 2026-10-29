import os
import pickle
import sqlite3
import ldap
from lxml import etree
from reportlab.platypus import Paragraph
from urllib.request import urlopen
from flask import Flask, request, render_template_string, redirect, send_file

app = Flask(__name__)
conn = sqlite3.connect("db.sqlite3")
cur = conn.cursor()
ldap_conn = ldap.initialize("ldap://localhost")


@app.route("/search")
def search():
    name = request.args.get("name")
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # ruleid: SQL Injection
    return "ok"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # ruleid: Command Injection
    return "ok"


@app.route("/read")
def read_file():
    fname = request.args.get("fname")
    return open(fname).read()  # ruleid: Path Traversal / LFI


@app.route("/dl")
def download():
    fname = request.args.get("fname")
    return send_file(fname)  # ruleid: Path Traversal / LFI


@app.route("/tpl")
def tpl():
    name = request.args.get("name")
    return render_template_string("Hello " + name)  # ruleid: Server-Side Template Injection (SSTI)


@app.route("/go")
def go():
    url = request.args.get("url")
    return redirect(url)  # ruleid: Open Redirect


@app.route("/load")
def load():
    data = request.args.get("data")
    return str(pickle.loads(data))  # ruleid: Unsafe Deserialization


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))  # ruleid: Command Injection / RCE


def run_query(q):
    cur.execute(q)  # ruleid: SQL Injection


@app.route("/search2")
def search2():
    # one-hop interprocedural: `q` is tainted at the CALL SITE below, which
    # must seed run_query's own `q` parameter for the line above to fire.
    name = request.args.get("name")
    run_query(f"SELECT * FROM users WHERE name = '{name}'")


@app.route("/typed/<int:user_id>")
def typed_route(user_id: int):
    # route path params are just as attacker-controlled as request.args
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")  # ruleid: SQL Injection
    return "ok"


class UserController:
    # one-hop interprocedural through a CLASS METHOD: `self` is the
    # implicit receiver, excluded from self.run_query(...)'s call-site
    # arguments (as it always is at any Python call site) — the seeding
    # logic has to drop `self` from run_query's own parameter list too, or
    # every real parameter's index is off by one and seeding silently
    # fails for every method in the codebase, not just this one.
    @app.route("/search3")
    def search3(self):
        name = request.args.get("name")
        self.run_query(f"SELECT * FROM users WHERE name = '{name}'")

    def run_query(self, q):
        cur.execute(q)  # ruleid: SQL Injection


@app.route("/ldap")
def ldap_login():
    uid = request.args.get("uid")
    filterstr = "(uid=" + uid + ")"
    ldap_conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filterstr)  # ruleid: LDAP Injection


@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    return urlopen(target).read()  # ruleid: SSRF (Server-Side Request Forgery)


@app.route("/xxe", methods=["POST"])
def xxe():
    # Deliberately no safe-parsing guard anywhere in this file — see the
    # guarded counterpart in clean_sinks.py. (Careful: don't restate any
    # of xxe_guard.py's actual marker strings in this comment, or this
    # file would suppress its own finding — exactly the self-referential
    # trap loot.py's docstring fell into earlier.)
    data = request.data
    return str(etree.fromstring(data))  # ruleid: XML External Entity (XXE)


@app.route("/pdf", methods=["POST"])
def pdf_cross_line():
    # the realistic shape: tainted several lines before the sink, same as
    # the actual CyberSci-style PDF-generator challenge that prompted this
    # check — Paragraph() is called with no inline hint it's tainted.
    title = request.form.get("title", "")
    return str(Paragraph(title, None))  # ruleid: ReportLab Paragraph Injection (CVE-2023-33733)


@app.route("/pdf_inline", methods=["POST"])
def pdf_inline():
    # same-line backstop case, covered by the regex layer even without
    # tree-sitter-python installed.
    return str(Paragraph(request.form.get("title", ""), None))  # ruleid: ReportLab Paragraph Injection (CVE-2023-33733)
