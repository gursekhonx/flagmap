import os
import sqlite3
import ldap
import defusedxml.ElementTree as etree
from reportlab.platypus import Paragraph
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


@app.route("/read_safe")
def read_file_safe():
    # cross-line sanitizer case: int() guarantees fname can only ever be a
    # plain integer by the time it reaches open() — deliberately NOT on the
    # same line as request.args.get(...), so this is a pure AST-taint-
    # tracking test, not something patterns.py's same-line regex for this
    # vuln could coincidentally pass on its own (that regex only matches
    # `open(os.path.join(..request..)` / `open(request.args[...]` shapes).
    fname = request.args.get("fname")
    fname = int(fname)
    return open(fname).read()  # safe: Path Traversal / LFI


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


@app.route("/xxe_safe", methods=["POST"])
def xxe_safe():
    # the call shape alone (`etree.fromstring(...)`) is exactly what
    # patterns.py's XXE regex matches on, same as the vulnerable case in
    # vuln_sinks.py — what's different here, and what xxe_guard.py must
    # pick up on, is the `defusedxml` import at the top of this file,
    # which makes this specific "etree" safe by construction.
    data = request.data
    return str(etree.fromstring(data))  # safe: XML External Entity (XXE)


@app.route("/pdf_safe")
def pdf_safe():
    # fixed, non-tainted text — exactly the call shape the ReportLab
    # Paragraph Injection check matches on, just with nothing attacker-
    # controlled reaching it.
    return str(Paragraph("Static Report Title", None))  # safe: ReportLab Paragraph Injection (CVE-2023-33733)


@app.route("/graphql_safe")
def graphql_safe():
    # A GraphQL client call, but the query is a single fixed literal with
    # no "+"/"%" construction at all — nothing for the GraphQL / Query
    # Injection check's own construction-site shape to match.
    query = "{ quote(id: 1) { id value } }"
    return query  # safe: GraphQL / Query Injection


def plain_concat_unrelated_name():
    # Plain "+" concatenation, but the assigned-to variable's name has
    # nothing GraphQL-shaped about it at all — must NOT fire just because
    # concatenation is happening somewhere in a Python file.
    greeting = "Hello, " + request.args.get("name", "")
    return greeting  # safe: GraphQL / Query Injection


# Hardcoded Secret in Source: read from the environment, not a literal —
# the whole point of the check is a literal RIGHT of "=", and this isn't
# one (os.environ.get(...) doesn't start with a quote character at all).
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-fallback-value")  # safe: Hardcoded Secret in Source

# A variable name with nothing secret-ish about it at all — must not
# fire just because SOME string gets assigned somewhere.
greeting_template = "hello there, friend"  # safe: Hardcoded Secret in Source

# aiohttp static route left at the default follow_symlinks=False — the
# resolved path is checked against the static root, so no finding.
aiohttp_app.add_routes([web.static('/files', './files')])  # safe: Path Traversal / LFI
aiohttp_app.add_routes([web.static('/files', './files', follow_symlinks=False)])  # safe: Path Traversal / LFI

# Lookup keys chosen by the code, only the value from the request — the
# client can't pick a relation or an operator. And a Mass Assignment-style
# constructor unpack is still Mass Assignment, not an ORM lookup leak.
chosen = Article.objects.filter(title__icontains=request.data.get("q", ""))  # safe: ORM Injection / Filter Leak
