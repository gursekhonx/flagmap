const express = require("express");
const fs = require("fs");
const app = express();
let db;

app.get("/search", (req, res) => {
  const name = req.query.name;
  // parameterized query — placeholder, not string concatenation
  db.query("SELECT * FROM users WHERE name = ?", [name]);  // safe: SQL Injection
  res.send("ok");
});

app.get("/go", (req, res) => {
  // same-origin relative redirect — not an open redirect
  res.redirect("/dashboard");  // safe: Open Redirect
});

app.get("/calc", (req, res) => {
  // NOTE: eval() is intentionally flagged ("possible" confidence) by a
  // generic regex regardless of whether the argument is tainted today —
  // not tested as a false-positive case here, that's by design.
  res.send(String(eval("1 + 1")));
});

app.get("/proxy_safe", async (req, res) => {
  // fixed, non-tainted URL
  const upstream = await fetch("https://api.example.com/status");  // safe: SSRF (Server-Side Request Forgery)
  res.send(await upstream.text());
});

app.get("/read_safe", (req, res) => {
  // cross-line sanitizer case: parseInt() guarantees p can only ever be a
  // plain number by the time it reaches readFileSync() — deliberately NOT
  // on the same line as req.query, so this is a pure AST-taint-tracking
  // test (patterns.py's same-line fs.readFileSync(...req.query...) regex
  // can't match here, since req.query never appears on the sink line).
  let p = req.query.fname;
  p = parseInt(p);
  res.send(fs.readFileSync(p));  // safe: Path Traversal / LFI
});

// Single-family algorithms allowlist — the new JWT "algorithm confusion"
// rule only fires when BOTH an HMAC family (HS256/384/512) and an
// asymmetric family (RS/ES/PS 256/384/512) appear in the same allowlist;
// a single algorithm, however it's spelled, must never trip it.
const verifyAlgSafe = { algorithms: ['RS256'] };  // safe: JWT / Auth Token Weakness
const verifyAlgSafeHs = { algorithms: ["HS256", "HS512"] };  // safe: JWT / Auth Token Weakness

// Correct redirect-target validation: checks .protocol as well as
// .hostname on the same line, so the new hostname-only-check rule must
// not fire here — a javascript:// payload would be rejected by this
// .protocol comparison before the .hostname comparison even matters.
function sendBrowserRedirectResponseSafe(res, redirectTo) {
  const defaultRedirect = `${process.env.BASE_URL}/flag/`;
  const redirectUrl = new URL(redirectTo, process.env.BASE_URL);
  const expected = new URL(defaultRedirect);
  if (redirectUrl.protocol !== expected.protocol || redirectUrl.hostname !== expected.hostname) {  // safe: Open Redirect
    redirectTo = defaultRedirect;
  }
  res.send(`<script>window.location = "${redirectTo}";</script>`);
}

// Escaped before use as a $regex pattern.
const safeHits = await Files.find({ filename: { $regex: _.escapeRegExp(req.query.search) } });  // safe: NoSQL Injection

// Tagged templates (postgres.js / Bun SQL / secure-sqlite / Prisma) bind
// every ${...} as a parameter — mirrors LA CTF 2025 "arclbroth" and 2026
// "bobles-and-narnes".
const existing = sql`SELECT * FROM users WHERE username=${username}`;  // safe: SQL Injection
const potentialUsers = await db`SELECT * FROM users WHERE username=${username}`;  // safe: SQL Injection
const rows = await prisma.$queryRaw`SELECT * FROM users WHERE id=${id}`;  // safe: SQL Injection

// Global replacement — /g regex or replaceAll — escapes every occurrence.
function htmlEscapeSafe(s) {
  s = s.replace(/&/g, "&amp;");  // safe: Cross-Site Scripting (XSS)
  s = s.replaceAll("<", "&lt;");  // safe: Cross-Site Scripting (XSS)
  return s;
}

// Random (v4) UUIDs.
const { v4: uuid4 } = require('uuid');  // safe: Insecure Randomness
const reqId = uuid.v4();  // safe: Insecure Randomness
