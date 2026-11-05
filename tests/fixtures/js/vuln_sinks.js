const express = require("express");
const { exec, execSync } = require("child_process");
const fs = require("fs");
const app = express();
let db;

app.get("/search", (req, res) => {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'");  // ruleid: SQL Injection
  res.send("ok");
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host);  // ruleid: Command Injection
  res.send("ok");
});

app.get("/pingsync", (req, res) => {
  const host = req.query.host;
  execSync("ping -c 1 " + host);  // ruleid: Command Injection
  res.send("ok");
});

app.get("/read", (req, res) => {
  const fname = req.query.fname;
  res.send(fs.readFileSync(fname));  // ruleid: Path Traversal / LFI
});

app.get("/dl", (req, res) => {
  const fname = req.query.fname;
  res.sendFile(fname);  // ruleid: Path Traversal / LFI
});

app.get("/go", (req, res) => {
  const url = req.query.url;
  res.redirect(url);  // ruleid: Open Redirect
});

app.get("/calc", (req, res) => {
  const expr = req.query.expr;
  res.send(String(eval(expr)));  // ruleid: Command Injection / RCE
});

function runQuery(q) {
  db.query(q);  // ruleid: SQL Injection
}

app.get("/search2", (req, res) => {
  // one-hop interprocedural: tainted at the call site, must seed runQuery's
  // own `q` parameter for the sink inside runQuery to fire.
  const name = req.query.name;
  runQuery("SELECT * FROM users WHERE name = '" + name + "'");
});

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const upstream = await fetch(target);  // ruleid: SSRF (Server-Side Request Forgery)
  res.send(await upstream.text());
});

function renderUserBio(bio) {
  // control case for vendor_guard.py: this file's own name ("vuln_sinks.js")
  // matches none of vendor_guard.is_vendor_file()'s signals, so the bare
  // .innerHTML= rule must still fire here exactly as before — see
  // tests/fixtures/js/jquery.fake-plugin.min.js for the suppressed case.
  document.getElementById("bio").innerHTML = bio;  // ruleid: Cross-Site Scripting (XSS) — DOM-based
}

// Mirrors DownUnderCTF 2024's real "i-am-confusion" web challenge
// (src/main-app/server.js) almost verbatim: signs with RS256 only, but
// verifies with an allowlist that also accepts HS256 against the same
// public-key variable — the classic JWT "algorithm confusion" attack,
// since an RSA public key isn't secret and can be replayed as an HMAC key.
const verifyAlg = { algorithms: ['HS256','RS256'] };  // ruleid: JWT / Auth Token Weakness
app.get("/admin.html", (req, res) => {
  jwt.verify(req.cookies['auth'], publicKey, verifyAlg, (err, decoded) => {
    if (!err && decoded['user'] == 'admin') res.sendFile("admin.html");
  });
});

// Mirrors DownUnderCTF 2024's real "waifu" web challenge
// (src/app/src/utils/response.ts) almost verbatim: the allowlist check
// compares only .hostname, never .protocol, so "javascript://<same
// hostname>/<payload>" sails through with the same hostname as the real
// app, then gets assigned to window.location — script execution, not
// just an open redirect.
function sendBrowserRedirectResponse(res, redirectTo) {
  const defaultRedirect = `${process.env.BASE_URL}/flag/`;
  const redirectUrl = new URL(redirectTo, process.env.BASE_URL);
  if ((redirectUrl.hostname ?? '') !== new URL(defaultRedirect).hostname) {  // ruleid: Open Redirect
    redirectTo = defaultRedirect;
  }
  res.send(`<script>window.location = "${redirectTo}";</script>`);
}

// Same shape in JS, with the unquoted-key spelling Mongo drivers accept.
const hits = await Files.find({ filename: { $regex: req.query.search } });  // ruleid: NoSQL Injection

// Untagged template literal building SQL — still SQL injection.
const rawQuery = `SELECT * FROM users WHERE username=${username}`;  // ruleid: SQL Injection

// First-occurrence-only HTML escaping — mirrors LA CTF 2026 "job-board".
function htmlEscape(s) {
  s = s.replace("&", "&amp;");  // ruleid: Cross-Site Scripting (XSS)
  s = s.replace("<", "&lt;");  // ruleid: Cross-Site Scripting (XSS)
  s = s.replace('\'', "&#x27;");  // ruleid: Cross-Site Scripting (XSS)
  return s;
}

// Time-based v1 UUIDs as session ids — mirrors LA CTF 2023 "uuid-hell".
const sessionId = uuid.v1({ node: [0x67, 0x69, 0x6e, 0x6b, 0x6f, 0x69], clockseq: 0x2a64 });  // ruleid: Insecure Randomness
const { v1: makeId } = require('uuid');  // ruleid: Insecure Randomness

// Destructured request fields are tainted too (v1.51.0) — mirrors LA CTF
// 2026 "lactf-invoice-generator": request fields -> HTML -> rendered by a
// server-side headless browser, which then fetches whatever it references.
app.post("/generate-invoice", async (req, res) => {
  const { name, item: lineItem } = req.body;
  const invoiceHTML = buildInvoice(name, lineItem);
  await page.setContent(invoiceHTML, { waitUntil: "load" });  // ruleid: SSRF (Server-Side Request Forgery)
  const { cmd = "ls" } = req.query;
  exec(cmd);  // ruleid: Command Injection
});
