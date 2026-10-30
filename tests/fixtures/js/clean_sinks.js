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
