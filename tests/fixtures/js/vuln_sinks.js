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
