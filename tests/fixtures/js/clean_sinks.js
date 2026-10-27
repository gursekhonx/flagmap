const express = require("express");
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
