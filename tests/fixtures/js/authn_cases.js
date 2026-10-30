const express = require("express");
const bcrypt = require("bcrypt");
const app = express();

app.post("/login", (req, res) => {
  // grants a session for whatever username was supplied, with no
  // credential check of any kind anywhere in this handler at all — the
  // same gap as python/authn_cases.py's login_vuln (see its comment for
  // why this one doesn't name the missing check by its usual term either).
  const username = req.body.username;
  req.session.userId = username;  // ruleid: Missing Authentication Check
  res.send("ok");
});

app.post("/login/safe", async (req, res) => {
  const username = req.body.username;
  const pass = req.body.password;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(pass, user.passwordHash))) {
    return res.status(401).send("invalid credentials");
  }
  req.session.userId = user.id;  // safe: Missing Authentication Check
  res.send("ok");
});

app.post("/refresh", (req, res) => {
  // grants a new session, but never reads a username/identity claim at
  // all — a different shape than logging in.
  req.session.touched = Date.now();  // safe
});
