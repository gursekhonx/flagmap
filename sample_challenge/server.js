const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const app = express();

app.get("/run", (req, res) => {
  exec(`echo ${req.query.cmd}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/read", (req, res) => {
  const data = fs.readFileSync(req.query.path);
  res.send(data);
});

app.get("/render", (req, res) => {
  const tpl = nunjucks.renderString(req.query.tpl, {});
  res.send(tpl);
});
