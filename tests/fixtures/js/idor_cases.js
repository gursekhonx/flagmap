const express = require("express");
const app = express();
let Order;

app.get("/orders/:orderId", (req, res) => {
  // no ownership check anywhere in this handler.
  const orderId = req.params.id;  // ruleid: Missing Authorization / IDOR
  res.send(Order.findById(orderId));
});

app.get("/orders/:orderId/edit", requireLogin, (req, res) => {
  // requireLogin alone proves authentication, not ownership — must still fire.
  const orderId = req.params.id;  // ruleid: Missing Authorization / IDOR
  res.send(Order.findById(orderId).update({ status: "shipped" }));
});

app.get("/orders/:orderId/safe", requireLogin, (req, res) => {
  const orderId = req.params.id;
  // ownership folded directly into the lookup filter.
  res.send(Order.findOne({ id: orderId, user_id: req.user.id }));  // safe: Missing Authorization / IDOR
});

app.get("/orders/:orderId/safe2", requireLogin, (req, res) => {
  const orderId = req.params.id;
  const order = Order.findById(orderId);
  // explicit, separate ownership compare.
  if (order.ownerId !== req.user.id) {
    return res.status(403).send("forbidden");
  }
  res.send(order);  // safe: Missing Authorization / IDOR
});

app.get("/orders/:orderId/log", (req, res) => {
  // id is read but never reaches a lookup/mutation call.
  const orderId = req.params.id;
  console.log("access attempt for order", orderId);  // safe
  res.send("ok");
});

app.post("/orders/:orderId/bypassable", requireLogin, (req, res) => {
  // owner_param_guard.py's motivating shape (see its module docstring,
  // found against OWASP Juice Shop's payment.ts/address.ts/wallet.ts):
  // this LOOKS like it checks ownership, but UserId's own value comes
  // from the request body, not the session — exactly as
  // attacker-controlled as orderId itself, so idor.py must still fire
  // here (and owner_param_guard.py upgrades it, though the regression
  // harness only asserts vuln_name presence, not confidence — see
  // owner_param_guard.py's module docstring and the Testing section for
  // why there's no separate fixture category for the upgrade itself).
  const orderId = req.params.id;  // ruleid: Missing Authorization / IDOR
  res.send(Order.findOne({ id: orderId, UserId: req.body.UserId }));
});
