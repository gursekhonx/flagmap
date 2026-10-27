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
