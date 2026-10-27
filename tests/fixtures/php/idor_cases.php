<?php

function viewOrder() {
    $orderId = $_GET['order_id'];  // ruleid: Missing Authorization / IDOR
    $stmt = $conn->prepare("SELECT * FROM orders WHERE id = ?");
    return $stmt->first($orderId);
}

function viewOrderSafe() {
    $orderId = $_GET['order_id'];
    // ownership folded directly into the query chain.
    return Order::where('id', $orderId)->where('user_id', Auth::id())->first();  // safe: Missing Authorization / IDOR
}

function logAccess() {
    // id is read but never reaches a lookup/mutation call.
    $orderId = $_GET['order_id'];
    error_log("access attempt for order " . $orderId);  // safe
}

class OrderController {
    // id arrives as a bound route parameter (Laravel-style route-model
    // binding) — no $_GET/request-object extraction call anywhere, just
    // the parameter itself.
    public function show($orderId) {  // ruleid: Missing Authorization / IDOR
        return Order::find($orderId);
    }

    public function showSafe($orderId) {
        return Order::where('id', $orderId)->where('user_id', Auth::id())->first();  // safe: Missing Authorization / IDOR
    }
}
