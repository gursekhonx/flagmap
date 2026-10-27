package main

import "net/http"

func ShowOrder(w http.ResponseWriter, r *http.Request) {
	orderId := r.URL.Query().Get("order_id")  // ruleid: Missing Authorization / IDOR
	order := repo.FindById(orderId)
	_ = order
}

func ShowOrderSafe(w http.ResponseWriter, r *http.Request) {
	orderId := r.URL.Query().Get("order_id")
	// ownership folded directly into the lookup call.
	order := repo.FindByIdAndUserId(orderId, currentUser.ID)  // safe: Missing Authorization / IDOR
	_ = order
}

func LogAccess(w http.ResponseWriter, r *http.Request) {
	// id is read but never reaches a lookup/mutation call.
	orderId := r.URL.Query().Get("order_id")
	println("access attempt for order", orderId)  // safe
}
