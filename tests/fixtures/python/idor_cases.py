from flask import Flask, request, session

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
def view_order_vuln(order_id):
    # no ownership check anywhere in this function — any logged-in user
    # can view any order by id.
    order_id = request.args.get("order_id")  # ruleid: Missing Authorization / IDOR
    return Order.query.filter_by(id=order_id).first()


@app.route("/orders/<int:order_id>/edit")
@login_required
def edit_order_vuln(order_id):
    # a bare @login_required proves the request is from SOME logged-in
    # user, not that it's the right user for THIS order — must still fire.
    order_id = request.args.get("order_id")  # ruleid: Missing Authorization / IDOR
    return Order.query.filter_by(id=order_id).update({"status": "shipped"})


@app.route("/orders/<int:order_id>/safe")
@login_required
def view_order_safe(order_id):
    order_id = request.args.get("order_id")
    # ownership check baked directly into the query — current_user.id is
    # part of the filter, not just existence-by-id.
    return Order.query.filter_by(id=order_id, user_id=current_user.id).first()  # safe: Missing Authorization / IDOR


@app.route("/orders/<int:order_id>/safe2")
@login_required
def view_order_safe2(order_id):
    order_id = request.args.get("order_id")
    order = Order.query.filter_by(id=order_id).first()
    # explicit, separate ownership compare rather than query-embedded.
    if order.user_id != current_user.id:
        abort(403)
    return order  # safe: Missing Authorization / IDOR


@app.route("/orders/<int:order_id>/log")
def log_order_access(order_id):
    # id is read but never reaches a lookup/mutation call — nothing to see.
    order_id = request.args.get("order_id")
    app.logger.info("access attempt for order %s", order_id)  # safe
