class OrdersController
  def show
    order_id = params[:order_id]  # ruleid: Missing Authorization / IDOR
    @order = Order.find(order_id)
  end

  def show_safe
    order_id = params[:order_id]
    # ownership folded directly into the lookup filter.
    @order = Order.where(id: order_id, user_id: current_user.id).first  # safe: Missing Authorization / IDOR
  end

  def log_access
    # id is read but never reaches a lookup/mutation call.
    order_id = params[:order_id]
    Rails.logger.info("access attempt for order #{order_id}")  # safe
  end
end
