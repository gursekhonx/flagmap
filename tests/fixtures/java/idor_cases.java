import javax.servlet.http.HttpServletRequest;

public class OrderController {
    private Repository repo;

    public Order show(HttpServletRequest request) {
        String orderId = request.getParameter("order_id");  // ruleid: Missing Authorization / IDOR
        return repo.findById(orderId);
    }

    public Order showSafe(HttpServletRequest request) {
        String orderId = request.getParameter("order_id");
        // ownership folded directly into the lookup call.
        return repo.findByIdAndUserId(orderId, currentUser.getId());  // safe: Missing Authorization / IDOR
    }

    public void logAccess(HttpServletRequest request) {
        // id is read but never reaches a lookup/mutation call.
        String orderId = request.getParameter("order_id");
        System.out.println("access attempt for order " + orderId);  // safe
    }

    // admin-only route: no per-user ownership concept applies here, and
    // @PreAuthorize is recognized as that kind of signal too.
    @PreAuthorize("hasRole('ADMIN')")
    public Order showAdminChecked(HttpServletRequest request) {
        String orderId = request.getParameter("order_id");  // safe: Missing Authorization / IDOR
        return repo.findById(orderId);
    }
}
