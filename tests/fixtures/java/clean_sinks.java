import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class App {
    private java.sql.Connection conn;

    public void searchSafe(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        // parameterized query — the tainted value never touches the SQL string
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");  // safe: SQL Injection
        stmt.setString(1, name);
    }

    public void pingSafe() throws Exception {
        // NOTE: Runtime.getRuntime().exec(...) is intentionally flagged by
        // a generic pre-existing regex regardless of whether the argument
        // is tainted today (patterns.py) — not tested as a false-positive
        // case here, that's by design (same as eval() in the Python/JS
        // fixtures).
        Runtime.getRuntime().exec("echo hello");
    }

    public void goSafe(HttpServletResponse response) throws Exception {
        // same-origin relative redirect — not an open redirect
        response.sendRedirect("/dashboard");  // safe: Open Redirect
    }
}
