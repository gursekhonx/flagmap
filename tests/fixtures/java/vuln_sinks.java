import java.io.File;
import java.sql.Statement;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class App {
    private java.sql.Connection conn;
    private DirContext ctx;

    public void search(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);  // ruleid: SQL Injection
    }

    public void update(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String sql = "UPDATE users SET name = '" + name + "'";
        Statement stmt = conn.createStatement();
        stmt.executeUpdate(sql);  // ruleid: SQL Injection
    }

    public void ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        String cmd = "ping -c 1 " + host;
        Runtime.getRuntime().exec(cmd);  // ruleid: Command Injection
    }

    public void readFile(HttpServletRequest request) throws Exception {
        String fname = request.getParameter("fname");
        File f = new File(fname);  // ruleid: Path Traversal / LFI
    }

    public void go(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = request.getParameter("url");
        response.sendRedirect(url);  // ruleid: Open Redirect
    }

    public void search2(HttpServletRequest request) throws Exception {
        // one-hop interprocedural: `sql` is tainted at the call site below,
        // which must seed runQuery's own `sql` parameter for the sink
        // inside it to fire.
        String name = request.getParameter("name");
        runQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    private void runQuery(String sql) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);  // ruleid: SQL Injection
    }

    public void ldapLogin(HttpServletRequest request) throws Exception {
        String uid = request.getParameter("uid");
        String filter = "(uid=" + uid + ")";
        SearchControls cons = new SearchControls();
        ctx.search("dc=example,dc=com", filter, cons);  // ruleid: LDAP Injection
    }
}
