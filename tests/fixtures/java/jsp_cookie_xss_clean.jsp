<%@ page import="java.util.*" %>
<%!
    public String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }
%>
<%
    // Safe counterpart to jsp_cookie_xss_vuln.jsp: same Cookie-loop ->
    // plain-variable shape, but the <%= %> tag wraps the cookie-sourced
    // variable in a recognized escaping call, which
    // jsp_cookie_xss_guard.py's _SAFE_ESCAPE_CALL_RE is meant to catch.
    String lang = "en";
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
        for (Cookie c : cookies) {
            if ("language".equals(c.getName())) {
                lang = c.getValue();
            }
        }
    }
%>
<!DOCTYPE html>
<html lang="<%= escapeHtml(lang) %>"><% // safe: Cross-Site Scripting (XSS)
<head><title>fixture</title></head>
<body></body>
</html>
