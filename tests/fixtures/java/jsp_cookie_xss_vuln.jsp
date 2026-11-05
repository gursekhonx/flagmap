<%@ page import="java.util.*" %>
<%
    // JSP Cookie XSS (v1.28.0) — a standalone .jsp fixture, since
    // jsp_cookie_xss_guard.py's signals (a Cookie-loop variable's own
    // .getValue() assigned to a plain variable, that variable later
    // echoed through a <%= %> tag with no escaping call) are collected
    // across the WHOLE file, not one line. Mirrors the real DownUnderCTF
    // 2025 "sweet_treat" web challenge's index.jsp/admin-review.jsp
    // almost verbatim: a "language" cookie's value is read out through a
    // Cookie[] request.getCookies() loop into a plain `lang` variable,
    // then echoed raw in the page's own <html lang="..."> attribute.
    //
    // The trailing ruleid marker below has to sit on the exact line the
    // <%= %> tag itself is on (that's the line jsp_cookie_xss_guard.py
    // reports), so the scriptlet tag it's written inside is deliberately
    // left unclosed on that line — fixtures aren't meant to compile,
    // only to exercise the detector's line-matching logic. See the
    // groovy fixtures for the same accepted convention.
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
<html lang="<%= lang %>"><% // ruleid: Cross-Site Scripting (XSS)
<head><title>fixture</title></head>
<body></body>
</html>
