r"""
jsp_cookie_xss_guard.py — best-effort "a cookie value, read out of a
`request.getCookies()` loop into a plain variable, is later echoed raw
through a JSP `<%= %>` expression tag" XSS detector.

`patterns.py` already has a dedicated JSP XSS rule (search for
"<%=\s*(?:request\.getParameter|request\.getAttribute)"), and its own
comment is explicit about the trade-off it makes: it ONLY matches a
`request.getParameter(...)`/`request.getAttribute(...)` call written
directly INSIDE the `<%= %>` tag, on the same line, deliberately — "a
blanket 'any non-literal <%= %>' pattern would fire on nearly every JSP
page, since <%= %> has no safe form to contrast against." That's a
reasonable line to draw, but it leaves a real, confirmed-in-practice gap
on the other side of it: a cookie's value, read out through Java's
`Cookie[] request.getCookies()` + a `for` loop + `.getValue()` (never a
`request.getParameter(...)`/`getAttribute(...)` call at all), assigned to
a plain local variable, and THAT variable echoed raw several lines later.

Found in the real DownUnderCTF 2025 "sweet_treat" web challenge, in TWO
separate files (`index.jsp` and `admin/admin-review.jsp`), both with the
identical shape:

    String lang = "en";
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
        for (Cookie c : cookies) {
            if ("language".equals(c.getName())) {
                lang = c.getValue();
            }
        }
    }
    ...
    <html lang="<%= lang %>">

`index.jsp` even defines and correctly uses its own `escapeHtml(...)`
helper for a DIFFERENT value two lines later (`<%= escapeHtml(user) %>`)
— proof the developer knew to escape, and simply missed this one spot,
exactly the kind of real "escaped everywhere except here" miss this
project's own rules are written to catch.

Three-signal, whole-file design, same discipline as
`jenkins_pipeline_guard.py` and `zipslip_guard.py`: (1) a `for (Cookie
<var> : ...)` loop, binding some loop variable; (2) that SAME loop
variable's own `.getValue()` assigned to a plain variable somewhere in
the loop body (regardless of whether that assignment sits inside an
`if` guard checking the cookie's name — the real bug doesn't require
conditioning on anything else, only on SOME cookie reaching the loop
body); and (3) that assigned-to variable name appearing inside a `<%=
%>` expression tag. Requiring the receiver of `.getValue()` to be the
SAME variable bound by a real `Cookie` loop (rather than matching any
`.getValue()` call at all) matters in practice: this file's own
`admin/admin.jsp` has an unrelated `HttpSession s = entry.getValue();`
line, from iterating a `Map<String, HttpSession>`'s entries — a
same-named method on a completely different, non-attacker-controlled
type, which an earlier, looser draft of this module's regex (matching
ANY `\w+.getValue()` assignment) would have wrongly treated as
cookie-tainted. A `<%= %>` occurrence is suppressed only when it also
contains a recognized escaping call (`escapeHtml(`, `StringEscapeUtils.
escapeHtml4(`, `fn:escapeXml(`, `Encode.forHtml(`, or `ESAPI.encoder().
encodeForHTML(`) — not by the mere presence of an `if`/name-check nearby,
since the real motivating bug already has exactly that shape (checking
`"language".equals(c.getName())`) and still reflects raw.

Deliberately scoped to `.jsp` files only (gated on the literal `<%=`
token being present in the file at all, which real `.java` source can
never contain) and to the `request.getCookies()`-sourced case
specifically — NOT extended to the broader "any variable later used in
a stored DB value" case also present in the same challenge (`aboutMe`,
sourced from a SQL query result in `admin-review.jsp`), since that
would require deciding which DB reads are "tainted" at all, a much
harder line to draw safely and not (yet) corroborated by a second real
occurrence the way the cookie case is.

Known blind spots: no interprocedural tracking across JSP include
files/tag libraries; a variable reused for an unrelated, non-cookie
purpose under the same name later in the file could in principle
false-positive (not observed in the one real corpus tested); and a
cookie value escaped through a custom helper this module doesn't
recognize by name would be wrongly flagged. Accepted on the same terms
as every other best-effort guard in this project.
"""

import re
from typing import List

JSP_EXTENSIONS = (".jsp",)

_COOKIE_LOOP_VAR_RE = re.compile(r"\bfor\s*\(\s*Cookie\s+(\w+)\s*:")
_GET_COOKIES_RE = re.compile(r"\brequest\.getCookies\s*\(\s*\)")

_EXPR_TAG_RE = re.compile(r"<%=(.*?)%>", re.DOTALL)
_SAFE_ESCAPE_CALL_RE = re.compile(
    r"\bescapeHtml\w*\s*\(|\bStringEscapeUtils\.\w*\s*\(|\bfn:escapeXml\s*\(|"
    r"\bEncode\.forHtml\w*\s*\(|\bESAPI\s*\(\s*\)\s*\.encoder\s*\(\s*\)\s*\.encodeForHTML\s*\("
)


class _JspCookieXssFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_jsp_cookie_xss(path: str, language: str, lines: List[str]) -> List[_JspCookieXssFinding]:
    """Best-effort detector — see module docstring. Returns one finding
    per `<%= %>` expression tag that references a variable assigned from
    a `Cookie`'s own `.getValue()` somewhere earlier in the file, unless
    that same tag also contains a recognized escaping call. `[]` for any
    non-`.jsp` file or a file with no `<%=` tag at all."""
    if not path.endswith(JSP_EXTENSIONS):
        return []
    full_text = "".join(lines)
    if "<%=" not in full_text:
        return []
    if not _GET_COOKIES_RE.search(full_text):
        return []

    cookie_loop_vars = set(_COOKIE_LOOP_VAR_RE.findall(full_text))
    if not cookie_loop_vars:
        return []

    tainted_names = set()
    for loop_var in cookie_loop_vars:
        value_assign_re = re.compile(r"\b(\w+)\s*=\s*" + re.escape(loop_var) + r"\.getValue\s*\(\s*\)\s*;")
        tainted_names.update(value_assign_re.findall(full_text))
    if not tainted_names:
        return []
    name_alt = "|".join(re.escape(n) for n in tainted_names)
    var_ref_re = re.compile(r"\b(?:" + name_alt + r")\b")

    findings = []
    seen_lines = set()
    for m in _EXPR_TAG_RE.finditer(full_text):
        expr_body = m.group(1)
        if not var_ref_re.search(expr_body):
            continue
        if _SAFE_ESCAPE_CALL_RE.search(expr_body):
            continue
        line_no = full_text.count("\n", 0, m.start()) + 1
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        line_idx = line_no - 1
        line_text = lines[line_idx].strip()[:200] if line_idx < len(lines) else ""
        findings.append(_JspCookieXssFinding(file=path, line_no=line_no, line_text=line_text))
    return findings
