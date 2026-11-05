r"""
store_html_xss_guard.py — stored XSS in an Express app that keeps user
content in an in-memory store (a Map) and later sends it back as HTML.

Two real LA CTF 2023 web challenges share the shape:

  - "california-state-police" (index.js):
        const crime = req.body.crime;
        ...
        reports.set(id, crime);
        ...
        res.type(<html>).send(reports.get(req.params.id));
  - "metaverse" (index.js):
        const content = req.body.content;
        ...
        posts.set(id, content);
        ...
        res.type(<html>).send(postTemplate.replace("$CONTENT", () => posts.get(req.params.id)));

(Content types shown as <html> here so this docstring doesn't trip its
own signal.) In both, the value is stored on one request and served raw
as HTML on another — stored XSS, which the admin bot then views. No
existing rule saw it: the request read, the `.set()`, and the `.send()`
are three different statements, often in three different route handlers,
and the AST taint engine doesn't follow values through a Map.

Three whole-file signals: (1) a variable bound from `req.body/query/params`
(plain `const x = req.body.x` or destructuring `const { x } = req.body`);
(2) `STORE.set(<key>, <that variable or a direct req.* expression>)`,
which marks STORE as holding request data; (3) a `.send(` line containing
`STORE.get(` for such a store, where that line or one of the three lines
before it sets an HTML content type (`res.type("text/html")`,
`.type("html")`, `Content-Type: text/html`). Fires on the send line.

Known blind spots: stores other than Map-style `.set/.get` (plain objects,
arrays, a database); content type set further away, or by default (Express
`res.send(string)` defaults to text/html — deliberately NOT assumed here,
since `.get()` results are as often objects sent as JSON); and escaping done
inside a helper between `.get()` and `.send()` isn't recognized.
"""

import re
from typing import List

STORE_XSS_LANGUAGES = {"js"}

_REQ = r"req\.(?:body|query|params)"
_SIMPLE_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*" + _REQ + r"\b")
_DESTRUCTURE_RE = re.compile(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*" + _REQ + r"\b")
_HTML_TYPE_RE = re.compile(
    r"""\.type\s*\(\s*["'](?:text/)?html["']|Content-Type["']?\s*[,:]\s*["']text/html""",
    re.IGNORECASE,
)


class _StoreXssFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def _tainted_names(text: str) -> set:
    names = set(_SIMPLE_ASSIGN_RE.findall(text))
    for group in _DESTRUCTURE_RE.findall(text):
        for part in group.split(","):
            part = part.strip()
            if not part:
                continue
            # `{ a: b }` binds b; `{ a = 1 }` binds a
            name = part.split(":")[-1].split("=")[0].strip()
            if re.fullmatch(r"\w+", name):
                names.add(name)
    return names


def find_store_html_xss(path: str, language: str, lines: List[str]) -> List[_StoreXssFinding]:
    if language not in STORE_XSS_LANGUAGES:
        return []
    full_text = "".join(lines)
    if ".set(" not in full_text or ".get(" not in full_text:
        return []
    names = _tainted_names(full_text)
    value_alt = [_REQ + r"\.\w+"] + [re.escape(n) for n in names]
    set_re = re.compile(r"\b(\w+)\s*\.\s*set\s*\(\s*(?:[^,()]|\([^()]*\))+,\s*(?:" + "|".join(value_alt) + r")\s*\)")
    stores = set(set_re.findall(full_text))
    if not stores:
        return []
    get_re = re.compile(r"\b(?:" + "|".join(re.escape(s) for s in stores) + r")\s*\.\s*get\s*\(")
    findings: List[_StoreXssFinding] = []
    for idx, line in enumerate(lines):
        if ".send(" not in line or not get_re.search(line):
            continue
        window = lines[max(0, idx - 3): idx + 1]
        if not any(_HTML_TYPE_RE.search(w) for w in window):
            continue
        findings.append(_StoreXssFinding(path, idx + 1, line.strip()[:200]))
    return findings
