r"""
signed_cookie_guard.py — an Express signed cookie whose VALUE is a string
the client chose, read back through cookie-parser's `req.signedCookies`.

cookie-parser treats any cookie value starting with `j:` as JSON and
decodes it. That applies to signed cookies too: signing proves the server
produced the bytes, not what they mean. So if the server will sign an
arbitrary user-chosen string — typically by registering a username and
setting it as the session cookie — a user who registers the name
`j:"admin"` gets a validly-signed cookie that `req.signedCookies` hands
back as the string `admin`.

Found in LA CTF 2026's public "clawcha" web challenge (app.js), paraphrased:

    app.use(cookieParser(secret));
    ...
    const username = <the request body's username field>;
    if (!users.has(username)) users.set(username, { username, password, owner: false });
    ...
    res.cookie(<"username">, username, { signed: true })
    ...
    if (typeof req.signedCookies.username === 'string') {
        if (users.has(req.signedCookies.username)) res.locals.user = users.get(...);

The solve registers `j:"r2uwu2"` (the owner's name). The author's note:
reported to the Express team, who consider it intended — the developer is
expected to validate what they sign.

Three whole-file signals: (1) a name bound from `req.body/query/params`
(plain or destructured); (2) `.cookie(<name>, <that variable or a direct
req.* member>, { ... signed: true ... })` on one line; (3) the file reads
`signedCookies` (the decoding side that does the `j:` parse). Fires on the
`.cookie(` line.

Known blind spots: the options object on another line; cookie values built
from the input (`"u:" + name`, which can't start with `j:` — correctly not
flagged anyway); and frameworks other than cookie-parser.
"""

import re
from typing import List

SIGNED_COOKIE_LANGUAGES = {"js"}

_REQ = r"req\.(?:body|query|params)"
_SIMPLE_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*" + _REQ + r"\b")
_DESTRUCTURE_RE = re.compile(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*" + _REQ + r"\b")


class _SignedCookieFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def _request_names(text: str) -> set:
    names = set(_SIMPLE_ASSIGN_RE.findall(text))
    for group in _DESTRUCTURE_RE.findall(text):
        for part in group.split(","):
            name = part.split(":")[-1].split("=")[0].strip()
            if re.fullmatch(r"\w+", name):
                names.add(name)
    return names


def find_signed_cookie_json(path: str, language: str, lines: List[str]) -> List[_SignedCookieFinding]:
    if language not in SIGNED_COOKIE_LANGUAGES:
        return []
    full_text = "".join(lines)
    if "signedCookies" not in full_text or "signed" not in full_text:
        return []
    value_alt = [_REQ + r"\.\w+"] + [re.escape(n) for n in _request_names(full_text)]
    cookie_re = re.compile(
        r"""\.cookie\s*\(\s*[^,]+,\s*(?:""" + "|".join(value_alt) + r""")\s*,\s*\{[^}]*\bsigned\s*:\s*true"""
    )
    findings: List[_SignedCookieFinding] = []
    for idx, line in enumerate(lines):
        if cookie_re.search(line):
            findings.append(_SignedCookieFinding(path, idx + 1, line.strip()[:200]))
    return findings
