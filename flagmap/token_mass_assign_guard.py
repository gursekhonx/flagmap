r"""
token_mass_assign_guard.py — best-effort "the WHOLE request form/JSON body
becomes the claims of a session/auth token" Mass Assignment detector.

Found in DownUnderCTF 2023's public "grades-grades-grades" web challenge
(`src/routes.py`), paraphrased:

    if request.method == 'POST':
        jwt_data = <the whole submitted form, as a dict>
        jwt_cookie = current_app.auth.create_token(jwt_data)
        ...
        response.set_cookie('auth_token', jwt_cookie, httponly=True)

`create_token()` (in `auth.py`) signs its argument as the JWT payload,
and `requires_teacher` later trusts that payload's `is_teacher` claim.
The signup form only has student-number/email/password inputs, but
nothing stops a client from adding `is_teacher=1` to the POST body — every
submitted field becomes a signed claim. The challenge's own solve script
is a single signup request with that extra field.

`patterns.py`'s existing Python Mass Assignment rule only matches
request.json/request.form double-star-unpacked into a call on one line; this
file never unpacks anything, it hands the whole dict to a token minter
via an intermediate variable on the next line.

Two-signal, whole-file design, same discipline as this project's other
guard modules: (1) a variable assigned the ENTIRE request payload as a
dict — `request.form/args/values.to_dict()`, `request.get_json(...)`,
`request.json`, or `dict(request.form)` and friends — capturing its
name; (2) that same variable passed as the FIRST argument of a
token-minting call: `jwt.encode(...)`, or any call named like
`*create*/*make*/*generate*/*issue*/*sign*/*encode*` + `token`/`jwt`.
A whole-request expression passed directly as the first argument of such
a call on one line is matched too. Building the payload from individual,
chosen fields (`{"user": request.form["user"]}`) never matches — that's
the safe way to do this, and it's what signal (1) deliberately requires
the absence of.

Known blind spots: no cross-file tracking (the dict built in one module,
minted in another); minting helpers named without "token"/"jwt" in
them (e.g. `login_user(data)`) aren't recognized; and Flask's
`session.update(request.form)` style isn't covered (not observed).
"""

import re
from typing import List

TOKEN_MASS_ASSIGN_LANGUAGES = {"python"}

_WHOLE_REQUEST = (
    r"(?:request\.(?:form|args|values)\.to_dict\s*\(\s*\)"
    r"|request\.get_json\s*\([^)]*\)"
    r"|request\.json\b"
    r"|dict\s*\(\s*request\.(?:form|args|values|json)\s*\))"
)

_ASSIGN_RE = re.compile(r"\b(\w+)\s*=\s*" + _WHOLE_REQUEST)

_MINT_CALL = (
    r"(?:\bjwt\.encode"
    r"|\b\w*(?:create|make|generate|issue|sign|encode)\w*(?:token|jwt)\w*)"
)

_DIRECT_RE = re.compile(_MINT_CALL + r"\s*\(\s*" + _WHOLE_REQUEST)


class _TokenMassAssignFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_token_mass_assign(path: str, language: str, lines: List[str]) -> List[_TokenMassAssignFinding]:
    """Best-effort detector — see module docstring. One finding per
    token-minting call whose first argument is the whole request payload,
    either directly or via a variable assigned it earlier in the file."""
    if language not in TOKEN_MASS_ASSIGN_LANGUAGES:
        return []
    full_text = "".join(lines)
    if "request." not in full_text:
        return []

    patterns = [_DIRECT_RE]
    for var in set(_ASSIGN_RE.findall(full_text)):
        patterns.append(re.compile(_MINT_CALL + r"\s*\(\s*" + re.escape(var) + r"\s*[,)]"))

    findings: List[_TokenMassAssignFinding] = []
    seen_lines = set()
    for pat in patterns:
        for m in pat.finditer(full_text):
            line_no = full_text.count("\n", 0, m.start()) + 1
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            line_text = lines[line_no - 1].strip()[:200] if line_no - 1 < len(lines) else ""
            findings.append(_TokenMassAssignFinding(file=path, line_no=line_no, line_text=line_text))
    return findings
