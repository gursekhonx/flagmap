"""
authn_guard.py — best-effort "Missing Authentication Check" heuristic.

Found via real-world testing against a real MetaCTF-style gRPC challenge
("stubborne"): its `Login()` RPC handler looks up a user by a
client-supplied username and unconditionally issues a brand-new session
token — `session = str(uuid.uuid4())` — for ANY username, registered or
not, with no password/credential check anywhere in the function at all.
The request message (`LoginRequest`) doesn't even have a password field.
flagmap had no rule shape for this at all before: it's not IDOR (no
id-ownership check missing — there's no "specific resource" concept
here), not Weak Auth Logic (that's for a check that exists but is done
*wrong* — `==` type juggling, `strcmp` bypass; this is a check that
doesn't exist at all), not Missing CSRF Protection. The gap is a function
that clearly GRANTS access (issues a session/token/cookie) for a
client-claimed identity, with nothing in it that verifies that identity
is who it claims to be.

Same shape of problem as idor.py's and csrf.py's checks, and built the
same deliberately coarse, textual, "possible"-confidence way, for the
same reason: "this function creates a session for a request-supplied
username/identity, and I don't see password/bcrypt/verify/authenticate(
/jwt.decode/oauth/anything like it anywhere in it" is a real, common
signal worth a 30-second look — it is not proof of a bug.

Design:

- Function BOUNDARIES are found the same way idor.py finds them: reusing
  ast_engine.py's existing tree-sitter parse + SCOPE_NODE_TYPES table, not
  a second, worse indentation/brace counter.
- Everything INSIDE that boundary is matched with plain regex over the
  function's own source text — same "textual signal, not real
  data-flow" honesty idor.py/csrf.py already apply to themselves.
- Two things must BOTH be true for a function to even become a
  candidate: (1) it reads a username/identity-claim value straight from
  the request (IDENTITY_CLAIM_RE), AND (2) it grants a new session,
  token, or auth cookie somewhere in its body (SESSION_GRANT_RE).
  Deliberately requiring both, not either alone: (1) by itself just means
  "this function knows who the client says they are" (true of almost any
  authenticated endpoint, including ones that correctly check a
  password), and (2) by itself just means "this function sets a cookie"
  (true of plenty of unrelated code — a shopping-cart id, a CSRF token
  refresh, an analytics session). Only the combination — claims an
  identity AND hands out access for it — is the shape worth asking
  "...and where's the check?" about.
- The missing piece: no sign anywhere in the function (or its
  immediately preceding decorator/annotation lines, same
  `_HEADER_LOOKBACK_LINES` convention as idor.py) of a credential/token
  verification call (AUTHN_CHECK_HINT_RE). Deliberately broad and
  inclusive here, unlike idor.py's narrow OWNERSHIP_HINT_RE — the goal
  isn't to prove the check is *correct* (a bad `==` password comparison
  still counts as "a check exists", and is Weak Auth Logic's problem to
  flag, not this one's), only that *some* recognizable attempt at one is
  present. The literal word "password"/"passwd"/"pwd" counts on its own:
  if a login-granting function never even mentions a password-shaped
  term anywhere, that alone is already the stubborne-style bug this
  check exists for, regardless of whether a more specific verification
  call is also present.

Known false positives this does NOT try to rule out, same honesty
standard as idor.py/csrf.py:
- Passwordless/magic-link/SSO flows that legitimately grant a session
  after an identity was ALREADY verified by something this doesn't
  recognize (a third-party library call with no password/oauth/saml/jwt-
  shaped name, verification done in middleware in a different file,
  a signed magic-link token checked by a helper this regex doesn't match).
- An identity verified by a caller of this function (e.g. a decorator
  that has already authenticated the request before this function's body
  even runs) in a shape AUTHN_CHECK_HINT_RE doesn't recognize, or defined
  in a different file than the one being scanned — same "no
  interprocedural reasoning, on purpose" limit idor.py states for itself.
- A session REFRESH/rotation function that re-issues a token for an
  already-authenticated session (checked via a session/cookie lookup
  rather than a password) can plausibly still read a username and grant
  a new token without ever mentioning "password" — this check cannot
  tell "re-issuing for someone already logged in" apart from "never
  checked who they are" apart from source text alone.
Known false negatives: any verification phrased in a way
AUTHN_CHECK_HINT_RE doesn't recognize at all.

If this flags something, read the function. If there genuinely is no
credential check anywhere nearby, that's the 30 seconds paying off; if
there is one just phrased differently than this recognizes, that's the
same accepted cost every other best-effort heuristic in this project
already carries.
"""

import re
from dataclasses import dataclass
from typing import List

from . import ast_engine as _ast

# Same language set idor.py uses, same reasoning: this shape (a
# request-handling function that logs someone in) is a Flask/Express/
# Rails/Spring/Laravel-style web-app idiom, rare enough in Lua/Rust CTF
# code that it's not worth chasing without a real example to design
# against — but this project's very first real-world find for this check
# (stubborne) was a *Python gRPC service*, not a web framework at all, so
# unlike idor.py this is deliberately not assumed to be HTTP-only: the
# regexes below match on "a username was read from the request" and "a
# session/token was granted", neither of which is specific to HTTP.
AUTHN_GUARD_LANGUAGES = {"python", "js", "php", "go", "java", "ruby"}

# A value identifying who the client CLAIMS to be, read straight from the
# request. Deliberately does NOT require a password-shaped field
# alongside it — the bug this check exists for is a login endpoint that
# never asks for (or never checks) a credential AT ALL, not one that asks
# for a password and compares it wrong (that's Weak Auth Logic's job, a
# different, already-existing check in patterns.py).
IDENTITY_CLAIM_RE = re.compile(
    r"""request\.(?:form|args|json|values)\s*(?:\.get\(|\[)\s*['"]?(?:username|user|email|login)\b|
        req\.(?:body|params|query)\.(?:username|user|email|login)\b|
        \$_(?:POST|GET|REQUEST)\s*\[\s*['"](?:username|user|email|login)['"]\s*\]|
        \bparams\s*\[\s*:?['"]?(?:username|user|email|login)\b|
        getParameter\s*\(\s*['"](?:username|user|email|login)['"]\s*\)|
        request\.(?:username|user|email|login)\b|
        req\.body\.(?:username|user|email|login)\b""",
    re.IGNORECASE | re.VERBOSE,
)

# The function actually GRANTS something — a new session, a signed/
# opaque token, or an auth cookie — as opposed to merely reading one back.
# Deliberately broad across languages/frameworks, mirroring the breadth
# idor.py's own regexes already accept as a necessary cost of covering
# more than one ecosystem in one check.
SESSION_GRANT_RE = re.compile(
    r"""session\s*\[[^\]]*\]\s*=|
        request\.session\s*\[|
        req\.session\.\w+\s*=|
        \$_SESSION\s*\[[^\]]*\]\s*=|
        cookies(?:\.permanent)?\s*\[[^\]]*\]\s*=|
        \.set_cookie\s*\(|setcookie\s*\(|res\.cookie\s*\(|
        \bjwt\.encode\s*\(|\bjwt\.sign\s*\(|
        \b(?:session|token|auth_token|session_id|sessionid|authtoken)\s*=\s*
            (?:str\s*\(\s*)?(?:uuid\.uuid4|secrets\.token|jwt\.encode|jwt\.sign)""",
    re.IGNORECASE | re.VERBOSE,
)

# Any recognizable sign that a credential/token was actually checked
# SOMEWHERE in this function. Deliberately broad and inclusive — the
# point is only "did *something* verification-shaped happen", not "was
# it done correctly" (a weak `==` password comparison still counts; see
# module docstring). The bare words password/passwd/pwd are included on
# their own for exactly the reason explained there: their total absence
# in a session-granting, identity-reading function is itself already the
# signal this check exists to catch.
AUTHN_CHECK_HINT_RE = re.compile(
    r"""password|passwd|\bpwd\b|
        \bauthenticate\s*\(|
        check_password|checkpw|verify_password|has_secure_password|
        comparePassword|compare_password|verifyPassword|
        hmac\.compare_digest|secrets\.compare_digest|constant_time_compare|
        jwt\.decode\s*\(|jwt\.verify\s*\(|
        valid_password|authenticate_user|
        bcrypt\.|scrypt\.|pbkdf2|
        \boauth2?\b|\bopenid\b|\bsaml\b""",
    re.IGNORECASE | re.VERBOSE,
)

# Same lookback window idor.py uses, same reason: catch a decorator/
# annotation (`@login_required`-shaped, though note that alone wouldn't
# count as a credential check anyway — see docstring) sitting directly
# above the function without reaching into an unrelated previous one.
_HEADER_LOOKBACK_LINES = 5


@dataclass
class AuthnFinding:
    file: str
    line_no: int
    line_text: str


def find_missing_authn_candidates(path: str, language: str, source_bytes: bytes, lines: List[str]) -> List[AuthnFinding]:
    """Best-effort: a function that reads a username/identity claim
    straight from the request and grants a new session/token/cookie
    somewhere in its body, with no textual sign of a credential check
    anywhere in the function (or its immediately preceding decorator/
    annotation lines). See the module docstring for exactly what this
    does and doesn't try to catch."""
    if language not in AUTHN_GUARD_LANGUAGES:
        return []
    parser = _ast._PARSERS.get(language)
    if parser is None:
        return []

    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return []

    scope_types = _ast.SCOPE_NODE_TYPES.get(language, set())
    findings: List[AuthnFinding] = []
    seen_lines = set()

    def check_function(node) -> None:
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        body_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

        if not IDENTITY_CLAIM_RE.search(body_text):
            return
        if not SESSION_GRANT_RE.search(body_text):
            return

        header_start = max(0, start_line - _HEADER_LOOKBACK_LINES)
        header_text = "".join(lines[header_start:start_line])
        if AUTHN_CHECK_HINT_RE.search(header_text + body_text):
            return

        # Point at the line that actually grants the session — the part
        # worth looking at first — rather than the function's own
        # signature line.
        line_no = start_line + 1
        line_text = lines[start_line].strip()[:200] if start_line < len(lines) else ""
        for i in range(start_line, min(end_line + 1, len(lines))):
            if SESSION_GRANT_RE.search(lines[i]):
                line_no = i + 1
                line_text = lines[i].strip()[:200]
                break

        if line_no not in seen_lines:
            seen_lines.add(line_no)
            findings.append(AuthnFinding(file=path, line_no=line_no, line_text=line_text))

    def walk(node) -> None:
        if node.type in scope_types:
            check_function(node)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings
