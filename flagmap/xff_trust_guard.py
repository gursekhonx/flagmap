r"""
xff_trust_guard.py — best-effort "a client-IP allowlist decision is made
from the X-Forwarded-For / X-Real-IP request header" detector.

X-Forwarded-For is an ordinary request header: the client sets it to
whatever it likes, and a proxy in front only ever APPENDS to it (and a
sloppy one, or none at all, may not even do that). Using its value as
"the client's IP" for an access-control decision lets the attacker claim
any address they want.

Found in three real DownUnderCTF web challenges across two years:

  - 2023 "proxed" (beginner) — `cmd/secret_server/main.go`:
        xff := r.Header.Values(<the X-Forwarded-For name>)
        ...
        if xff != nil {
            ips := strings.Split(xff[len(xff)-1], ", ")
            ip = ips[len(ips)-1]
            ...
        }
        if ip != <the literal 31.33.33.7> { ...403... } else { ...flag... }
    Solved with a single `curl -H 'X-Forwarded-For: 31.33.33.7'`.
  - 2023 "actually-proxed" — the identical secret_server, now behind a
    hand-written proxy that appends the real client IP only to the FIRST
    X-Forwarded-For header it sees; the server reads the LAST one, so two
    headers win. Same server-side line, same root cause.
  - 2025 "sodium" — `rpc_service/server.py`:
        forwarded_for = headers.get(<the x-forwarded-for name>, "").strip()
        if config.authorized_ips and forwarded_for not in config.authorized_ips:
            ...403...
    reached via request smuggling through the front proxy, then passed by
    simply sending `X-Forwarded-For: 127.0.0.1`.

(The quoted code above is paraphrased with <placeholders> where the real
files have quoted header names/IP literals, so this module's own source
doesn't satisfy its own two signals when flagmap scans itself.)

Two-signal, whole-file design, same discipline as this project's other
guard modules: (1) a READ of the X-Forwarded-For / X-Real-IP header from
the request (`Header.Get/Values(name)`, `headers.get(name)`,
`headers[name]`, `req.get(name)`, PHP's `$_SERVER` HTTP_X_FORWARDED_FOR
key, a WSGI `environ` lookup of the same key) — a dict literal that SETS the
header (an attack bot or HTTP client building its own request) and a
proxy comparing a header NAME to the string "x-forwarded-for" are both
deliberately not reads; and (2) somewhere in the same file, an
access-shaped IP decision: an equality/inequality comparison against a
literal dotted-quad IPv4 string, or a membership test against a name that
looks like an IP allowlist (`... in authorized_ips`, `trusted_proxies`,
`allowlist`, `.includes(...)` on one). A file that reads the header
purely for logging, with no such decision anywhere, stays quiet.

Fires on the header-read line, not the comparison line: that's the line
where the untrusted value enters, and it's the same line in all three
real files regardless of how the comparison is spelled.

Known blind spots: no cross-file tracking (header read in a middleware
module, IP compared in a route module elsewhere); IPv6 literals and CIDR
range checks (`ipaddress.ip_address(x) in ip_network(...)`) aren't
recognized as decisions; and a file that reads the header for logging
AND independently compares some other IP to a literal would be a false
positive in principle (not observed in any corpus this was checked
against).
"""

import re
from typing import List

XFF_LANGUAGES = {"python", "js", "go", "php"}

_HDR_NAME = r"""["'](?:x-forwarded-for|x-real-ip|http_x_forwarded_for|http_x_real_ip)["']"""

_READ_RE = re.compile(
    r"(?:\bHeader\.(?:Get|Values)\s*\(\s*"
    r"|\bheaders?\s*(?:\.get\s*\(\s*|\[\s*)"
    r"|\bget\s*\(\s*"
    r"|\bheader\s*\(\s*"
    r"|\$_SERVER\s*\[\s*"
    r"|\benviron\s*(?:\.get\s*\(\s*|\[\s*))"
    + _HDR_NAME,
    re.IGNORECASE,
)

_IPV4_LITERAL = r"""["']\d{1,3}(?:\.\d{1,3}){3}["']"""
_ALLOWLIST_NAME = r"""[\w.]*(?:ips|ip_list|allowlist|whitelist|allowed_hosts|trusted_\w+|trusted)\b"""

_DECISION_RE = re.compile(
    r"(?:===?|!==?|\beq\b|\bne\b)\s*" + _IPV4_LITERAL
    + r"|" + _IPV4_LITERAL + r"\s*(?:===?|!==?)"
    + r"|\bin\s+" + _ALLOWLIST_NAME
    + r"|\b" + _ALLOWLIST_NAME + r"\s*\.\s*(?:includes|indexOf|has|contains)\s*\(",
    re.IGNORECASE,
)


class _XffTrustFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_xff_trust(path: str, language: str, lines: List[str]) -> List[_XffTrustFinding]:
    """Best-effort detector — see module docstring. One finding per line
    that reads an X-Forwarded-For/X-Real-IP header, but only in a file that
    also contains an IP-allowlist-shaped decision. `[]` otherwise."""
    if language not in XFF_LANGUAGES:
        return []
    full_text = "".join(lines)
    if not _DECISION_RE.search(full_text):
        return []
    findings: List[_XffTrustFinding] = []
    for idx, line in enumerate(lines):
        if _READ_RE.search(line):
            findings.append(_XffTrustFinding(file=path, line_no=idx + 1, line_text=line.strip()[:200]))
    return findings
