r"""
aead_decipher_guard.py — Node.js AEAD decryption (AES-GCM / CCM / OCB,
ChaCha20-Poly1305) whose authentication tag is never actually enforced.

Authenticated encryption only authenticates if the receiver checks the tag.
Node's crypto API makes that easy to skip in two ways, and two real LA CTF
challenges — the same app, fixed once and still broken — hit one each:

  - 2023 "zero-trust" (index.js): the session cookie is iv.tag.ciphertext,
    decrypted as
        const cipher = crypto.createDecipheriv(<aes-256-gcm>, key, iv);
        cipher.setAuthTag(authTag);
        res.locals.user = JSON.parse(cipher.update(ct).toString("utf8"));
    `setAuthTag()` only stores the tag; it is compared inside `.final()`,
    which this code never calls. GCM is CTR mode underneath, so XOR-ing the
    known plaintext `{"tmpfile":"/tmp/pastestore/..."}` into the ciphertext
    rewrites it to `{"tmpfile":"/flag.txt",...}` and the page serves the
    flag.
  - 2026 "single-trust" (index.js): the sequel adds `cipher.final()`, but
    still calls `createDecipheriv(<aes-256-gcm>, key, iv)` with no
    `authTagLength` option, so Node accepts a tag of ANY length the client
    sends — down to one byte. Same bit-flip, then try all 256 one-byte tags.

(The quoted lines above are paraphrased with a placeholder cipher name so
this module's own source doesn't match its own signal.)

Design: for every `createDecipheriv(...)` call naming an AEAD cipher —
(A) if `.final(` is never called on the variable the decipher is assigned
to, between this call and the next createCipheriv/createDecipheriv, the
tag is never checked at all: "high"/"likely". Both limits matter —
"zero-trust" names its *encrypting* object `cipher` too, and calls
`.final()` on that one a few lines earlier; (B) otherwise, for GCM only
(CCM and OCB already require authTagLength), if that same line has no
`authTagLength`, truncated tags are accepted: "medium"/"likely". Fires on
the createDecipheriv line in both cases.

Known blind spots: a decipher passed to a helper that calls `.final()`
elsewhere is reported as case (A) (over-report, not a miss); the options object built on another line hides
the authTagLength check for (B) (it will over-report there, not miss);
and WebCrypto/`crypto.subtle.decrypt` is out of scope — it always checks
the full tag.
"""

import re
from typing import List

AEAD_LANGUAGES = {"js"}

_DECIPHER_RE = re.compile(
    r"""createDecipheriv\s*\(\s*["'](?P<alg>aes-\d+-(?:gcm|ccm|ocb)|chacha20-poly1305)["']""",
    re.IGNORECASE,
)
_FINAL_RE = re.compile(r"\.final\s*\(")
_CREATE_RE = re.compile(r"\bcreate(?:De)?cipheriv\s*\(", re.IGNORECASE)
_ASSIGN_RE = re.compile(r"\b(?:const|let|var)?\s*(\w+)\s*=\s*[\w.]*$")


class _AeadFinding:
    __slots__ = ("file", "line_no", "line_text", "kind")

    def __init__(self, file, line_no, line_text, kind):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text
        self.kind = kind  # "no_final" or "no_tag_length"


def find_aead_decipher_issues(path: str, language: str, lines: List[str]) -> List[_AeadFinding]:
    if language not in AEAD_LANGUAGES:
        return []
    full_text = "".join(lines)
    if "createDecipheriv" not in full_text:
        return []
    findings: List[_AeadFinding] = []
    for idx, line in enumerate(lines):
        m = _DECIPHER_RE.search(line)
        if not m:
            continue
        # Only look for .final() between this decipher and the next
        # createCipheriv/createDecipheriv — "zero-trust" reuses the name
        # `cipher` for its encrypting object, whose .final() is elsewhere.
        rest = [line[m.end():]]
        for nxt in lines[idx + 1:]:
            if _CREATE_RE.search(nxt):
                break
            rest.append(nxt)
        window = "".join(rest)
        var = _ASSIGN_RE.search(line[:m.start()])
        if var:
            final_re = re.compile(r"\b" + re.escape(var.group(1)) + r"\s*\.\s*final\s*\(")
            has_final = bool(final_re.search(window))
        else:
            has_final = bool(_FINAL_RE.search(window))
        if not has_final:
            kind = "no_final"
        elif m.group("alg").lower().endswith("gcm") and "authTagLength" not in line:
            kind = "no_tag_length"
        else:
            continue
        findings.append(_AeadFinding(path, idx + 1, line.strip()[:200], kind))
    return findings
