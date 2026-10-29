"""
loot.py — recon/loot scanning: things worth finding that need zero
exploitation, just looking. A category of CTF mistake that's genuinely
distinct from "code vulnerability" (patterns.py/ast_engine.py) and
"misconfiguration" (config_scanner.py): an exposed `.git` folder, a
leftover `.env`, a `.bak` file sitting next to the real source, a
hardcoded flag-shaped string, or a stray private key aren't bugs in the
challenge's logic at all — they're packaging mistakes, and in the
specific context flagmap is built for (a team handed a tarball of
challenge source), finding one of these is often strictly faster than
finding and exploiting the "intended" vulnerability. A lot of CTF points
are won by someone running `git log -p` or `cat .env` five minutes in,
not by someone who found the SQL injection.

Two kinds of check:

1. Suspicious file/directory PRESENCE — the existence of the thing is
   the whole finding, no content inspection needed. `.git` is the
   headline case: scanner.py's main source walk (and config_scanner.py's)
   both deliberately SKIP it via patterns.SKIP_DIRS, because it's noise
   for "scan the code for bugs" — but noise for that purpose is exactly
   the signal for this one, so this module does its own separate walk
   that does NOT skip it.
2. Suspicious file CONTENT — deliberately narrow and high-precision only:
   flag-shaped strings (`flag{...}`/`CTF{...}` and common variants) and
   PEM private-key headers. Deliberately does NOT attempt a generic
   "any long random-looking string near the word 'secret'" check here —
   that's the exact kind of noisy heuristic the hardcoded-credential
   regex in patterns.py (Weak Auth Logic) already covers for recognized
   source files; duplicating a weaker version of it here would just be
   noise. What this module adds that nothing else in flagmap does is
   scanning file types the main code/config scanners don't look at at
   all (a loose .txt/.md/.log/.json/.yml, or anything inside what used
   to be a skipped directory), and the two patterns chosen are chosen
   specifically because they have close to zero false-positive rate on
   their own (an AWS access key ID's format is fixed; a PEM header is a
   fixed literal string; a flag-wrapper string is, by construction, not
   going to appear by accident in unrelated code).

Confidence is "likely", not "possible", for everything here — unlike a
tainted-sink match (which is a pattern that *might* be exploitable
depending on code this tool can't fully see), a `.git` folder being
present, a `.env` file being present, or a literal flag-shaped string
being present are not probabilistic: they're facts about what's in the
tarball you were just handed, and the very next action ("open the file",
"run git log") requires no further verification to be worth doing right
now.
"""

import os
import re
from dataclasses import dataclass
from typing import List

from .patterns import SKIP_DIRS

MAX_FILE_BYTES = 1_000_000

# Directories still worth skipping for noise/performance even here — a
# vendored dependency tree is never where a challenge author's own
# mistake lives, and .git's own internals are a binary-packed object
# store that's pointless to regex-scan for content. ".git" staying in
# this set only stops the walk from *descending into* it for content
# checks — its mere *presence* is still detected and flagged by
# _check_presence below, which looks at each directory's dirnames
# BEFORE this filter is applied to them, every level of the walk.
LOOT_SKIP_DIRS = SKIP_DIRS

# Exact filenames (case-sensitive, matching real-world convention) whose
# mere presence is the finding.
_EXACT_NAME_FINDINGS = {
    ".env": ("Exposed .env file", "Environment files commonly hold the flag itself, database credentials, "
                                   "or a signing secret — open it directly, no exploitation needed."),
    ".htpasswd": ("Exposed .htpasswd file", "Contains hashed HTTP Basic Auth credentials — crack them offline "
                                             "(they're frequently weak/default in CTF setups) or check if the "
                                             "hash algorithm itself is broken (plain crypt/MD5)."),
    "id_rsa": ("Exposed SSH private key", "A private key left in the challenge source/handout — try it "
                                           "directly against any SSH service the challenge exposes."),
    "id_dsa": ("Exposed SSH private key", "A private key left in the challenge source/handout — try it "
                                           "directly against any SSH service the challenge exposes."),
    "id_ecdsa": ("Exposed SSH private key", "A private key left in the challenge source/handout — try it "
                                             "directly against any SSH service the challenge exposes."),
    "id_ed25519": ("Exposed SSH private key", "A private key left in the challenge source/handout — try it "
                                               "directly against any SSH service the challenge exposes."),
}

# Suffix-matched filenames.
_SUFFIX_FINDINGS = [
    (".bak", "Backup file present", "A `.bak` copy often serves as raw source instead of being executed if "
                                     "it's ever web-accessible, and even just in the handout it's worth "
                                     "diffing against the real file — the backup may predate a redaction."),
    ("~", "Editor backup/swap file present", "Emacs/vim-style backup file — same idea as `.bak`: diff it "
                                              "against the real file for anything that was changed or redacted."),
    (".swp", "Editor swap file present", "A vim swap file can contain an in-progress, unsaved edit of the "
                                          "real source — recoverable with `vim -r` even from a partial copy."),
    (".orig", "Original/pre-patch file present", "Often left behind by a patch/merge tool — diff it against "
                                                  "the current file to see exactly what the author changed."),
    (".sql", "Database dump file present", "Likely contains real table data — user records, password hashes, "
                                            "or the flag itself. Open it directly."),
    (".sqlite3", "SQLite database file present", "Likely contains real table data — user records, password "
                                                  "hashes, or the flag itself. Open it directly."),
    (".sqlite", "SQLite database file present", "Likely contains real table data — user records, password "
                                                 "hashes, or the flag itself. Open it directly."),
]

# Content-based checks: (compiled regex, vuln_name, why, payload-ish hint).
# Kept deliberately small and high-precision — see module docstring.
# Requires at least 3 alphanumeric/underscore/hyphen characters inside the
# braces specifically (not just "any non-brace character") — this check
# ran against flagmap's own source during development and flagged its
# OWN docstring's illustrative `flag{...}` example, since bare "..." is
# a non-brace, non-whitespace sequence just as much as a real flag body
# is. Real flags (hex digests, words, random tokens) are always
# alphanumeric; placeholder ellipses in prose aren't, and this is cheap
# insurance against every other piece of documentation that describes
# the flag format the same way.
FLAG_SHAPED_RE = re.compile(
    r"""\b(?:flag|ctf|CTF|FLAG)\{[A-Za-z0-9_\-]{3,120}\}""",
)
PEM_PRIVATE_KEY_RE = re.compile(
    r"""-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----""",
)
AWS_ACCESS_KEY_RE = re.compile(r"""\bAKIA[0-9A-Z]{16}\b""")

_CONTENT_CHECKS = [
    (FLAG_SHAPED_RE, "Hardcoded flag-shaped string",
     "A flag-shaped literal is sitting directly in this file — open it and read it; no exploitation needed. "
     "If this is the real flag left in by mistake, this is the whole challenge. If it's a placeholder/decoy "
     "from development, it's still worth ruling out first."),
    (PEM_PRIVATE_KEY_RE, "Exposed private key material",
     "A PEM-format private key is embedded directly in this file — try it against any SSH/TLS service the "
     "challenge exposes, or use it to decrypt anything encrypted with the matching public key."),
    (AWS_ACCESS_KEY_RE, "Exposed AWS access key ID",
     "An AWS access key ID is sitting directly in this file — if the matching secret key is nearby or "
     "findable, check what it's scoped to access (often more than the challenge intends)."),
]

# File extensions treated as definitely-binary, not worth a text scan —
# kept short and conservative: when in doubt, scan it, since false
# negatives here are more costly than the (bounded, by MAX_FILE_BYTES)
# cost of reading one more file as text with errors="ignore".
_SKIP_CONTENT_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pyc", ".class", ".o", ".so", ".dll", ".exe",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".jar", ".war",
}


@dataclass
class LootFinding:
    file: str
    line_no: int
    line_text: str
    vuln_name: str
    why: str
    payload: str


def _check_presence(dirpath: str, dirnames: List[str], filenames: List[str], root: str) -> List[LootFinding]:
    findings = []

    if ".git" in dirnames:
        git_path = os.path.join(dirpath, ".git")
        findings.append(LootFinding(
            file=git_path,
            line_no=0,
            line_text=".git/",
            vuln_name="Exposed .git directory",
            why="Version history is sitting right here — `git log -p` and `git show` on every commit "
                "frequently surface deleted files, old credentials, or the original flag before it was "
                "swapped out for the live challenge.",
            payload="git -C '{}' log -p --all; git -C '{}' show --all".format(git_path, git_path),
        ))

    for fname in filenames:
        full = os.path.join(dirpath, fname)
        if fname in _EXACT_NAME_FINDINGS:
            vuln_name, why = _EXACT_NAME_FINDINGS[fname]
            findings.append(LootFinding(file=full, line_no=0, line_text=fname, vuln_name=vuln_name, why=why,
                                         payload=f"Open {full} directly."))
            continue
        for suffix, vuln_name, why in _SUFFIX_FINDINGS:
            if fname.endswith(suffix) and fname != suffix:
                findings.append(LootFinding(file=full, line_no=0, line_text=fname, vuln_name=vuln_name, why=why,
                                             payload=f"Open {full} directly."))
                break

    return findings


def _check_content(path: str) -> List[LootFinding]:
    _, ext = os.path.splitext(path)
    if ext.lower() in _SKIP_CONTENT_EXT:
        return []
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return []
    except OSError:
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    findings = []
    seen = set()  # (vuln_name,) per file — one finding per category per file is plenty
    for line_no, line in enumerate(lines, start=1):
        if len(line) > 5000:
            continue  # same minified-asset guard scanner.py uses elsewhere
        for regex, vuln_name, why in _CONTENT_CHECKS:
            if vuln_name in seen:
                continue
            m = regex.search(line)
            if m:
                seen.add(vuln_name)
                findings.append(LootFinding(
                    file=path, line_no=line_no, line_text=line.strip()[:200],
                    vuln_name=vuln_name, why=why, payload=f"See {path}:{line_no}.",
                ))
    return findings


def find_loot(root: str) -> List[LootFinding]:
    findings: List[LootFinding] = []

    if os.path.isfile(root):
        return _check_content(root)

    for dirpath, dirnames, filenames in os.walk(root):
        findings.extend(_check_presence(dirpath, dirnames, filenames, root))
        dirnames[:] = [d for d in dirnames if d not in LOOT_SKIP_DIRS]
        for fname in filenames:
            findings.extend(_check_content(os.path.join(dirpath, fname)))

    return findings
