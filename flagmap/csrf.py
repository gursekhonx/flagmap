"""
csrf.py — best-effort CSRF protection check.

Heuristic: a <form method="post" ...> with no sign of a CSRF token anywhere
in the same file is worth a look. This is intentionally crude (no
cross-file/template-include awareness, no JS-based CSRF header checks) but
catches the extremely common "plain HTML form, no token field, no middleware"
pattern used in a lot of intentionally-vulnerable CTF apps.
"""

import re
from dataclasses import dataclass

FORM_POST_RE = re.compile(r"""<form\b[^>]*\bmethod\s*=\s*["']post["']""", re.IGNORECASE)
CSRF_HINT_RE = re.compile(r"""csrf""", re.IGNORECASE)


@dataclass
class CsrfFinding:
    file: str
    line_no: int
    line_text: str


def find_missing_csrf(path: str, language: str, lines: list) -> list:
    if language not in ("php", "html"):
        return []

    full_text = "".join(lines)
    if CSRF_HINT_RE.search(full_text):
        return []  # some mention of csrf exists somewhere in the file — don't flag

    findings = []
    for line_no, line in enumerate(lines, start=1):
        if FORM_POST_RE.search(line):
            findings.append(CsrfFinding(file=path, line_no=line_no, line_text=line.strip()[:200]))
    return findings
