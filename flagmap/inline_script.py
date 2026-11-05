"""
inline_script.py — scan the JavaScript inside an HTML file's inline
<script> blocks as JavaScript.

flagmap picks a language per FILE by extension, so a `.html` file is only
ever matched against the "html" rules (forms, CSRF, ...) and the
"generic" ones. Every JavaScript rule — `.innerHTML =`, `eval(`,
`document.write(`, `location = ...` — is scoped to "js", so JavaScript
written inline in a page was never looked at by any of them.

Found via LA CTF 2025's public "mavs-fan" web challenge, whose whole
client side is an inline script in `public/post/post.html`:

    const response = await fetch(`/api/post/${postId}`);
    const post = await response.json();
    document.getElementById('post-content').innerHTML = post.message;

`post.message` is whatever the attacker posted; the admin bot opens the
post and the stored payload runs with the admin's cookies (the challenge's
solve is a one-line `<img onerror=...>` post). The very same line in a
`.js` file would have been flagged by the existing DOM-XSS rule.

This module mirrors heredoc.py: it finds the inline script bodies and
hands them to scanner.scan_lines() as "js", but keeps the REAL file path
and REAL line numbers — every line outside a script block (and the part of
a line before `<script ...>` / after `</script>`) is blanked rather than
removed, so a finding points at the exact line in the .html file.

Deliberately skipped: `<script src=...>` (no inline body; the referenced
.js file is scanned on its own), and any `type` that isn't JavaScript
(`text/template`, `application/json`, `application/ld+json`,
`text/x-handlebars-template`, importmap, ...), whose bodies aren't code.
"""

import os
import re
from typing import Iterator, List, Tuple

from .patterns import SKIP_DIRS

HTML_EXTENSIONS = (".html", ".htm")

_OPEN_RE = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)
_SRC_RE = re.compile(r"""\bsrc\s*=""", re.IGNORECASE)
_TYPE_RE = re.compile(r"""\btype\s*=\s*["']?([^"'\s>]+)""", re.IGNORECASE)
_JS_TYPES = {
    "text/javascript", "application/javascript", "module",
    "text/ecmascript", "application/ecmascript", "text/babel", "text/jsx",
}

MAX_FILE_BYTES = 2_000_000


def _is_js_script(attrs: str) -> bool:
    if _SRC_RE.search(attrs):
        return False
    m = _TYPE_RE.search(attrs)
    return m is None or m.group(1).lower() in _JS_TYPES


def extract_inline_script_lines(text: str) -> List[str]:
    """Return the file's lines with everything that ISN'T inside an inline
    JavaScript <script> block replaced by spaces (newlines kept, so line
    numbers and even columns are unchanged). Returns [] when the file has
    no such block at all."""
    spans = []
    pos = 0
    while True:
        m = _OPEN_RE.search(text, pos)
        if not m:
            break
        close = _CLOSE_RE.search(text, m.end())
        body_end = close.start() if close else len(text)
        if _is_js_script(m.group(1)):
            spans.append((m.end(), body_end))
        pos = close.end() if close else len(text)
    if not spans:
        return []
    chars = [c if c == "\n" else " " for c in text]
    for a, b in spans:
        chars[a:b] = text[a:b]
    return "".join(chars).splitlines(keepends=True)


def iter_inline_scripts(root: str) -> Iterator[Tuple[str, str, List[str]]]:
    """Yield (path, "js", lines) for every .html/.htm file under root that
    contains at least one inline JavaScript <script> block."""
    if os.path.isfile(root):
        paths = [root] if root.lower().endswith(HTML_EXTENSIONS) else []
    else:
        paths = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in filenames:
                if fname.lower().endswith(HTML_EXTENSIONS):
                    paths.append(os.path.join(dirpath, fname))
    for path in paths:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        lines = extract_inline_script_lines(text)
        if lines:
            yield path, "js", lines
