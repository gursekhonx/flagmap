r"""
shell_template_guard.py — a shell command string built with template-literal
interpolation on one line, then run through `exec()`/`execSync()` (which
use a shell) on a later one.

patterns.py's JS command-injection regex only sees the template literal
when it is written INSIDE the exec call. Found in UofTCTF 2024's public
"Voice Changer" web challenge (src/index.js), paraphrased:

    const command = <ffmpeg ... -af "asetrate=44100*${formData.pitch},...">
    exec(command, (error, stdout, stderr) => { ... })

`formData` is filled from busboy `field` events — the multipart form —
which no taint source models, so the AST engine can't see it either. The
solve sets `pitch` to a backtick command substitution and reads the flag
out of the ffmpeg error output.

Two whole-file signals: (1) `const|let|var X = ` followed by a template
literal containing at least one `${...}` whose expression isn't a plainly
server-side value (`__dirname`, `__filename`, `process.env.*`, a number,
or a quoted literal); (2) `exec(X` / `execSync(X` /
`child_process.exec(X` with that same variable as the first argument.
`execFile`/`spawn` without `shell: true` don't go through a shell and are
not matched. Fires on the exec line, "possible": without taint the tool
can't prove the interpolated value is attacker-controlled, only that it
was pasted into a shell string.

Known blind spots: a command assembled with `+` concatenation across
lines (the existing regex covers the one-line form); a template literal
that spans several lines.
"""

import re
from typing import List

SHELL_TEMPLATE_LANGUAGES = {"js"}

_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*`([^`]*)`")
_INTERP_RE = re.compile(r"\$\{([^}]*)\}")
_SERVER_SIDE_RE = re.compile(
    r"""^\s*(?:__dirname|__filename|process\.env\.\w+|\d+|"[^"]*"|'[^']*')\s*$"""
)


class _ShellTemplateFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_shell_template_exec(path: str, language: str, lines: List[str]) -> List[_ShellTemplateFinding]:
    if language not in SHELL_TEMPLATE_LANGUAGES:
        return []
    full_text = "".join(lines)
    if "exec" not in full_text:
        return []
    names = set()
    for line in lines:
        for m in _ASSIGN_RE.finditer(line):
            exprs = _INTERP_RE.findall(m.group(2))
            if any(not _SERVER_SIDE_RE.match(e) for e in exprs):
                names.add(m.group(1))
    if not names:
        return []
    exec_re = re.compile(
        r"\b(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:" + "|".join(re.escape(n) for n in names) + r")\s*[,)]"
    )
    return [
        _ShellTemplateFinding(path, idx + 1, line.strip()[:200])
        for idx, line in enumerate(lines)
        if exec_re.search(line)
    ]
