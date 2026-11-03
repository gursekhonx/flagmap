"""
log_message_guard.py — best-effort suppression of `patterns.py`'s JS
"Sensitive Data Exposure in Logs" regex
(`console.log/debug/info/warn/error(...password...)`) when every one of
its keyword matches on the flagged line sits inside a quoted STRING
LITERAL — a human-readable log message that happens to contain a word
like "password"/"secret"/"token" in its own prose — rather than an
actual sensitive VARIABLE being passed as an argument.

Found via real-world testing against WebGoat:
`lessons/passwordstorage/js/password-storage.js` has

    .catch((error) => console.error("Unable to load password storage
    training data", error));

which the rule flags purely because the literal string "Unable to load
password storage training data" contains the word "password" — the
actual argument being logged is `error`, a generic JS `Error` object
from a failed network fetch, carrying no password data at all.

The JS rule has no syntactic marker to lean on the way its sibling
rules in `patterns.py` do: the Python version additionally requires a
keyword-argument assignment right after the sensitive word (so a
structured-logger call naming the value as an argument matches, but a
plain string message never would), and the PHP version additionally
requires the language's own variable sigil immediately before the word
(so a real PHP variable reference matches, but the bare word sitting
inside an ordinary string never would — careful: don't spell either of
those two trigger shapes out literally in this prose with the actual
punctuation attached, or this docstring would self-match the very rules
it's describing, the same trap this project keeps hitting). JS
identifiers and string contents look identical to a keyword-only
regex — there's no equivalent marker baked into the match itself — so
the JS rule alone needed this additional, separate check.

Suppresses a finding only when stripping every quoted string literal
from the flagged line leaves NO remaining match for the exact same
compiled regex that fired in the first place — i.e. every keyword
occurrence on that line was inside message text. Deliberately
conservative: single- and double-quoted strings are stripped entirely
(plain JS strings have no interpolation, so there's nothing to lose),
but a backtick template literal keeps its `${...}` interpolated
expressions — only the surrounding literal text is dropped. This
matters for a genuine leak written as `` console.log(`password is
${password}`) ``: the interpolated `password` identifier survives the
strip and the regex still matches it, so the finding is correctly left
alone. A keyword appearing anywhere OUTSIDE a string literal on the
same line (a real second argument, e.g. `console.log("password:",
password)`) is untouched for the identical reason — this only ever
removes a finding whose keyword match came entirely from message text.

Known blind spot, same honesty standard as every guard before it: a
multi-line template literal, or a password variable concatenated into
the message string with `+` rather than template-literal interpolation
(`console.log("password: " + password)` — the `+ password` part sits
outside any quotes already, so this specific shape is actually fine,
but a genuinely obscure concatenation pattern could still slip past
either direction of this check). Accepted — no real corpus tested so
far (DVWA, Mutillidae, NodeGoat, RailsGoat, Juice Shop, WebGoat) has hit
a case this check gets wrong, and the alternative (leaving the
message-string false positive in place) was already confirmed, common
noise: logging a load/network failure next to a lesson or variable
named after what it teaches is an extremely ordinary thing for any
front-end script to do.
"""

import re
from typing import List

from .patterns import compiled_patterns

_VULN_NAME = "Sensitive Data Exposure in Logs"

_TEMPLATE_LITERAL_RE = re.compile(r"`(?:[^`\\]|\\.)*`")
_INTERPOLATION_RE = re.compile(r"\$\{([^}]*)\}")
_QUOTED_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')


def _strip_message_text(line: str) -> str:
    """Removes quoted-string content from `line`, keeping a backtick
    template literal's `${...}` interpolated expressions (joined by a
    space) in place of the literal text around them."""

    def _keep_interpolations(match: "re.Match") -> str:
        return " ".join(m.group(1) for m in _INTERPOLATION_RE.finditer(match.group(0)))

    line = _TEMPLATE_LITERAL_RE.sub(_keep_interpolations, line)
    line = _QUOTED_STRING_RE.sub("", line)
    return line


def _js_log_regex():
    for pat in compiled_patterns():
        if pat["name"] == _VULN_NAME and pat["language"] == "js":
            return pat["regex"]
    return None  # pragma: no cover — only reachable if patterns.py drops the rule entirely


def filter_log_message_false_positive(language: str, lines: List[str], findings: List) -> List:
    """Returns `findings` with any JS "Sensitive Data Exposure in Logs"
    entry removed when every keyword match on its own line came from
    inside a quoted string literal rather than a real variable/property
    reference. Every other finding — including one with a keyword
    reference sitting outside any string on the same line, every
    non-JS-rule finding, and anything in a non-JS file — passes through
    unchanged. See module docstring for exactly what this does and
    doesn't try to prove."""
    if language != "js":
        return findings
    targets = [f for f in findings if getattr(f, "vuln_name", None) == _VULN_NAME]
    if not targets:
        return findings

    regex = _js_log_regex()
    if regex is None:
        return findings

    to_remove = set()
    for f in targets:
        if f.line_no < 1 or f.line_no > len(lines):
            continue
        stripped = _strip_message_text(lines[f.line_no - 1])
        if not regex.search(stripped):
            to_remove.add(f.line_no)
    if not to_remove:
        return findings
    return [f for f in findings if not (f.vuln_name == _VULN_NAME and f.line_no in to_remove)]
