"""
xxe_guard.py — whole-file false-positive suppression for the XXE patterns
in patterns.py.

patterns.py's "XML External Entity (XXE)" / "XXE" entries are blanket
"this XML-parsing call exists" regex matches (`etree.fromstring(`,
`simplexml_load_string(`, `new DOMDocument(...)->loadXML(`, ...) — they
have no way to see whether the parser was actually configured safely
somewhere else in the file, because that's a different call/import
entirely, often many lines away from the parse call itself. Before this
module existed, flagmap would flag `defusedxml.ElementTree.fromstring(...)`
exactly the same way it flags raw `lxml.etree.fromstring(...)` — which is
backwards, since `defusedxml` exists specifically to make that call safe.

Rather than teaching every XXE regex in patterns.py to also NOT match a
growing list of safe-configuration shapes (fragile — the safe marker is
frequently nowhere near the call site, e.g. a module-level
`defusedxml.defuse_stdlib()` call at the top of the file, or a shared
`SAFE_PARSER = etree.XMLParser(resolve_entities=False)` built once and
reused everywhere), this takes the same approach as idor.py/csrf.py:
a deliberately coarse, whole-file, best-effort heuristic, honestly scoped.

What it checks for, per language — if ANY of these appear ANYWHERE in the
file, every XXE finding in that file is suppressed, not just ones "near"
the marker:
  - Python: `defusedxml` used anywhere (import or qualified call) — that
    library's entire purpose is safe-by-default XML parsing; `resolve_
    entities=False` or `no_network=True` passed to an `etree.XMLParser(...)`
    anywhere in the file.
  - PHP: `libxml_disable_entity_loader(true)` anywhere in the file — the
    historical (PHP <8.0) global switch for this. PHP 8.0+ disables
    external entity loading by default regardless of this call, but this
    scanner can't know which PHP version the challenge actually runs
    (and CTF web challenges deliberately targeting XXE are disproportionately
    likely to be *on* an older PHP for exactly that reason), so the absence
    of this call is NOT treated as a safe signal — only its presence is.

This is deliberately a coarse, whole-file signal, not a per-call,
taint-aware one — actually proving "THIS specific DOMDocument instance,
right here, was configured safely before this specific loadXML() call"
would need the same cross-line object-flow tracking the AST taint engine
does for its own sinks (see ast_engine.py), which is a bigger lift than a
narrow false-positive fix justifies on its own. A file that uses an unsafe
parser for one XML input and a safe one for another will have its genuine
unsafe-parser finding wrongly suppressed too, if any safe marker appears
anywhere in that same file — a known, accepted trade-off: a handful of
real CTF challenges file could in theory hit this, but a flood of false
positives on every file that merely imports defusedxml is a worse and far
more common failure mode to leave unfixed.
"""

import re
from typing import List

XXE_VULN_NAMES = {"XML External Entity (XXE)", "XXE"}

_SAFE_MARKERS = {
    "python": [
        re.compile(r"\bdefusedxml\b"),
        re.compile(r"resolve_entities\s*=\s*False"),
        re.compile(r"\bno_network\s*=\s*True"),
    ],
    "php": [
        re.compile(r"libxml_disable_entity_loader\s*\(\s*true\s*\)", re.IGNORECASE),
    ],
}


def has_xxe_guard(language: str, full_text: str) -> bool:
    for rx in _SAFE_MARKERS.get(language, []):
        if rx.search(full_text):
            return True
    return False


def filter_guarded_xxe(language: str, full_text: str, findings: List) -> List:
    """Drops any Finding whose vuln_name is an XXE one if this file (as a
    whole) contains a recognized safe-parsing marker for this language. A
    no-op for languages patterns.py doesn't have XXE checks for at all, or
    for files with no XXE findings to begin with — cheap to call
    unconditionally."""
    if language not in _SAFE_MARKERS:
        return findings
    if not any(f.vuln_name in XXE_VULN_NAMES for f in findings):
        return findings
    if not has_xxe_guard(language, full_text):
        return findings
    return [f for f in findings if f.vuln_name not in XXE_VULN_NAMES]
