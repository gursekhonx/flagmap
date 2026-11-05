r"""
class_pollution_guard.py — best-effort Python "class pollution" detector:
a hand-rolled recursive merge function that walks an attacker-controlled
dict's `.items()` and calls `setattr()` on the destination object using
the key itself as the attribute name, with no denylist on dunder names
like `__class__`/`__init__`/`__globals__`/`__dict__`/`__bases__`. This is
the Python analog of `patterns.py`'s existing JS "Prototype Pollution"
rule for a homemade recursive merge (`instanceof Object && key in
target`) — same underlying mistake (an unbounded attacker-controlled
merge into a live object), different language and different
magic-attribute vocabulary (`__proto__`/`constructor` in JS vs.
`__class__`/`__globals__` in Python), filed under the SAME vuln name
since both describe the identical class of bug.

Found in two real DownUnderCTF 2024 web challenges that share the exact
same merge helper — "co2" and its sequel "co2v2"
(`DownUnderCTF/Challenges_2024_Public` on GitHub). Paraphrased here (with
the tuple-unpacking parenthesized, unlike the real code, specifically so
this docstring's own illustrative example doesn't trip this module's own
two detection signals when flagmap scans its own source — the real
shape is identical either way):

    def merge(src, dst):
        for (key, val) in src.items():
            if hasattr(dst, '__getitem__'):
                if dst.get(key) and type(val) == dict:
                    merge(val, dst.get(key))
                else:
                    dst[key] = val
            elif hasattr(dst, key) and type(val) == dict:
                merge(val, getattr(dst, key))
            else:
                dst.__setattr__(key, val)

`co2`'s own route handler merges a fresh JSON body straight into a
`Feedback()` instance (`merge(json.loads(request.data), feedback)`) with
no key filtering at all. Since `setattr()` doesn't special-case dunder
names, a payload like `{"__class__": {"__init__": {"__globals__":
{"flag": "true"}}}}` walks `feedback.__class__` (the `Feedback` class
itself) `.​__init__` (its constructor function) `.__globals__` (that
function's module-level globals dict) and overwrites the module-global
`flag` variable directly — exactly the gadget chain the linked writeup
and its own reference article ("Prototype pollution in Python") describe.
`co2v2` carries the identical `merge()` function forward untouched (the
challenge's own fix for that round addressed a *different* endpoint, not
this primitive) — real, duplicated evidence of the same generalizable
shape, not a one-off.

Two-signal, whole-file design, same discipline as this project's other
guard modules: (1) a `for <k>, <v> in <dict>.items():` loop, capturing
the key/value variable names; (2) `setattr(<obj>, <k>, <v>)` appearing
anywhere later in the file using THOSE SAME two variable names as the
attribute-name/value arguments (not a literal string name — a literal
`setattr(self, "x", 1)` is completely ordinary Python and must never be
flagged). No attempt is made to prove `src` traces back to a request
body on this line — same trade `patterns.py`'s own JS homemade-merge
rule already makes, and for the same reason: the dangerous CONSTRUCT
itself (dict-driven `setattr` with no denylist) is the signal, not
provable taint, and a function written this way is only ever called
with trusted, fully-known keys in practice if it's never fed external
input at all, which is rare for a "generic merge helper."

Known blind spots: no suppression for a denylist check written
elsewhere in the same loop (e.g. `if k.startswith('__'): continue`) —
neither real occurrence has one, so this hasn't needed to be precise
about recognizing one yet; and a `setattr` call using the right
variable NAMES by coincidence, fed by an unrelated loop reusing the same
names for something harmless, would be a false positive in principle
(not observed in either real file). Accepted on the same terms as every
other best-effort guard in this project.
"""

import re
from typing import List

CLASS_POLLUTION_LANGUAGES = {"python"}

_ITEMS_LOOP_RE = re.compile(r"\bfor\s+(\w+)\s*,\s*(\w+)\s+in\s+\w+\.items\s*\(\s*\)\s*:")


class _ClassPollutionFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_class_pollution(path: str, language: str, lines: List[str]) -> List[_ClassPollutionFinding]:
    """Best-effort detector — see module docstring. Returns one finding
    per `setattr(obj, k, v)` call whose second/third arguments are the
    exact key/value variable names bound by some `for k, v in
    <dict>.items():` loop elsewhere in the file. `[]` for any non-Python
    file or a file with no such loop at all."""
    if language not in CLASS_POLLUTION_LANGUAGES:
        return []
    full_text = "".join(lines)

    kv_pairs = _ITEMS_LOOP_RE.findall(full_text)
    if not kv_pairs:
        return []

    findings = []
    seen_lines = set()
    for key_var, value_var in kv_pairs:
        setattr_re = re.compile(
            r"\bsetattr\s*\(\s*\w+\s*,\s*" + re.escape(key_var) + r"\s*,\s*" + re.escape(value_var) + r"\s*\)"
        )
        for m in setattr_re.finditer(full_text):
            line_no = full_text.count("\n", 0, m.start()) + 1
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            line_idx = line_no - 1
            line_text = lines[line_idx].strip()[:200] if line_idx < len(lines) else ""
            findings.append(_ClassPollutionFinding(file=path, line_no=line_no, line_text=line_text))
    return findings
