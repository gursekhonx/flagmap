r"""
forin_prefix_pollution_guard.py — best-effort JS/TS "prefix-filtered
for...in key, stripped and written straight into a bracket assignment
with no __proto__/constructor denylist" Prototype Pollution detector.

Found in a real DownUnderCTF 2024 web challenge, "prisoner-processor"
(src/app/src/index.ts):

    const getSignedData = (data: any): any => {
      const signedParams: any = {};
      for (const param in data) {
        if (param.startsWith(SIGNED_PREFIX)) {
          const keyName = param.slice(SIGNED_PREFIX.length);
          signedParams[keyName] = data[param];
        }
      }
      return signedParams;
    };

`for...in` walks every enumerable property NAME of `data` — including
one named e.g. "signed.__proto__" if an attacker's JSON body has that
key at all. This function filters those names by a literal prefix
("signed."), STRIPS the prefix with `.slice()`, and writes the result
straight onto a bracket assignment of a fresh plain object with zero
check against `__proto__`/`constructor`/`prototype`. A request key named
"signed.__proto__" survives the prefix filter untouched and becomes
`signedParams["__proto__"] = ...` — Object.prototype pollution for the
whole process. This is exactly how the challenge's own writeup bypasses
this very function's sibling signature check: `Object.entries(data)`
(used to compute the HMAC over the signed fields) never enumerates
inherited/prototype properties, so the injected `signed.__proto__` key
is invisible to the signature check but fully honored by this loop.

This is a different SHAPE of the SAME `"Prototype Pollution"` vuln name
flagmap's two existing JS rules already cover: one matches a known
deep-merge library call (`_.merge`/`deepmerge({}, req.body)`), the other
matches a hand-rolled RECURSIVE merge whose own `key in target` guard is
itself the gadget (walks the prototype chain, so it's not a real guard).
Neither matches this file: there's no library call and no recursion —
just a flat `for...in` loop, a prefix filter, a strip, and a bracket
write. A bare "copy every key from one plain object to another" loop
(`for (const k in obj) { out[k] = obj[k]; }`) is an extremely common,
harmless idiom on its own, so matching on the loop + bracket-assignment
shape alone (an earlier draft of this module did exactly that) would
false-positive constantly on ordinary shallow-copy code — this is why
the signal is deliberately narrowed to the specific "filter by a literal
prefix, THEN strip that exact prefix off with .slice(), THEN use the
stripped result as a brand-new property name" idiom, which is rare
outside this "flatten a namespaced/prefixed set of fields" pattern and
is precisely what makes the attacker-chosen suffix ("__proto__") land
as a literal property name with nothing in between to catch it.

Four-signal, whole-file design (one more than this project's usual
two-to-three, specifically because the two-signal version self-tested as
a false-positive generator against ordinary copy loops — see above):
(1) a `for (const/let/var V in ...)` loop; (2) a `V.startsWith(...)`
prefix check anywhere in the file; (3) a variable K declared via
`const/let K = V.slice(...)` (the prefix-stripped name); (4) a bracket
assignment `obj[K] = ...` elsewhere using that exact derived variable.
No attempt is made to detect a denylist check on K elsewhere in the file
(e.g. `if (K === '__proto__') continue`) — the same trade
`class_pollution_guard.py` already makes for the Python analog of this
exact bug, on the theory that a hand-rolled prefix-strip-and-copy loop
written this way is rarely paired with a complete, correct denylist in
practice (not observed in the one real file this is modeled on).

Known blind spots: no cross-function tracking (the loop, the prefix
check, the slice, and the bracket-write must all be in the same file);
a prefix check spelled some other way (`.indexOf(prefix) === 0`,
a regex test) instead of `.startsWith(` would be missed entirely; and a
denylist check this module doesn't recognize would be wrongly flagged
(same accepted trade as above, and as every other best-effort guard in
this project).
"""

import re
from typing import List

FORIN_PREFIX_LANGUAGES = {"js"}

_FORIN_RE = re.compile(r"\bfor\s*\(\s*(?:const|let|var)\s+(\w+)\s+in\b")


class _ForInPrefixPollutionFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_forin_prefix_pollution(path: str, language: str, lines: List[str]) -> List[_ForInPrefixPollutionFinding]:
    """Best-effort detector — see module docstring. Returns one finding per
    `obj[K] = ...` bracket assignment whose key variable K was declared as
    `V.slice(...)` of a `for...in` loop variable V that is also checked
    with `V.startsWith(...)` somewhere in the file. `[]` for any
    non-JS/TS file or a file missing any one of the four signals."""
    if language not in FORIN_PREFIX_LANGUAGES:
        return []
    full_text = "".join(lines)

    loop_vars = set(_FORIN_RE.findall(full_text))
    if not loop_vars:
        return []

    findings: List[_ForInPrefixPollutionFinding] = []
    seen_lines = set()
    for loop_var in loop_vars:
        prefix_check_re = re.compile(r"\b" + re.escape(loop_var) + r"\.startsWith\s*\(")
        if not prefix_check_re.search(full_text):
            continue

        derived_re = re.compile(
            r"\b(?:const|let|var)\s+(\w+)\s*=\s*" + re.escape(loop_var) + r"\.slice\s*\("
        )
        derived_vars = set(derived_re.findall(full_text))
        if not derived_vars:
            continue

        for derived_var in derived_vars:
            assign_re = re.compile(r"\w+\s*\[\s*" + re.escape(derived_var) + r"\s*\]\s*=")
            for m in assign_re.finditer(full_text):
                line_no = full_text.count("\n", 0, m.start()) + 1
                if line_no in seen_lines:
                    continue
                seen_lines.add(line_no)
                line_idx = line_no - 1
                line_text = lines[line_idx].strip()[:200] if line_idx < len(lines) else ""
                findings.append(_ForInPrefixPollutionFinding(file=path, line_no=line_no, line_text=line_text))
    return findings
