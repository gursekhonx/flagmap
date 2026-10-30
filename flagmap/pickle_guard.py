"""
pickle_guard.py — best-effort note for an Unsafe Deserialization finding
on a bare call to the pickle module's loads/load functions that is
immediately preceded, in the same function, by a call to something that
reads like a hand-rolled validator (`validate`/`sanitize`/`restrict`/
`allowlist`/... in the callee name) passed the SAME argument that then
gets deserialized. (Careful: never spell that call out literally with
its trailing parenthesis anywhere in this file's own prose, or this
module would self-match the very finding it exists to annotate — see
vendor_guard.py's docstring for the same trap, caught the same way, in
this project's history.)

Found via real-world testing (see README) against a real MetaCTF-style
challenge ("stubborne") whose `_sanitize_state()` function calls
`_validate_pickle_blob(blob)` — which restricts the pickle stream to a
curated, hand-picked opcode allowlist via `pickletools.genops()`,
excluding every opcode (REDUCE, GLOBAL, BUILD, ...) that could actually
call into application code — immediately before deserializing that same
blob. flagmap's blanket Unsafe Deserialization advice ("craft a pickle
with __reduce__ returning os.system(...)") is actively wrong for a call
site like that one: that payload gets rejected by the allowlist before
the deserializer ever sees it, and a player who tries it anyway wastes
time. What's actually worth trying against a guarded sink like that is
checking whether the allowed, "safe" opcodes ALONE (building a plain
dict/list/tuple of literals — no object construction) still satisfy
whatever the deserialized value is used for — in the motivating case, a
plain, legitimately pickle.dumps()-able dict of booleans was already
enough to reach the intended result through the application's own logic,
no RCE gadget needed at all.

This does NOT try to tell whether a given validator call is actually
sound or has a gap in it — that would mean flagmap understanding
arbitrary, hand-rolled opcode/type-filtering logic well enough to find
holes in it, which is close to the actual security research this kind of
challenge is testing, not something a textual heuristic can responsibly
claim to do. It only recognizes that SOME validation-shaped call sits in
front of the deserializing call at all, and swaps in advice that points
at checking what that validation still permits, instead of a blanket RCE
suggestion the guard may have been built specifically to block.

Deliberately conservative about what counts as "a validator call": the
callee name must contain one of a short, literal list of validation-
flavored words (see VALIDATOR_NAME_RE) AND the exact same
argument-expression text passed to the deserializing call must also
appear on that validator call's own line — a validator call that merely
appears somewhere nearby, without visibly sharing the argument, doesn't
count, to avoid crediting an unrelated validation call (one that checks
a totally different field) for protecting this one.

Known blind spots, same honesty standard as idor.py/csrf.py/xxe_guard.py:
- A validator named something this doesn't recognize is invisible here —
  the finding just keeps its original, generic advice, exactly as if no
  guard existed at all. That costs nothing beyond the advice not being
  *extra* precise, unlike a false suppression would.
- Only looks within the same function as the deserializing call, and
  only one call deep — a validator invoked further up the call stack, in
  a decorator, or in middleware, is not seen.
- Never determines whether the validator is actually effective. A
  validator-shaped name that does nothing useful still gets the "check
  what's still permitted" note — harmless (it's reasonable general
  advice for deserialization behind ANY filter), but not a claim that
  the filter in front of it is real or sufficient.
- Python-only: pickle itself is Python-specific. The equivalent
  RCE-via-deserialization sinks in other languages (PHP unserialize,
  Node node-serialize, Ruby Marshal.load/YAML.load) each have their own
  ecosystem-specific hand-rolled-guard idioms, left for a future pass
  rather than guessed at without a real example to design against — same
  "don't extend past what was actually observed" discipline the rest of
  this project follows.
"""

import re
from typing import List

from . import ast_engine as _ast

# Python-only — see module docstring's last point.
PICKLE_GUARD_LANGUAGES = {"python"}

PICKLE_LOAD_ARG_RE = re.compile(r"""\bpickle\.loads?\s*\(\s*([^()\s,]+)""")

VALIDATOR_NAME_RE = re.compile(
    r"""\b\w*(?:validate|sanitize|restrict|whitelist|allowlist|allow_list|
         check_safe|safe_load|is_safe)\w*\s*\(""",
    re.IGNORECASE | re.VERBOSE,
)


def annotate_guarded_pickle_loads(language: str, source_bytes: bytes, lines: List[str], findings: List) -> None:
    """Mutates `findings` in place: for each existing "Unsafe
    Deserialization" finding that sits on a bare call to the pickle
    module's loads/load functions which is immediately preceded, in the
    same function, by a call matching VALIDATOR_NAME_RE sharing that
    call's own argument text, replaces that finding's why/payload with a note
    pointing at the validator instead of the default RCE-gadget
    suggestion. See the module docstring for exactly what this does and
    doesn't try to prove. No-op (and cheap to check) if there is no
    Unsafe Deserialization finding to begin with."""
    if language not in PICKLE_GUARD_LANGUAGES:
        return
    if not any(f.vuln_name == "Unsafe Deserialization" for f in findings):
        return

    parser = _ast._PARSERS.get(language)
    if parser is None:
        return
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return

    scope_types = _ast.SCOPE_NODE_TYPES.get(language, set())
    by_line = {f.line_no: f for f in findings if f.vuln_name == "Unsafe Deserialization"}

    def check_function(node) -> None:
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        for idx in range(start_line, min(end_line + 1, len(lines))):
            finding = by_line.get(idx + 1)
            if finding is None:
                continue
            m = PICKLE_LOAD_ARG_RE.search(lines[idx])
            if not m:
                continue
            arg_text = m.group(1)

            validator_name = None
            for prior_idx in range(start_line, idx):
                prior_line = lines[prior_idx]
                vm = VALIDATOR_NAME_RE.search(prior_line)
                if vm and arg_text in prior_line:
                    validator_name = vm.group(0).rstrip("( \t").strip()
                    break
            if validator_name is None:
                continue

            finding.why = (
                finding.why + f" A call that looks like a validator ({validator_name}(...)) runs on the "
                "same value immediately before this — check what it actually still allows through (a plain "
                "dict/list/tuple of literals built via 'safe' pickle opcodes needs no __reduce__/GLOBAL gadget "
                "at all) before assuming this needs real RCE to exploit."
            )
            finding.payload = (
                "First check what the preceding validator call still permits. If it restricts opcodes/types "
                "but not values, a plain pickle.dumps() of an ordinary dict/list/bool/string (protocol 2 is "
                "usually small enough) may already satisfy whatever the deserialized value is used for, with "
                "no RCE gadget needed at all."
            )

    def walk(node) -> None:
        if node.type in scope_types:
            check_function(node)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
