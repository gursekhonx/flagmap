"""
jquery_dom_guard.py — best-effort suppression of idor.py's bare-id-
parameter-name fallback false-firing on plain client-side/jQuery-flavored
JS functions whose only "lookup-shaped call" is a jQuery DOM method that
textually collides with `LOOKUP_SINK_RE`'s generic ORM vocabulary.

idor.py's fallback path (`has_id_param`, see its module docstring) exists
specifically for the Flask/Express/Rails/Laravel route-bound-parameter
idiom (`@app.route("/orders/<int:id>") def view(id): ...`) where the id
arrives as a bound function parameter with NO `request.args`/
`req.params`-style extraction call anywhere in the body — `LOOKUP_SINK_RE`
then has to do all the work of proving a real lookup happens, since
there's no `req.*`/`request.*`-style context to lean on at all.

Found via real-world testing against WebGoat's own hand-written front-end
(`static/js/goatApp/view/MenuView.js`) and the bundled jQuery UI library
it ships (`static/js/libs/jquery-ui-1.10.4.js`), where every instance of
this false positive has the exact same shape — a plain JS function
taking a parameter literally named `id` (an HTML element id, not a
database row id) that calls jQuery's own DOM-manipulation methods:

    accordionMenu: function(id) {
        this.$el.find('#' + this.openMenu).slideUp(200);   // <- .find(
        this.$el.find('#' + id).slideDown(300);
        ...
    }

jQuery's `.find()` textually matches `LOOKUP_SINK_RE`'s bare `find(`
alternative — which exists there for `Model.find(id)`-style ORM calls —
for a reason that has nothing to do with authorization at all. This
isn't a rare edge case: `.find()` is one of the single most common
jQuery selector calls in existence, so any jQuery-heavy front-end file
with a function taking an "id"-named parameter is likely to trip it
(the same risk exists for `.remove(`/`.select`/`.first(`/`.save(`,
LOOKUP_SINK_RE's other generic entries, though `.find(` is what actually
fired in both motivating cases).

Deliberately scoped to ONLY the bare-parameter-name fallback path, never
the explicit-extraction path (`req.params.id`-style): when idor.py's own
`ID_PARAM_RE` already matched an actual request-extraction call
somewhere in the function, that's strong, specific evidence this IS
server-route code handling a real HTTP request, and the existing
`LOOKUP_SINK_RE` vocabulary should stay exactly as broad as it already
is there — narrowing it would risk false NEGATIVES on real Express/
Flask/Rails IDOR bugs, the opposite of what this project accepts. The
fallback path has no such anchor: a function merely HAVING a parameter
named `id` proves nothing on its own about where that id came from or
what kind of code this is, which is exactly why its false-positive risk
is categorically different and worth a narrower, additional check.

Suppresses (removes outright, rather than downgrading like
`pickle_guard.py`/`owner_param_guard.py` do — there's no sharper advice
to offer on a finding that shouldn't exist at all) a fallback-only IDOR
finding only when BOTH:

  1. No request-extraction call (idor.py's own `ID_PARAM_RE`) appears
     anywhere in the enclosing function — confirming this finding really
     did come from the bare-parameter fallback, not the explicit-
     extraction path.
  2. No sign the FILE is server-side route-handling code at all — see
     `js_clientside_guard.py`'s `is_clientside_js()`, which this module
     reuses rather than keeping its own copy of the signal (as of
     v1.20.0 — it originally defined this check inline). A real
     server-route file calling a genuine ORM `.find(`/`.remove(` would
     show at least one of `is_clientside_js()`'s recognized signals
     somewhere; a pure front-end script never will. See that module's
     own docstring for exactly what's checked, including the `vendor_
     guard.py`-reuse bypass for vendored files (needed to reach jQuery
     UI's own false positive in the first place: its real Autocomplete
     widget names its `source` callback `function(request, response)`,
     a plain variable-naming convention with nothing to do with HTTP).

Both conditions narrow this to files that are unambiguously client-side
JS with zero server-routing context anywhere — the same "when in doubt,
don't suppress" discipline every other precision guard in this project
already follows. A real IDOR bug reached only via the bare-parameter
fallback in a genuinely server-side file keeps firing exactly as before;
this only removes the finding when there is no server-side signal
anywhere in the file to begin with.

Known blind spot, same honesty standard as every guard before it: a
server route file that happens to use none of `is_clientside_js()`'s
recognized signals (e.g. a raw Node `http.createServer` callback with a
hand-rolled router using none of them, or one that spells its handler
parameters `request`/`response` in full rather than the short `req`/
`res` form) would also be wrongly suppressed if its only IDOR signal was
this same fallback path. Accepted — the same tradeoff `vendor_guard.py`'s
own filename-only signals already make, and one that hasn't been hit in
any real corpus tested so far (DVWA, Mutillidae, NodeGoat, RailsGoat,
Juice Shop, WebGoat).
"""

from typing import List

from . import ast_engine as _ast
from .idor import ID_PARAM_RE
from .js_clientside_guard import is_clientside_js


def filter_clientside_js_false_idor(path: str, language: str, source_bytes: bytes, lines: List[str],
                                     findings: List) -> List:
    """Returns `findings` with any "Missing Authorization / IDOR" entry
    removed when it fired purely via idor.py's bare-parameter-name
    fallback inside a JS file with no server-side signal anywhere. Every
    other finding — including every IDOR finding anchored on an explicit
    request-extraction call, every non-IDOR finding, and anything in a
    non-JS file — passes through unchanged. See module docstring for
    exactly what this does and doesn't try to prove."""
    if language != "js":
        return findings
    idor_findings = [f for f in findings if getattr(f, "vuln_name", None) == "Missing Authorization / IDOR"]
    if not idor_findings:
        return findings

    full_text = "".join(lines)
    if not is_clientside_js(path, full_text):
        return findings  # some sign of server-route code exists somewhere in the file — never suppress

    parser = _ast._PARSERS.get(language)
    if parser is None:
        return findings
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return findings

    scope_types = _ast.SCOPE_NODE_TYPES.get(language, set())
    by_line = {f.line_no: f for f in idor_findings}
    to_remove = set()

    def check_function(node) -> None:
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        matched_lines = [ln for ln in by_line if start_line <= ln - 1 <= end_line]
        if not matched_lines:
            return
        body_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
        if ID_PARAM_RE.search(body_text):
            return  # an explicit extraction call is present — real request-handling signal, never suppress
        for ln in matched_lines:
            to_remove.add(ln)

    def walk(node) -> None:
        if node.type in scope_types:
            check_function(node)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    if not to_remove:
        return findings
    # Finding is a plain (unhashable) @dataclass, so identity is tracked
    # by (line_no, vuln_name) rather than by putting the objects
    # themselves in a set — same keying convention scanner.py's own
    # `seen` set already uses for dedup.
    return [
        f for f in findings
        if not (getattr(f, "vuln_name", None) == "Missing Authorization / IDOR" and f.line_no in to_remove)
    ]
