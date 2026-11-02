"""
owner_param_guard.py — best-effort annotation for an existing "Missing
Authorization / IDOR" finding: upgrades it when the SAME lookup/update/
delete call also includes a per-user "ownership" filter key (userId/
user_id/ownerId/owner_id/accountId/account_id), but that key's own VALUE
is itself read straight from the request rather than from the
authenticated session — meaning the "ownership check" is real code, but
it trusts a field the caller controls, so it isn't actually a boundary at
all.

Like pickle_guard.py, this does not add or suppress a finding — it
mutates an EXISTING "Missing Authorization / IDOR" finding's confidence
and why/payload in place. idor.py's own OWNERSHIP_HINT_RE is deliberately
narrow (`user_id` with a literal underscore, not the camelCase `userId`
spelling) and that narrowness is NOT a bug to fix by loosening it:
widening OWNERSHIP_HINT_RE to recognize `UserId` as "a check exists"
would make idor.py go silent on exactly the cases this module exists to
sharpen, since the check it would start trusting is the same one that's
actually worthless here. The right fix is additive, not a loosened
suppression — say MORE about the finding idor.py already made, not less.

Found via real-world testing (see README) against OWASP Juice Shop's
routes/payment.ts, address.ts, wallet.ts, and delivery.ts, all of which
share the exact same shape:

    const card = await CardModel.findOne({
        where: { id: req.params.id, UserId: req.body.UserId }
    })

idor.py correctly flags this (an id read from the request, handed to a
lookup call) at "possible" confidence, with why-text saying "there's no
sign ... of a check that the current user actually owns this specific
resource." That's not quite accurate here: there IS a per-user filter —
`UserId: req.body.UserId` — idor.py just doesn't recognize camelCase
`UserId` as the check vocabulary it looks for (deliberately, see above).
But even if it did, treating this as a real check would be WRONG: the
value being compared against isn't the session's own authenticated user
id, it's `req.body.UserId` — a field the attacker supplies in the very
same request. Changing that one field is enough to read or modify
anyone's address, card, wallet, or delivery method. This is a stronger,
more concrete, more exploitable claim than plain "no sign of a check" —
worth a confidence bump and sharper advice, not just leaving the original
possible-confidence, slightly-inaccurate-reasoning finding as the final
word on it.

Deliberately conservative about what counts as "the ownership value came
from the request": it has to be one of the same per-language request-read
idioms idor.py's own ID_PARAM_RE already recognizes (req.body.X/
req.params.X/req.query.X, request.form/args/json/values, $_GET/$_POST/
$_REQUEST, params[...], getParameter(...)) — a value assigned from
req.user.id/current_user.id/session['user_id'] would NOT match this (that
IS the legitimate, trusted form of the same check), so this only upgrades
the finding when the "ownership" value is demonstrably just as
attacker-controlled as the id it's supposedly protecting.

Searches the WHOLE enclosing function's text, not just the single line
idor.py's own finding is anchored on — idor.py anchors a finding at the
id-EXTRACTION line (`const orderId = req.params.id`), which is routinely
a different physical line than the lookup call carrying the ownership
filter (`Order.findOne({ id: orderId, UserId: req.body.UserId })`), even
though Juice Shop's own style happens to collapse both onto one line.
Reuses the exact same AST scope-walk idiom idor.py/pickle_guard.py
already use to find "where does this function end" rather than guessing
with a line-count window.

Known blind spots, same honesty standard as idor.py/pickle_guard.py:
- Only looks within the SAME function as idor.py's own finding — an
  ownership filter built in a sibling helper function, or assembled by
  spreading an object built elsewhere into the lookup call, won't be
  seen. The existing possible-confidence IDOR finding still fires either
  way; this module only ever adds detail, never removes it.
- Searches the WHOLE function body, not just the lookup call next to the
  id read that triggered idor.py's own finding in the first place. In a
  large function (a long promise chain, several nested callbacks) the
  upgrade can fire because of a bypassable ownership filter on a
  DIFFERENT lookup than the one idor.py originally flagged, rather than
  the exact call the id in question reaches — confirmed in practice
  against Juice Shop's placeOrder() handler, where the upgrade is
  triggered by a wallet-balance lookup several dozen lines below the
  basket-id read idor.py actually anchored the finding on. Both lookups
  turned out to be real, exploitable instances of the same bug in that
  case, but that won't always be true; read the whole function, not just
  the annotated line, before concluding what's actually bypassable.
- Doesn't check whether the ownership key's value is later overwritten
  with something trustworthy before the lookup runs (e.g. a middleware
  that reassigns req.body.UserId to the session's own id) — same
  "no interprocedural reasoning" limit idor.py itself accepts.
"""

import re
from typing import List

from . import ast_engine as _ast

OWNER_KEY_RE = r"""(?:user_?id|owner_?id|account_?id|uid)"""

# The same per-language request-read idioms idor.py's own ID_PARAM_RE
# recognizes, reused here for consistency — deliberately NOT including
# req.user/current_user/session['user_id']-style reads, since those ARE
# the legitimate, trusted form of this exact check.
REQUEST_VALUE_RE = re.compile(
    r"""\b""" + OWNER_KEY_RE + r"""\s*[:=]\s*
        (?:req\.(?:body|params|query)\.\w+
          |request\.(?:form|args|json|values)\s*(?:\.get\(|\[)
          |\$_(?:GET|POST|REQUEST)\s*\[
          |params\s*\[\s*:?
          |getParameter\s*\(
        )""",
    re.IGNORECASE | re.VERBOSE,
)


def annotate_bypassable_ownership(language: str, source_bytes: bytes, lines: List[str], findings: List) -> None:
    """Mutates `findings` in place: for each existing "Missing
    Authorization / IDOR" finding whose enclosing function also assigns/
    compares a user/owner/account-id-shaped key against a value read
    straight from the request anywhere in its body, raises its
    confidence to "likely" and appends a note naming the exact bypass.
    See this module's docstring for exactly what this does and doesn't
    try to prove. No-op (and cheap to check) if there is no IDOR finding
    to begin with."""
    idor_findings = [f for f in findings if f.vuln_name == "Missing Authorization / IDOR"]
    if not idor_findings:
        return

    parser = _ast._PARSERS.get(language)
    if parser is None:
        return
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return

    scope_types = _ast.SCOPE_NODE_TYPES.get(language, set())
    by_line = {f.line_no: f for f in idor_findings}

    def check_function(node) -> None:
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        matched_lines = [ln for ln in by_line if start_line <= ln - 1 <= end_line]
        if not matched_lines:
            return
        body_text = "".join(lines[start_line:min(end_line + 1, len(lines))])
        if not REQUEST_VALUE_RE.search(body_text):
            return
        for ln in matched_lines:
            finding = by_line[ln]
            finding.confidence = "likely"
            finding.why = (
                finding.why + " In fact, this function DOES filter by a per-user ownership key — but that "
                "key's own value is read straight from the request, not from the authenticated session, so "
                "the \"ownership check\" is just as attacker-controlled as the id it's supposed to be "
                "protecting."
            )
            finding.payload = (
                "Log in as one low-privilege user, then resend this request with the ownership field (userId/"
                "accountId/...) in the body changed to another user's id — the id-ownership pair is "
                "self-supplied, so nothing here actually verifies they match the caller."
            )

    def walk(node) -> None:
        if node.type in scope_types:
            check_function(node)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
