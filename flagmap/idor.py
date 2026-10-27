"""
idor.py — best-effort "Missing Authorization / IDOR" heuristic.

This is the one category the rest of flagmap explicitly avoids (see
README's "What it can't catch (on purpose)"): a route that reads an id
from the request with no check that the current user actually owns that
id. That's an *absence* of a check, not a syntax shape — no dangerous call,
no tainted sink, nothing a `SINKS`-style table can anchor on. A precise
detector for "there is no comparison to the current user anywhere in this
function" doesn't exist here any more than it exists anywhere else in the
tool. What follows is the same trade a human reviewer makes skimming code
fast: "this function pulls an id straight from the request, hands it to a
lookup/update/delete, and I don't see `current_user`/`owner`/`authorize`/
anything like it anywhere nearby" is a real, common signal worth a 30-second
look — it is not proof of a bug. Every finding here is capped at "possible"
confidence for exactly that reason, same as the pre-existing CSRF check
(csrf.py), which this deliberately follows in spirit: coarse, textual,
upfront about its own blind spots, not a confident claim.

Design, and why it's shaped this way:

- Function BOUNDARIES are found precisely, by reusing ast_engine.py's
  existing tree-sitter parse + SCOPE_NODE_TYPES table for whichever
  AST-supported language is in play, rather than hand-rolling a second,
  worse brace/indentation counter. Finding "where does this function end"
  reliably is the one genuinely hard part of this check; the AST engine
  already solved it for every language it supports, so this reuses that
  instead of re-solving it badly with regex.
- Everything INSIDE that boundary — the id-extraction shape, the
  lookup-shaped sink, the ownership-check vocabulary — is matched with
  plain regex over the function's own source text, deliberately, in the
  same spirit as the CSRF check: this is a best-effort textual signal, not
  a claim of real data-flow understanding, so there's no value pretending
  otherwise with AST node matching here.
- A few lines immediately above the function are included too (as
  `header_text`), so a `@login_required`-style decorator or a Java
  `@PreAuthorize` annotation sitting just above the `def`/method is seen
  as part of "this function's context" even though it isn't literally
  inside the body.

Deliberately conservative about what counts as "a check was made": a
generic auth-required decorator/call (`@login_required`, `@jwt_required`,
"authenticated", `isAuthenticated()`) proves the request comes from SOME
logged-in user, not that it's the RIGHT user for *this specific* resource
— that gap is the entire premise of IDOR. So `OWNERSHIP_HINT_RE` below
deliberately does NOT include bare authentication keywords; it only
counts signals that compare the request's identity to the resource's
(`current_user`, `.owner`, `user_id=`, a policy/authorize call, Spring's
`@PreAuthorize`, ...). Treating `@login_required` as sufficient mitigation
would make this check fire approximately never, including on the exact
"logged in as any user, no ownership check, can read/edit anyone's record"
shape that IS the textbook CTF IDOR bug.

Known false positives this does NOT try to rule out (said plainly, same
as "What it can't catch" does for everything else):
- Ownership enforced at the database layer (a row-security policy, a
  tenant-scoped connection) rather than in application code — invisible
  to a source-text check by construction.
- Ownership checked in a *different* function this one calls — this check
  does not do interprocedural reasoning (not even the one-hop seeding
  ast_engine.py's taint tracking does), on purpose: chasing that would
  turn a deliberately "possible, go look" signal into something that
  looks more authoritative than it is.
- A genuinely admin-only / no-ownership-concept route (a health check
  that happens to take an `id` query param for unrelated reasons, a
  moderation endpoint where ANY staff member is meant to touch ANY
  record) — nothing here understands what a resource is "for".
Known false negatives: any ownership check phrased in a way
`OWNERSHIP_HINT_RE` doesn't recognize, or one that lives in middleware/a
decorator defined in a different file than the one being scanned (this
check, like the rest of flagmap, only ever looks at one file at a time).

If this flags something, read the function. If the nearby ownership check
genuinely isn't there, that's the 30 seconds paying off; if it is there
just phrased differently than this recognizes, that's an accepted cost of
a check this coarse existing at all, exactly as README says plainly for
every other "can't catch" case.
"""

import re
from dataclasses import dataclass
from typing import List

from . import ast_engine as _ast

# Languages this heuristic runs on. Lua/Rust skipped, same "light
# coverage, rare fit" reasoning their own SINKS tables already use
# elsewhere in the codebase — a per-user-owned-REST-resource endpoint is a
# far less common shape in the kind of CTF challenge written in either
# language than it is in a Flask/Express/Rails/Spring/Laravel-style app.
IDOR_LANGUAGES = {"python", "js", "php", "go", "java", "ruby"}

# An id-like value pulled straight from the request/route — the "attacker
# controls which row this touches" half of the bug. Deliberately broad on
# the extraction side: any of the common per-language request/route-param
# access shapes, naming one of a handful of id-ish key names.
# Both snake_case and camelCase spelled out via an optional "_" (combined
# with re.IGNORECASE below, "user_?id" matches user_id/userId/USER_ID
# alike) — a string-keyed lookup ($_GET['orderId'], req.query.get('orderId'))
# is just as likely in a PHP/Java/JS codebase as the snake_case form, and
# unlike the parameter-name check below, a regex alternation can't
# normalize programmatically, so both spellings have to be written out.
_ID_KEY = r"""(?:id|user_?id|uid|account_?id|order_?id|file_?id|doc_?id|pk|owner_?id)"""
ID_PARAM_RE = re.compile(
    r"""(?:
        # dict/index-style access: request.args.get('id'), request.args['id'],
        # $_GET['id'], params[:id], ...
        \b(?:request\.args|request\.form|request\.values|request\.view_args|
            req\.params|req\.query|req\.body|params)
            \s*(?:\.get\(\s*|\[\s*)['"]?""" + _ID_KEY + r"""\b
        # plain dot-property access: req.params.id, req.query.userId, ... —
        # the more common Express/Koa idiom, and just as attacker-controlled
        # as the dict-style access above.
        |\b(?:req\.params|req\.query|req\.body)\.""" + _ID_KEY + r"""\b
        |\$_(?:GET|POST|REQUEST)\s*\[\s*['"]""" + _ID_KEY + r"""['"]\s*\]
        |getParameter\s*\(\s*['"]""" + _ID_KEY + r"""['"]\s*\)
        |\bparams\s*\[\s*:""" + _ID_KEY + r"""\b
        # Go: r.URL.Query().Get("id") (net/http), mux.Vars(r)["id"]
        # (gorilla/mux), chi.URLParam(r, "id") (go-chi) — three unrelated
        # shapes for the same "route/query param" concept, none of which
        # look anything like the dict/dot-access patterns above.
        |\.Query\(\)\.Get\(\s*['"]""" + _ID_KEY + r"""['"]\s*\)
        |[Vv]ars\s*\([^)]*\)\s*\[\s*['"]""" + _ID_KEY + r"""['"]\s*\]
        |URLParam\s*\([^,]+,\s*['"]""" + _ID_KEY + r"""['"]\s*\)
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# A call that LOOKS like a single-row lookup/mutation, not just any
# function call — cuts down on firing inside functions that merely
# mention an id in passing (logging, validation, serialization) without
# ever using it to reach a specific row. Deliberately does NOT include
# bare "get(" despite how common `Repository.getById`-style names are in
# some codebases: the id-extraction shapes in ID_PARAM_RE themselves use
# `.get(` constantly (`request.args.get("id")` is the standard Flask
# idiom) — including bare "get" here would make this self-collide with
# its own source check on nearly every real route, firing regardless of
# whether any actual lookup call exists downstream at all. "getById" is
# kept since it's distinctive enough not to share that problem.
LOOKUP_SINK_RE = re.compile(
    r"""\b(?:find(?:_by_id|ById|OrFail)?|findOne|findById|getById|select|where|
         filter_by|get_object_or_404|update(?:One|Many)?|delete(?:One|Many)?|
         destroy|remove|save|first)\s*\(""",
    re.IGNORECASE | re.VERBOSE,
)

# Signals that an ownership/authorization check is actually happening.
# Deliberately does NOT include a bare "is this user logged in at all"
# decorator/call (login_required, jwt_required, isAuthenticated, ...) —
# see module docstring for why that distinction is the entire point.
OWNERSHIP_HINT_RE = re.compile(
    r"""current_user|currentUser|\bowner_id\b|\.owner\b|\buser_id\s*[=:]|
        session\s*\[\s*['"]user_id['"]|session\.get\(\s*['"]user_id['"]|
        \bg\.user\b|request\.user\b|req\.user\b|
        \bauthorize\b|\bcan\?\s*\(|\bpolicy\(|Auth::|auth\(\)->user|
        @PreAuthorize|hasPermission|hasRole|is_owner|isOwner|check_owner|checkOwner""",
    re.IGNORECASE | re.VERBOSE,
)

# How many lines above a function's own definition to pull in as
# "context" — enough to catch a decorator/annotation sitting directly on
# top of it (@login_required, @PreAuthorize, a Ruby before_action, ...)
# without reaching so far back that an unrelated previous function's body
# gets credited for this one's missing check.
_HEADER_LOOKBACK_LINES = 5

# Plain names that count as "this parameter IS the id", for the route-
# path-binding shape below (`@app.route("/orders/<int:id>") def
# view(id): ...` — the id arrives as a bound function parameter with no
# request.args/params-style extraction call anywhere in the body at all,
# which is at least as common a Flask/Express/Rails/Laravel idiom as the
# explicit extraction ID_PARAM_RE matches, so a parameter-name-only check
# is needed alongside it, not instead of it. Compared against a
# normalized (lowercased, underscores stripped) form of the parameter
# name, since the same concept is spelled `order_id` in Python/Ruby and
# `orderId` in PHP/Java/JS — comparing raw strings would miss every
# camelCase codebase entirely.
_ID_PARAM_NAMES = {_n.replace("_", "") for _n in (
    "id", "user_id", "uid", "account_id", "order_id", "file_id", "doc_id", "pk", "owner_id",
)}


def _normalize_param_name(name: str) -> str:
    # PHP's _param_names keeps the leading "$" sigil as part of the name
    # (it's part of the identifier in that grammar); every other
    # supported language's parameter names come back bare.
    return (name or "").lstrip("$").lower().replace("_", "")


@dataclass
class IdorFinding:
    file: str
    line_no: int
    line_text: str


def find_idor_candidates(path: str, language: str, source_bytes: bytes, lines: List[str]) -> List[IdorFinding]:
    """Best-effort: a function that pulls an id-like value straight from
    the request/route and hands it to something lookup/mutation-shaped,
    with no textual sign of an ownership check anywhere in the function
    (or its immediately preceding decorator/annotation lines). See the
    module docstring for exactly what this does and doesn't try to catch."""
    if language not in IDOR_LANGUAGES:
        return []
    parser = _ast._PARSERS.get(language)
    if parser is None:
        return []

    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return []

    scope_types = _ast.SCOPE_NODE_TYPES.get(language, set())
    findings: List[IdorFinding] = []
    seen_lines = set()

    def check_function(node) -> None:
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        body_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

        has_extraction = bool(ID_PARAM_RE.search(body_text))
        has_id_param = any(
            _normalize_param_name(n) in _ID_PARAM_NAMES for n in _ast._param_names(node, language)
        )
        if not has_extraction and not has_id_param:
            return
        if not LOOKUP_SINK_RE.search(body_text):
            return

        header_start = max(0, start_line - _HEADER_LOOKBACK_LINES)
        header_text = "".join(lines[header_start:start_line])
        if OWNERSHIP_HINT_RE.search(header_text + body_text):
            return

        # Point at the first line inside the function that actually shows
        # the id extraction — the line worth looking at first — when
        # there's an explicit extraction call; otherwise (the bound-
        # route-parameter shape, no extraction call anywhere) point at the
        # function's own signature line, since that's where the id-shaped
        # parameter is actually declared.
        line_no = start_line + 1
        line_text = lines[start_line].strip()[:200] if start_line < len(lines) else ""
        if has_extraction:
            for i in range(start_line, min(end_line + 1, len(lines))):
                if ID_PARAM_RE.search(lines[i]):
                    line_no = i + 1
                    line_text = lines[i].strip()[:200]
                    break
        if line_no not in seen_lines:
            seen_lines.add(line_no)
            findings.append(IdorFinding(file=path, line_no=line_no, line_text=line_text))

    def walk(node) -> None:
        if node.type in scope_types:
            check_function(node)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings
