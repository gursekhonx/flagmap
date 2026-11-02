"""
sql_construct.py — best-effort "SQL built via PHP string concatenation or
inline interpolation" detector. Extends the construction-site philosophy
patterns.py already uses for Python f-strings and JS template literals
(matching the query string's own shape — SQL keywords plus an
interpolated/concatenated value — rather than proving that value is
tainted) to two PHP shapes patterns.py's line-by-line regex matching
structurally cannot reach: the "." concatenation operator, and
double-quoted-string inline "$var" interpolation, either of which can
span several physical lines.

Found via real-world testing (see README) against OWASP Mutillidae II's
classes/SQLQueryHandler.php: every one of its DAO-style methods
(getUserAccount, getUserAccountByID, getAccountByClientId,
authenticateByClientCredentials, ...) builds a raw SQL query by joining
literal fragments with a function parameter via PHP's "." operator, split
across several physical lines for readability, e.g.:

    $lQueryString =
        "SELECT * FROM accounts
        WHERE username='".$pUsername.
        "' AND password='".$pPassword."'";

patterns.py's two existing PHP SQL-Injection regexes both miss this: one
requires the dangerous call itself (->query(...)/->exec(...)/etc.) to sit
on the same physical line as the literal string; the other requires the
assigned-to variable be named literally $sql or $query AND requires the
concatenated value be a $_GET/$_POST/$_REQUEST/$_COOKIE superglobal, by
name, on that one line. Here the sink is a custom wrapper method
(executeQuery() — not a name flagmap's sink list can recognize as a SQL
driver call without risking false-positives on every other method named
"execute*" in any codebase), the assigned-to variable is named
$lQueryString, the tainted-looking values are function parameters (not
superglobals), and the whole expression spans 2-4 physical lines. None of
patterns.py's rules were ever going to reach this shape — that needed an
AST-level, statement-boundary-aware pass, which is exactly what
ast_engine.py's tree-sitter parsing already gives every other check in
this file for free.

Deliberately uses the SAME "match the query string's own shape, not
provable taint" philosophy patterns.py already applies for Python
f-strings/JS template literals — this does NOT try to determine whether
the interpolated value actually originates from user input anywhere up
the call chain. That is a deliberate, already-accepted trade (see
README's "Architecture" and the "Full interprocedural taint tracking"
roadmap entry): a DAO/handler method that joins its own parameter into a
query string with no parameterization is bad practice regardless of what
any one caller happens to pass today, and in virtually every real CTF or
production case that parameter does eventually trace back to a request
somewhere. The cost is the same one patterns.py's own construction-site
rules already accept: a SQL-shaped string joined with a provably-constant
value (a hardcoded table name, say) would also match.

Two shapes, one tree walk, both anchored on the same parse tree
ast_engine.py's other checks already build:

- "." concatenation: a chain of `binary_expression` nodes joined by the
  "." operator. The string-literal segments among the chain's operands
  (each `encapsed_string`/`string` leaf), joined back together in order,
  are checked against SQL_SHAPE_RE; the chain also needs at least one
  operand that is not a string literal (a variable, a property access, a
  function call, ...).
- Inline interpolation: a single `encapsed_string` node — PHP's
  double-quoted strings interpolate "$var" directly, with no "."
  operator at all — whose own `string_content` children, joined
  together, are checked the same way, with the interpolated variable
  itself standing in for "at least one non-literal operand."

Both are walked in one pass so a "." chain whose own leaves include an
inline-interpolated `encapsed_string` is counted once, not twice: on
entering a concatenation chain's top node, every descendant that belongs
to that same chain is skipped as its own separate top-level check, and
only the chain's aggregate shape is evaluated.

Known blind spots, same honesty standard as idor.py/pickle_guard.py/
authn_guard.py:
- PHP-only. Python's "+"/"%" string concatenation and JS's "+" operator
  can span multiple physical lines in exactly the same way (Python/JS
  already have single-line f-string/template-literal construction-site
  coverage, but not this multi-line "+" case) — left open rather than
  guessed at without a real motivating example, same discipline as every
  other gap in this project's history.
- A "." chain or inline-interpolated string that happens to contain SQL
  keywords in a comment, a log message, or any other non-query string
  (e.g. an inline-interpolated "please SELECT an item FROM the list
  below, $username") would also match — same shape-not-meaning trade
  patterns.py already accepts for every construction-site rule it has.
- Only recognizes the literal PHP "." operator and double-quoted-string
  interpolation; a query built through a fluent query-builder's chained
  method calls (->where(...)->from(...)) is a different shape entirely
  and isn't attempted here.
"""

import re
from typing import List

from . import ast_engine as _ast

SQL_CONSTRUCT_LANGUAGES = {"php"}

STRING_LITERAL_NODE_TYPES = {"encapsed_string", "string"}

# Same keyword groups as patterns.py's Python f-string / JS template-literal
# construction-site rules, kept in sync deliberately — this is the same shape,
# just reached a different way for a language whose construction-site queries
# routinely span more than one physical line.
SQL_SHAPE_RE = re.compile(
    r"""\b(?:SELECT\b[^"']*\bFROM|INSERT\b[^"']*\bINTO|UPDATE\b[^"']*\bSET|DELETE\b[^"']*\bFROM)\b""",
    re.IGNORECASE,
)


class _ConstructFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file: str, line_no: int, line_text: str):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def _is_concat_node(node) -> bool:
    return node.type == "binary_expression" and any(c.type == "." for c in node.children)


def _encapsed_literal_and_hasvar(node, source_bytes: bytes):
    """For an `encapsed_string`/`string` node: join its own literal
    (`string_content`) children's text, and report whether it has any
    other (non-quote, non-string_content) child — i.e. an inline-
    interpolated variable/expression."""
    literal_parts = []
    has_var = False
    for child in node.children:
        if child.type == "string_content":
            literal_parts.append(source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore"))
        elif child.type in ("'", '"'):
            continue
        else:
            has_var = True
    return " ".join(literal_parts), has_var


def _flatten_concat(node, source_bytes: bytes):
    """Flatten a chain of '.' binary_expression nodes (left-to-right) into
    the joined literal text of all string-literal operands, plus whether
    any operand in the chain is not a string literal."""
    if _is_concat_node(node):
        literal_text = []
        has_nonliteral = False
        for child in node.children:
            if child.type == ".":
                continue
            sub_text, sub_nonliteral = _flatten_concat(child, source_bytes)
            literal_text.append(sub_text)
            has_nonliteral = has_nonliteral or sub_nonliteral
        return " ".join(t for t in literal_text if t), has_nonliteral
    if node.type in STRING_LITERAL_NODE_TYPES:
        text, has_var = _encapsed_literal_and_hasvar(node, source_bytes)
        return text, has_var
    # Any other operand (variable, property access, function call, ...)
    # contributes no literal text, but does count as "not a literal".
    return "", True


def find_sql_construction(path: str, language: str, source_bytes: bytes, lines: List[str]) -> List[_ConstructFinding]:
    """Best-effort: a PHP string, built via "." concatenation or inline
    interpolation, whose literal portions read as a SQL query (SELECT...
    FROM / INSERT...INTO / UPDATE...SET / DELETE...FROM) and which joins
    in at least one variable/expression. See this module's docstring for
    exactly what this does and doesn't try to prove. No-op outside PHP."""
    if language not in SQL_CONSTRUCT_LANGUAGES:
        return []
    parser = _ast._PARSERS.get(language)
    if parser is None:
        return []
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return []

    findings: List[_ConstructFinding] = []
    seen_lines = set()

    def visit(node, parent_is_concat: bool) -> None:
        is_concat = _is_concat_node(node)
        if is_concat and not parent_is_concat:
            literal_text, has_nonliteral = _flatten_concat(node, source_bytes)
            line_no = node.start_point[0] + 1
            if has_nonliteral and SQL_SHAPE_RE.search(literal_text) and line_no not in seen_lines:
                seen_lines.add(line_no)
                line_idx = node.start_point[0]
                line_text = lines[line_idx].strip()[:200] if line_idx < len(lines) else ""
                findings.append(_ConstructFinding(file=path, line_no=line_no, line_text=line_text))
        elif node.type in STRING_LITERAL_NODE_TYPES and not parent_is_concat:
            text, has_var = _encapsed_literal_and_hasvar(node, source_bytes)
            line_no = node.start_point[0] + 1
            if has_var and SQL_SHAPE_RE.search(text) and line_no not in seen_lines:
                seen_lines.add(line_no)
                line_idx = node.start_point[0]
                line_text = lines[line_idx].strip()[:200] if line_idx < len(lines) else ""
                findings.append(_ConstructFinding(file=path, line_no=line_no, line_text=line_text))

        for child in node.children:
            visit(child, is_concat)

    visit(tree.root_node, False)
    return findings
