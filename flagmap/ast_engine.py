"""
ast_engine.py — tree-sitter-based structural scanning for Python, JavaScript
and PHP.

Why this exists: taint.py/patterns.py's regex engine kept needing the same
category of fix over and over this project's testing history — a
quote-conflict false negative, a catastrophic-backtracking guard, a
multi-line miss, a variable name coincidentally matching an unrelated token
(an f-string prefix, a method name). None of those were "we didn't know this
vulnerability shape exists" — they were regex losing to the fact that source
code isn't text, it's a tree, and a line-oriented matcher can't see that.

This module matches over the actual parse tree instead:
  - quote style, nesting, whitespace, and line breaks are irrelevant — a
    tainted f-string/template-literal/encapsed-string is recognized by its
    AST shape (an `interpolation`/`template_substitution`/embedded
    `variable_name` node), not by a regex trying to not-match the wrong
    quote character.
  - taint tracking is scoped per function, not "same file, textual
    proximity" — a variable in one function can't be confused with a
    same-named variable in another.
  - "is the tainted variable the call's receiver or its argument" is just
    which field of the call node we look at — SINKS below has one table
    instead of taint.py's separate SINKS/METHOD_SINKS mechanism.

All eight CTF-relevant languages flagmap supports are now matched
structurally here — see README's "Architecture" section for each port's
own notes (Go's multi-value-assignment handling, Java's constructor-call
pseudo-sinks, Ruby's receiver-slot html_safe, Lua's and Rust's narrower,
collision-avoiding sink sets).
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Set

try:
    import tree_sitter_python as _ts_python
    import tree_sitter_javascript as _ts_javascript
    import tree_sitter_php as _ts_php
    from tree_sitter import Language, Parser

    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False

try:
    import tree_sitter_go as _ts_go

    _TREE_SITTER_GO_AVAILABLE = True
except ImportError:
    _TREE_SITTER_GO_AVAILABLE = False

try:
    import tree_sitter_java as _ts_java

    _TREE_SITTER_JAVA_AVAILABLE = True
except ImportError:
    _TREE_SITTER_JAVA_AVAILABLE = False

try:
    import tree_sitter_ruby as _ts_ruby

    _TREE_SITTER_RUBY_AVAILABLE = True
except ImportError:
    _TREE_SITTER_RUBY_AVAILABLE = False

try:
    import tree_sitter_lua as _ts_lua

    _TREE_SITTER_LUA_AVAILABLE = True
except ImportError:
    _TREE_SITTER_LUA_AVAILABLE = False

try:
    import tree_sitter_rust as _ts_rust

    _TREE_SITTER_RUST_AVAILABLE = True
except ImportError:
    _TREE_SITTER_RUST_AVAILABLE = False

from .taint import SEVERITY_BY_VULN, WHY_BY_VULN, PAYLOAD_BY_VULN


def _make_parser(lang_capsule):
    return Parser(Language(lang_capsule))


_PARSERS = {}
if _TREE_SITTER_AVAILABLE:
    _PARSERS["python"] = _make_parser(_ts_python.language())
    _PARSERS["js"] = _make_parser(_ts_javascript.language())
    _PARSERS["php"] = _make_parser(_ts_php.language_php())
if _TREE_SITTER_GO_AVAILABLE:
    _PARSERS["go"] = _make_parser(_ts_go.language())
if _TREE_SITTER_JAVA_AVAILABLE:
    _PARSERS["java"] = _make_parser(_ts_java.language())
if _TREE_SITTER_RUBY_AVAILABLE:
    _PARSERS["ruby"] = _make_parser(_ts_ruby.language())
if _TREE_SITTER_LUA_AVAILABLE:
    _PARSERS["lua"] = _make_parser(_ts_lua.language())
if _TREE_SITTER_RUST_AVAILABLE:
    _PARSERS["rust"] = _make_parser(_ts_rust.language())

AST_SUPPORTED_LANGUAGES = set(_PARSERS.keys())


@dataclass
class ASTFinding:
    file: str
    line_no: int
    line_text: str
    vuln_name: str
    severity: str
    why: str
    payload: str
    confidence: str
    tainted_var: Optional[str] = None


# --- per-language structural tables ----------------------------------------

# Node types that open a new taint scope: each function/method body is
# scanned independently, so a variable in one function is never confused
# with a same-named variable in another.
SCOPE_NODE_TYPES = {
    "python": {"function_definition"},
    "js": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
    "php": {"function_definition", "method_declaration"},
    # func_literal: Go's extremely common inline-handler idiom —
    # `http.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
    # ... })` — needs its own scope just like a named function, even though
    # it has no name (so it never gets one-hop interprocedural seeding,
    # which is fine: nothing calls an anonymous func by name anyway).
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "java": {"method_declaration", "constructor_declaration"},
    "ruby": {"method", "singleton_method"},
    # function_definition: Lua's anonymous `local handler = function(req)
    # ... end` idiom — same func_literal-style treatment as Go.
    "lua": {"function_declaration", "function_definition"},
    "rust": {"function_item"},
}

CALL_NODE_TYPES = {
    "python": {"call"},
    "js": {"call_expression"},
    "php": {"function_call_expression", "member_call_expression"},
    "go": {"call_expression"},
    "java": {"method_invocation"},
    "ruby": {"call"},
    "lua": {"function_call"},
    "rust": {"call_expression"},
}

ASSIGN_NODE_TYPES = {
    "python": {"assignment", "augmented_assignment"},
    "js": {"assignment_expression", "variable_declarator"},
    "php": {"assignment_expression"},
    # Go has no single "assignment" node whose left/right are bare
    # expressions — short_var_declaration (`:=`) and assignment_statement
    # (`=`) both wrap their sides in an expression_list (to support multi-
    # value assignment), handled specially in _assign_lhs_rhs below.
    "go": {"short_var_declaration", "assignment_statement"},
    # Java: `String sql = "...";` is a variable_declarator (name/value
    # fields) nested inside local_variable_declaration, same shape as JS's
    # variable_declarator; `sql = "...";` on its own is assignment_expression.
    "java": {"assignment_expression", "variable_declarator"},
    "ruby": {"assignment"},
    # Lua, like Go, wraps both sides in a list node (variable_list/
    # expression_list) to support `a, b = f()` multi-assignment — same
    # "still walk a single RHS even without a clean 1:1 name pairing"
    # handling in _assign_lhs_rhs below. `local x = y` is this same
    # assignment_statement node, just wrapped in a variable_declaration
    # that _walk's generic recursion descends through unchanged.
    "lua": {"assignment_statement"},
    "rust": {"let_declaration", "assignment_expression"},
}

IDENTIFIER_NODE_TYPE = {
    "python": "identifier",
    "js": "identifier",
    "php": "variable_name",
    "go": "identifier",
    "java": "identifier",
    "ruby": "identifier",
    "lua": "identifier",
    "rust": "identifier",
}

# A short regex checked only against the exact text of one already-AST
# bounded expression node (never a raw source line) — there's no adjacent
# code for it to accidentally match into, and no risk of catastrophic
# backtracking since nodes are small.
SOURCE_TEXT_RE = {
    "python": re.compile(r"""\brequest\.(?:args|form|values|json|files)\b"""),
    "js": re.compile(r"""\breq\.(?:query|params|body)\b"""),
    "php": re.compile(r"""\$_(?:GET|POST|REQUEST|COOKIE)\b"""),
    # net/http's Request methods, plus gorilla/mux and go-chi's router
    # param accessors — the three ways a Go CTF handler usually reads
    # attacker-controlled data. Deliberately NOT matching bare `r.URL` or
    # `r.Header` alone (too broad, matches tons of safe introspection) —
    # only the specific value-returning accessors.
    "go": re.compile(
        r"""\br\.(?:FormValue|PostFormValue|URL\.Query|URL\.Path|Header\.Get|Cookie)\b"""
        r"""|\bmux\.Vars\b|\bchi\.URLParam\b"""
    ),
    # javax.servlet's HttpServletRequest (raw Servlets and most lightweight
    # Java frameworks built on it) plus Spark Java's queryParams.
    "java": re.compile(r"""\.(?:getParameter|getParameterValues|getHeader|getQueryString|queryParams)\b"""),
    # Rails/Sinatra-style controller `params[...]`/`request.params`, plus
    # cookies/headers. Deliberately not matching bare `params` alone (every
    # method in a Rails controller mentions it for completely unrelated
    # reasons) — only the subscript/attribute-access shape that actually
    # reads a value out.
    "ruby": re.compile(r"""\bparams\s*\[|\brequest\.params\b|\bcookies\s*\[|\brequest\.headers\b"""),
    # OpenResty/nginx-lua's ngx.req accessors, plus a generic
    # params./req.params. accessor for Lapis-style and custom frameworks.
    # Only the SOURCE-RETURNING call/access itself needs to match here — a
    # variable later assigned from one of these (`local args =
    # ngx.req.get_uri_args()`) gets added to the tainted set by the normal
    # assignment-propagation step, so `args.name` a line later is already
    # covered by the plain identifier-in-tainted-set check with no extra
    # pattern needed for the derived access.
    "lua": re.compile(r"""\bngx\.req\.get_uri_args\b|\bngx\.req\.get_post_args\b|\bngx\.var\.arg_\w+\b|\bparams\."""),
    # actix-web/common Rust web framework request accessors.
    "rust": re.compile(r"""\.query_string\b|\.match_info\b|\.uri\(\)\.query\b"""),
}

SOURCE_CANDIDATE_NODE_TYPES = {
    "python": {"call", "subscript", "attribute"},
    "js": {"member_expression", "subscript_expression"},
    "php": {"subscript_expression", "variable_name"},
    "go": {"call_expression", "selector_expression", "index_expression"},
    "java": {"method_invocation"},
    "ruby": {"element_reference", "call"},
    "lua": {"function_call", "dot_index_expression"},
    "rust": {"call_expression", "field_expression"},
}

# FastAPI/Flask-style: a route handler's own parameters are just as
# attacker-controlled as request.args — Python only (this is where
# taint.py's FASTAPI_PARAM_RE/ROUTE_DECORATOR_RE came from).
ROUTE_DECORATOR_RE = re.compile(r"""@\w+\.(?:get|post|put|delete|patch|route)\b""")
TAINTED_PARAM_TYPE_RE = re.compile(r"""^(?:str|int|float|UUID|Optional\[)""")

# Dangerous sink calls/methods. Each entry: (vuln_name, slot, var_set),
# where slot is "arg0" (first argument must be tainted — a query string, a
# path, a template) or "receiver" (the object the method is called ON must
# be tainted — e.g. `f.save(...)` where `f` came from request.files), and
# var_set is "tainted" (the normal request-input taint set) or "built"
# (see Format String Injection below — a different, independent signal).
# Collapsing argument-sinks and receiver-sinks into one table is the direct
# structural payoff of having an AST: the call node already exposes both
# its receiver and its arguments as separate fields, so there's no reason
# to treat them as two different mechanisms the way taint.py's
# SINKS/METHOD_SINKS split had to.
SINKS = {
    "python": {
        "execute": ("SQL Injection", "arg0", "tainted"),
        "executemany": ("SQL Injection", "arg0", "tainted"),
        "system": ("Command Injection", "arg0", "tainted"),
        "popen": ("Command Injection", "arg0", "tainted"),
        "open": ("Path Traversal / LFI", "arg0", "tainted"),
        "send_file": ("Path Traversal / LFI", "arg0", "tainted"),
        "loads": ("Unsafe Deserialization", "arg0", "tainted"),
        "render_template_string": ("Server-Side Template Injection (SSTI)", "arg0", "tainted"),
        "eval": ("Command Injection / RCE", "arg0", "tainted"),
        "redirect": ("Open Redirect", "arg0", "tainted"),
        "save": ("Unrestricted File Upload", "receiver", "tainted"),
        "format": ("Format String Injection", "receiver", "built"),
    },
    "js": {
        "query": ("SQL Injection", "arg0", "tainted"),
        "execute": ("SQL Injection", "arg0", "tainted"),
        "exec": ("Command Injection", "arg0", "tainted"),
        "execSync": ("Command Injection", "arg0", "tainted"),
        "readFile": ("Path Traversal / LFI", "arg0", "tainted"),
        "readFileSync": ("Path Traversal / LFI", "arg0", "tainted"),
        "sendFile": ("Path Traversal / LFI", "arg0", "tainted"),
        "renderString": ("Server-Side Template Injection (SSTI)", "arg0", "tainted"),
        "eval": ("Command Injection / RCE", "arg0", "tainted"),
        "redirect": ("Open Redirect", "arg0", "tainted"),
    },
    "php": {
        "query": ("SQL Injection", "arg0", "tainted"),
        "mysqli_query": ("SQL Injection", "arg1", "tainted"),
        "exec": ("Command Injection", "arg0", "tainted"),
        "system": ("Command Injection", "arg0", "tainted"),
        "shell_exec": ("Command Injection", "arg0", "tainted"),
        "passthru": ("Command Injection", "arg0", "tainted"),
        "popen": ("Command Injection", "arg0", "tainted"),
        "fopen": ("Path Traversal / LFI", "arg0", "tainted"),
        "unserialize": ("Unsafe Deserialization", "arg0", "tainted"),
        "eval": ("Command Injection / RCE", "arg0", "tainted"),
    },
    "go": {
        # database/sql (and compatible drivers): Query/QueryRow/Exec all
        # take the SQL string as their first argument.
        "Query": ("SQL Injection", "arg0", "tainted"),
        "QueryRow": ("SQL Injection", "arg0", "tainted"),
        "Exec": ("SQL Injection", "arg0", "tainted"),
        # os/exec: exec.Command(name, arg...) — name is arg0.
        "Command": ("Command Injection", "arg0", "tainted"),
        # os/ioutil: path is arg0.
        "Open": ("Path Traversal / LFI", "arg0", "tainted"),
        "ReadFile": ("Path Traversal / LFI", "arg0", "tainted"),
        "Create": ("Path Traversal / LFI", "arg0", "tainted"),
        # net/http: ServeFile(w, r, name) — the path is the 3rd positional
        # argument (index 2), not arg0.
        "ServeFile": ("Path Traversal / LFI", "arg2", "tainted"),
        # net/http: Redirect(w, r, url, code) — same shape, url is index 2.
        "Redirect": ("Open Redirect", "arg2", "tainted"),
        # fmt.Fprintf(w, tainted)/fmt.Fprint(w, tainted): writing request
        # data straight to an http.ResponseWriter with no html/template
        # escaping — the Go equivalent of PHP's bare `echo $_GET[...]`.
        # Deliberately NOT "Write" (bytes.Buffer.Write, file.Write,
        # hash.Write, ... — far too generic a method name to key a sink on
        # without naming false positives on every unrelated byte-slice
        # write in the codebase).
        "Fprintf": ("Cross-Site Scripting (XSS)", "arg1", "tainted"),
        "Fprint": ("Cross-Site Scripting (XSS)", "arg1", "tainted"),
    },
    "java": {
        # java.sql.Statement — "execute" is also ExecutorService.execute(
        # Runnable), but that only matters if a Runnable reference happens
        # to share a name with a tainted String, and AST findings are
        # always confidence="possible" precisely for cases like this.
        "executeQuery": ("SQL Injection", "arg0", "tainted"),
        "executeUpdate": ("SQL Injection", "arg0", "tainted"),
        "execute": ("SQL Injection", "arg0", "tainted"),
        "exec": ("Command Injection", "arg0", "tainted"),  # Runtime.getRuntime().exec(cmd)
        "sendRedirect": ("Open Redirect", "arg0", "tainted"),
    },
    "ruby": {
        # ActiveRecord raw-SQL escape hatches.
        "execute": ("SQL Injection", "arg0", "tainted"),
        "exec_query": ("SQL Injection", "arg0", "tainted"),
        "system": ("Command Injection", "arg0", "tainted"),
        "popen": ("Command Injection", "arg0", "tainted"),
        "open": ("Path Traversal / LFI", "arg0", "tainted"),
        # Marshal.load / YAML.load on untrusted input — classic Rails RCE
        # gadget-chain vector (see README's "What it catches").
        "load": ("Unsafe Deserialization", "arg0", "tainted"),
        "redirect_to": ("Open Redirect", "arg0", "tainted"),
        # `.html_safe` is Rails' explicit "turn off auto-escaping" footgun —
        # ERB escapes by default, so the vulnerability IS calling this on
        # tainted data, not any particular sink function. Receiver-slot,
        # not arg-slot: the thing that must be tainted is the string this
        # is called ON, not anything passed to it (it takes no arguments).
        "html_safe": ("Cross-Site Scripting (XSS)", "receiver", "tainted"),
    },
    "lua": {
        # os.execute(cmd) — the unambiguous, canonical stdlib shell-exec
        # call. Deliberately NOT mapping "execute" to SQL Injection too
        # (some Lua DB drivers, e.g. LuaSQL, also call their raw-query
        # method "execute") — one callee name can only mean one vuln class
        # in this table, and os.execute is the far more common/unambiguous
        # of the two. "query" below covers the SQL side instead (matches
        # lua-resty-mysql and friends) — the regex layer still independently
        # catches LuaSQL-style `conn:execute(sql)` via its own SQL-keyword
        # text pattern, which doesn't have this naming collision problem.
        "execute": ("Command Injection", "arg0", "tainted"),
        "popen": ("Command Injection", "arg0", "tainted"),
        "query": ("SQL Injection", "arg0", "tainted"),
        "open": ("Path Traversal / LFI", "arg0", "tainted"),
        "load": ("Command Injection / RCE", "arg0", "tainted"),       # Lua 5.2+
        "loadstring": ("Command Injection / RCE", "arg0", "tainted"),  # Lua 5.1
        "redirect": ("Open Redirect", "arg0", "tainted"),  # ngx.redirect(url)
    },
    "rust": {
        # Deliberately NOT including Command::new / File::open-via-`new` —
        # "new" is Rust's universal constructor-method convention (every
        # struct has one), so keying a sink on that bare name would flag
        # unrelated constructors across the whole language. Also
        # deliberately NOT trying to catch `format!`-built SQL here: a
        # macro invocation's arguments are an opaque, unparsed token tree
        # in tree-sitter (macros aren't part of Rust's normal expression
        # grammar), so there's no clean AST shape to match against — the
        # existing regex pattern already covers that shape and isn't
        # actually disadvantaged by being regex-based here, unlike the
        # string-concatenation cases AST matching fixed in other languages.
        "execute": ("SQL Injection", "arg0", "tainted"),
        "query": ("SQL Injection", "arg0", "tainted"),
        "open": ("Path Traversal / LFI", "arg0", "tainted"),  # File::open(path)
    },
}

# Java-only: `new File(path)`/`new FileInputStream(path)`/etc. are
# constructor calls (object_creation_expression), not method_invocation —
# same reason PHP's include/require needed their own pseudo-sink table
# rather than fitting the regular call-shaped SINKS above.
JAVA_PATH_CONSTRUCTOR_SINKS = {"File", "FileInputStream", "FileReader", "FileOutputStream", "FileWriter"}

# PHP-only: include/require are language constructs, not function calls, so
# they get their own node types in the grammar rather than showing up as a
# "call" — handled as a one-slot pseudo-sink (the whole node's own
# named_children *are* the target expression, include/require has no
# separate "arguments" field to pull arg0 out of).
PHP_PSEUDO_SINKS = {
    "include_expression": "Path Traversal / LFI",
    "include_once_expression": "Path Traversal / LFI",
    "require_expression": "Path Traversal / LFI",
    "require_once_expression": "Path Traversal / LFI",
}

_SAME_ORIGIN_REDIRECT_RE = re.compile(r"""^[a-zA-Z]{0,2}["'`]/(?!/)""")

# PHP: an echoed expression wrapped in one of these is neutralized for XSS
# purposes and shouldn't be flagged even though its argument is tainted —
# `h()`/`e()`/`esc()` are extremely common hand-rolled htmlspecialchars
# wrapper names (Rails-style convention carried into PHP codebases), not
# just the literal `htmlspecialchars` call itself.
PHP_SAFE_ECHO_WRAPPER_RE = re.compile(
    r"""^(?:htmlspecialchars|htmlentities|strip_tags|filter_var|urlencode|rawurlencode|
         json_encode|intval|floatval|boolval|h|e|esc|escape)$""",
    re.IGNORECASE | re.VERBOSE,
)
PHP_SAFE_CAST_TYPES = {"int", "integer", "float", "double", "bool", "boolean"}


def _is_safe_echo_expr(node) -> bool:
    if node.type == "cast_expression":
        named = node.named_children
        if named and named[0].type == "cast_type":
            return _text(named[0]).strip().lower() in PHP_SAFE_CAST_TYPES
    if node.type == "function_call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "name" and PHP_SAFE_ECHO_WRAPPER_RE.match(_text(fn)):
            return True
    return False


def _text(node) -> str:
    return node.text.decode("utf-8", errors="ignore")


def _is_same_origin_redirect(node) -> bool:
    return bool(_SAME_ORIGIN_REDIRECT_RE.match(_text(node).strip()))


class _ScopeState:
    __slots__ = ("tainted", "built")

    def __init__(self):
        self.tainted: Set[str] = set()
        self.built: Set[str] = set()


def _matched_taint_source(node, var_set: Set[str], language: str) -> Optional[str]:
    """Returns the matched variable name (or a pseudo-label for a direct
    source access) if `node`'s subtree is tainted w.r.t. var_set, else None.
    This single recursive walk does double duty as both the boolean
    "is this expression tainted" check and, for display, "which variable
    caused it" — there's no separate literal-detection pass needed the way
    taint.py's regex engine required _is_plain_literal: a pure string
    literal simply has no identifier/source node anywhere in its subtree,
    so this naturally returns None for it."""
    if node is None:
        return None

    node_type = node.type

    if node_type in SOURCE_CANDIDATE_NODE_TYPES[language]:
        if SOURCE_TEXT_RE[language].search(_text(node)):
            return "(request data)"

    ident_type = IDENTIFIER_NODE_TYPE[language]
    if node_type == ident_type:
        name = _text(node)
        return name if name in var_set else None

    # Python-only special case: an `attribute` node's "attribute" field is a
    # property/method NAME, not a variable reference (unlike JS, where that
    # position has its own distinct node type `property_identifier` and so
    # never collides with `identifier` in the first place). Only the
    # `object` side can carry a real variable reference.
    if language == "python" and node_type == "attribute":
        return _matched_taint_source(node.child_by_field_name("object"), var_set, language)

    for child in node.named_children:
        found = _matched_taint_source(child, var_set, language)
        if found:
            return found
    return None


def _assign_lhs_rhs(node, language):
    t = node.type
    if language == "python":
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    if language == "js":
        if t == "variable_declarator":
            return node.child_by_field_name("name"), node.child_by_field_name("value")
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    if language == "php":
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    if language == "go":
        # Go's `:=`/`=` always wrap both sides in an expression_list, to
        # support multi-value assignment (`a, b := f()`, `a, b = b, a`).
        # Only a clean single-name<-single-expression pairing gets taint
        # PROPAGATED to a name (anything else — multi-target, multi-value
        # swaps — is too ambiguous to pair up correctly, so lhs comes back
        # None and no variable gets tainted). But a single right-hand
        # expression (even with 2+ names on the left, e.g. the extremely
        # common `rows, err := db.Query(sql)`) is still returned as rhs so
        # the caller's _walk still recurses into it and catches `db.Query`
        # itself as a sink — losing that would silently blind the engine
        # to every Go DB call written the idiomatic (err-returning) way.
        if t in ("short_var_declaration", "assignment_statement"):
            left_list = node.child_by_field_name("left")
            right_list = node.child_by_field_name("right")
            if left_list is None or right_list is None:
                return None, None
            right_children = right_list.named_children
            if len(right_children) != 1:
                return None, None  # multi-value RHS (rare, e.g. `a, b := f(), g()`)
            rhs = right_children[0]
            left_children = left_list.named_children
            lhs = left_children[0] if len(left_children) == 1 else None
            return lhs, rhs
        return None, None
    if language == "java":
        if t == "variable_declarator":
            return node.child_by_field_name("name"), node.child_by_field_name("value")
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    if language == "ruby":
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    if language == "lua":
        # Same shape as Go: both sides are list nodes (variable_list/
        # expression_list) with no field names of their own, to support
        # `a, b = f()` multi-assignment — only a clean single<-single
        # pairing gets taint PROPAGATED to a name, but a lone right-hand
        # expression is still returned for _walk to recurse into (catching
        # a sink call on the RHS) even when the left side has 2+ names.
        if t == "assignment_statement":
            var_list = next((c for c in node.named_children if c.type == "variable_list"), None)
            expr_list = next((c for c in node.named_children if c.type == "expression_list"), None)
            if var_list is None or expr_list is None:
                return None, None
            expr_children = expr_list.named_children
            if len(expr_children) != 1:
                return None, None
            rhs = expr_children[0]
            var_children = var_list.named_children
            lhs = var_children[0] if len(var_children) == 1 else None
            return lhs, rhs
        return None, None
    if language == "rust":
        if t == "let_declaration":
            return node.child_by_field_name("pattern"), node.child_by_field_name("value")
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    return None, None


def _call_info(node, language):
    """Returns (callee_name, is_method, receiver_node, args_node) for a
    call-shaped node, or None if this call's shape isn't one we can read
    (e.g. calling a computed/dynamic expression rather than a plain name)."""
    t = node.type
    if language == "python":
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return None
        if fn.type == "attribute":
            method_name_node = fn.child_by_field_name("attribute")
            if method_name_node is None:
                return None
            return _text(method_name_node), True, fn.child_by_field_name("object"), args
        if fn.type == "identifier":
            return _text(fn), False, None, args
        return None
    if language == "js":
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return None
        if fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            if prop is None:
                return None
            return _text(prop), True, fn.child_by_field_name("object"), args
        if fn.type == "identifier":
            return _text(fn), False, None, args
        return None
    if language == "php":
        if t == "function_call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is None or fn.type != "name":
                return None
            return _text(fn), False, None, args
        if t == "member_call_expression":
            name_node = node.child_by_field_name("name")
            args = node.child_by_field_name("arguments")
            if name_node is None:
                return None
            return _text(name_node), True, node.child_by_field_name("object"), args
        return None
    if language == "go":
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return None
        if fn.type == "selector_expression":
            # `db.Query(...)`, `exec.Command(...)`, `r.URL.Query().Get(...)`
            # — the field name is the callee, the operand is the receiver
            # (package qualifier OR a real receiver like `db`/`r`; SINKS'
            # go table only keys on arg-slot sinks today, so the receiver
            # distinction doesn't matter yet, but is threaded through for
            # consistency with the other languages / future receiver sinks).
            field = fn.child_by_field_name("field")
            if field is None:
                return None
            return _text(field), True, fn.child_by_field_name("operand"), args
        if fn.type == "identifier":
            return _text(fn), False, None, args
        return None
    if language == "java":
        if t != "method_invocation":
            return None
        name_node = node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        if name_node is None:
            return None
        obj = node.child_by_field_name("object")
        return _text(name_node), obj is not None, obj, args
    if language == "ruby":
        if t != "call":
            return None
        method_node = node.child_by_field_name("method")
        if method_node is None:
            return None
        args = node.child_by_field_name("arguments")
        receiver = node.child_by_field_name("receiver")
        return _text(method_node), receiver is not None, receiver, args
    if language == "lua":
        if t != "function_call":
            return None
        name_field = node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        if name_field is None:
            return None
        if name_field.type == "method_index_expression":
            method = name_field.child_by_field_name("method")
            if method is None:
                return None
            return _text(method), True, name_field.child_by_field_name("table"), args
        if name_field.type == "dot_index_expression":
            field = name_field.child_by_field_name("field")
            if field is None:
                return None
            return _text(field), True, name_field.child_by_field_name("table"), args
        if name_field.type == "identifier":
            return _text(name_field), False, None, args
        return None
    if language == "rust":
        if t != "call_expression":
            return None
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return None
        if fn.type == "field_expression":
            field = fn.child_by_field_name("field")
            if field is None:
                return None
            return _text(field), True, fn.child_by_field_name("value"), args
        if fn.type == "scoped_identifier":
            # `File::open(path)` — treats the qualifying path (`File`) as a
            # pseudo-receiver, same as Go's package-qualified calls; no
            # current rust sink keys on "receiver" slot, but this keeps the
            # shape consistent and ready for one if that changes.
            name_node = fn.child_by_field_name("name")
            if name_node is None:
                return None
            return _text(name_node), True, fn.child_by_field_name("path"), args
        if fn.type == "identifier":
            return _text(fn), False, None, args
        return None
    return None


def _nth_arg_expr(args_node, language, index: int):
    if args_node is None:
        return None
    named = list(args_node.named_children)
    if index >= len(named):
        return None
    arg = named[index]
    if language == "php" and arg.type == "argument":
        inner = list(arg.named_children)
        arg = inner[0] if inner else arg
    return arg


def _line_text(lines: List[str], node) -> str:
    row = node.start_point[0]
    if 0 <= row < len(lines):
        return lines[row].strip()[:200]
    return _text(node).strip()[:200]


def _emit(findings, path, lines, node, vuln, tainted_var):
    findings.append(ASTFinding(
        file=path,
        line_no=node.start_point[0] + 1,
        line_text=_line_text(lines, node),
        vuln_name=vuln,
        severity=SEVERITY_BY_VULN.get(vuln, "medium"),
        why=f"{WHY_BY_VULN.get(vuln, 'Tainted variable reaches a dangerous sink.')} (tainted var: `{tainted_var}`)",
        payload=PAYLOAD_BY_VULN.get(vuln, "Investigate manually."),
        confidence="possible",
        tainted_var=tainted_var,
    ))


def _check_call_sink(node, language, state: _ScopeState, findings, path, lines):
    info = _call_info(node, language)
    if info is None:
        return
    callee_name, is_method, receiver, args = info
    sink = SINKS[language].get(callee_name)
    if not sink:
        return
    vuln, slot, var_set_name = sink
    var_set = state.built if var_set_name == "built" else state.tainted

    if slot == "receiver":
        if not is_method or receiver is None:
            return
        if receiver.type != IDENTIFIER_NODE_TYPE[language]:
            return
        name = _text(receiver)
        if name in var_set:
            _emit(findings, path, lines, node, vuln, name)
        return

    if slot.startswith("arg"):
        index = int(slot[3:])
        target = _nth_arg_expr(args, language, index)
        if target is None:
            return
        if vuln == "Open Redirect" and _is_same_origin_redirect(target):
            return  # a leading single "/" can only ever redirect on-site
        matched = _matched_taint_source(target, var_set, language)
        if matched:
            _emit(findings, path, lines, node, vuln, matched)


def _check_php_pseudo_sink(node, state: _ScopeState, findings, path, lines):
    vuln = PHP_PSEUDO_SINKS[node.type]
    matched = _matched_taint_source(node, state.tainted, "php")
    if matched:
        _emit(findings, path, lines, node, vuln, matched)


def _check_java_path_constructor(node, state: _ScopeState, findings, path, lines):
    type_node = node.child_by_field_name("type")
    if type_node is None or _text(type_node) not in JAVA_PATH_CONSTRUCTOR_SINKS:
        return
    args = node.child_by_field_name("arguments")
    target = _nth_arg_expr(args, "java", 0)
    if target is None:
        return
    matched = _matched_taint_source(target, state.tainted, "java")
    if matched:
        _emit(findings, path, lines, node, "Path Traversal / LFI", matched)


def _check_php_echo(node, state: _ScopeState, findings, path, lines):
    # Check each comma-separated echoed expression independently (`echo $a,
    # $b;` is valid PHP) so a safe-wrapped one doesn't mask an unsafe one,
    # and so a safe wrapper (h()/htmlspecialchars()/an (int) cast) on THIS
    # expression is recognized even when a sibling expression is unsafe.
    for child in node.named_children:
        if _is_safe_echo_expr(child):
            continue
        matched = _matched_taint_source(child, state.tainted, "php")
        if matched:
            _emit(findings, path, lines, node, "Cross-Site Scripting (XSS)", matched)
            return  # one flag per echo statement is enough


def _seed_route_params(func_node, state: _ScopeState):
    params = func_node.child_by_field_name("parameters")
    if params is None:
        return
    for p in params.named_children:
        if p.type == "identifier":
            state.tainted.add(_text(p))
        elif p.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
            ident = next((c for c in p.named_children if c.type == "identifier"), None)
            type_node = next((c for c in p.named_children if c.type == "type"), None)
            if ident is None:
                continue
            if type_node is None or TAINTED_PARAM_TYPE_RE.match(_text(type_node)):
                state.tainted.add(_text(ident))


def _func_def_name(func_node, language) -> Optional[str]:
    name_node = func_node.child_by_field_name("name")
    if name_node is None:
        return None
    if language == "lua":
        # Lua's idiomatic OOP method style, `function Handler:run_search(term)`
        # (or the dot-defined equivalent, `function Handler.run_search(self,
        # term)`), makes the "name" field a method_index_expression/
        # dot_index_expression whose TEXT is the qualified "Handler:
        # run_search" — but a call site (`self:run_search(term)`) only ever
        # resolves the bare "run_search" part (see _call_info's lua branch).
        # Using the qualified text as the registered key here would never
        # match any real call site, silently breaking one-hop seeding for
        # the single most common Lua OOP method-definition shape — so pull
        # just the unqualified method/field name out instead.
        if name_node.type == "method_index_expression":
            method = name_node.child_by_field_name("method")
            return _text(method) if method is not None else None
        if name_node.type == "dot_index_expression":
            field = name_node.child_by_field_name("field")
            return _text(field) if field is not None else None
    return _text(name_node)


def _param_names(func_node, language) -> List[Optional[str]]:
    """Ordered parameter names (None for a positional slot flagmap doesn't
    know how to name — *args, destructuring, etc. — to keep call-site
    argument indices aligned)."""
    params = func_node.child_by_field_name("parameters")
    if params is None:
        return []
    names: List[Optional[str]] = []
    for p in params.named_children:
        if language == "rust" and p.type == "self_parameter":
            # `&self`/`&mut self`/`self` is never present in a `.`-call's
            # explicit arguments (same as every other language's implicit
            # receiver) — appending a None placeholder for it here would
            # reserve a slot that shifts every real parameter's index one
            # past where the call site's (receiver-less) argument list
            # expects it, silently breaking one-hop seeding for every
            # `&self` method. Skipping it outright (not even a None entry)
            # keeps the two index spaces aligned.
            continue
        if language == "python" and p is params.named_children[0] and _is_python_self_param(func_node, p):
            # Same index-alignment problem as Rust's self_parameter above,
            # for Python's `self`/`cls` — see _is_python_self_param's
            # docstring for why both the ancestry and the name check matter.
            continue
        if language == "python":
            if p.type == "identifier":
                names.append(_text(p))
            elif p.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                ident = next((c for c in p.named_children if c.type == "identifier"), None)
                names.append(_text(ident) if ident else None)
            else:
                names.append(None)
        elif language == "js":
            names.append(_text(p) if p.type == "identifier" else None)
        elif language == "php":
            if p.type == "simple_parameter":
                vn = p.child_by_field_name("name")
                names.append(_text(vn) if vn else None)
            else:
                names.append(None)
        elif language == "go":
            if p.type == "parameter_declaration":
                vn = p.child_by_field_name("name")
                # Go allows a grouped declaration (`func f(a, b string)`),
                # which the grammar represents as ONE parameter_declaration
                # with the "name" field only giving the first identifier —
                # that shared-type shorthand is rare enough in CTF handler
                # signatures (vs. the one-name-per-param net/http style) that
                # losing the second name here is an acceptable, documented
                # gap rather than something worth a bespoke multi-name path.
                names.append(_text(vn) if vn else None)
            else:
                names.append(None)
        elif language == "java":
            if p.type == "formal_parameter":
                vn = p.child_by_field_name("name")
                names.append(_text(vn) if vn else None)
            else:
                names.append(None)
        elif language == "ruby":
            names.append(_text(p) if p.type == "identifier" else None)
        elif language == "lua":
            names.append(_text(p) if p.type == "identifier" else None)
        elif language == "rust":
            if p.type == "parameter":
                vn = p.child_by_field_name("pattern")
                names.append(_text(vn) if vn else None)
            else:
                names.append(None)
        else:
            names.append(None)
    return names


def _is_python_self_param(func_node, first_param) -> bool:
    """Whether `first_param` is a plain-method's implicit self/cls — bound
    automatically at the call site (`obj.method(x)` never passes it
    explicitly), so it has to be excluded from the parameter-name list for
    one-hop seeding's call-site-arg-index <-> param-index alignment to
    hold, the same way Rust's distinctly-typed `self_parameter` node and
    Lua's colon-method call shape already are elsewhere in this file.
    Unlike those two, Python's `self`/`cls` is just an ordinary
    "identifier" parameter with no structural marker of its own, so this
    has to check two things instead of one node type: that the function
    sits directly inside a class body (so a plain top-level function
    merely happening to name its first param "self" is untouched — such a
    function IS called with that argument explicit, e.g. `helper(x)`), and
    that the first parameter's own name is actually "self"/"cls" (so an
    `@staticmethod`, which shares the exact same class-body ancestry but
    takes no implicit receiver, doesn't have its real first parameter
    wrongly dropped)."""
    if first_param is None or first_param.type != "identifier":
        return False
    if _text(first_param) not in ("self", "cls"):
        return False
    parent = func_node.parent
    if parent is None or parent.type != "block":
        return False
    grandparent = parent.parent
    return grandparent is not None and grandparent.type == "class_definition"


def _collect_function_defs(root, language) -> dict:
    """Map function/method name -> its definition node, found anywhere in
    the file (not scope-limited — this is purely for the one-hop
    interprocedural seeding below, not for taint tracking itself)."""
    func_defs = {}
    scope_types = SCOPE_NODE_TYPES[language]

    def walk(node):
        if node.type in scope_types:
            name = _func_def_name(node, language)
            if name and name not in func_defs:
                func_defs[name] = node
        for c in node.named_children:
            walk(c)

    walk(root)
    return func_defs


class _Ctx:
    """Bundles the read-mostly, file-wide state threaded through _walk:
    which language/path/lines we're scanning, the file's own function
    definitions (for one-hop interprocedural seeding), the seeds collected
    from call sites, where findings go, and whether this pass should emit
    findings or only record call-site seeds (see scan_ast)."""

    def __init__(self, language, path, lines, func_defs, seeds, findings, recording):
        self.language = language
        self.path = path
        self.lines = lines
        self.func_defs = func_defs
        self.seeds = seeds
        self.findings = findings
        self.recording = recording


def _record_call_site_seeds(node, language, state: _ScopeState, ctx: _Ctx):
    """One-hop interprocedural taint: `helper(data)` where `data` is
    tainted in the CALLER's scope seeds `helper`'s corresponding parameter
    as tainted for the pass that walks `helper`'s own body. Without this, a
    route handler that reads request data and hands it to a plain helper
    function (`parse_qr_code(data)`) would have its real vulnerability
    missed, because each function is (correctly) its own taint scope and
    has no visibility into what its caller passed — this is the one
    deliberate, narrow bridge across that boundary. It's one hop only (not
    a fixed point to arbitrary depth): good enough for the common
    handler-calls-helper shape without building a full call graph."""
    info = _call_info(node, language)
    if info is None:
        return
    callee_name = info[0]
    args = info[3]
    func_node = ctx.func_defs.get(callee_name)
    if func_node is None or args is None:
        return
    named = list(args.named_children)
    for i, arg in enumerate(named):
        real_arg = arg
        if language == "php" and arg.type == "argument":
            inner = list(arg.named_children)
            real_arg = inner[0] if inner else arg
        if _matched_taint_source(real_arg, state.tainted, language):
            ctx.seeds.setdefault(callee_name, set()).add(i)


def _enter_scope(func_node, language, ctx: _Ctx, route_decorated: bool) -> _ScopeState:
    nested = _ScopeState()
    if route_decorated:
        _seed_route_params(func_node, nested)
    seeded_indices = ctx.seeds.get(_func_def_name(func_node, language) or "", set())
    if seeded_indices:
        names = _param_names(func_node, language)
        for i in seeded_indices:
            if i < len(names) and names[i]:
                nested.tainted.add(names[i])
    return nested


def _walk(node, language, state: _ScopeState, ctx: _Ctx):
    t = node.type
    findings = ctx.findings
    path, lines = ctx.path, ctx.lines

    if language == "python" and t == "decorated_definition":
        decorator_text = " ".join(_text(c) for c in node.named_children if c.type == "decorator")
        func_node = next((c for c in node.named_children if c.type == "function_definition"), None)
        if func_node is not None:
            nested = _enter_scope(func_node, language, ctx, bool(ROUTE_DECORATOR_RE.search(decorator_text)))
            for c in func_node.named_children:
                _walk(c, language, nested, ctx)
        return

    if t in SCOPE_NODE_TYPES[language]:
        nested = _enter_scope(node, language, ctx, False)
        for c in node.named_children:
            _walk(c, language, nested, ctx)
        return

    if t in ASSIGN_NODE_TYPES[language]:
        lhs, rhs = _assign_lhs_rhs(node, language)
        if lhs is not None and lhs.type == IDENTIFIER_NODE_TYPE[language] and rhs is not None:
            name = _text(lhs)
            if _matched_taint_source(rhs, state.tainted, language):
                state.tainted.add(name)
            if language == "python" and t == "augmented_assignment":
                state.built.add(name)
        if rhs is not None:
            _walk(rhs, language, state, ctx)
        return

    if t in CALL_NODE_TYPES[language]:
        if not ctx.recording:
            _check_call_sink(node, language, state, findings, path, lines)
        _record_call_site_seeds(node, language, state, ctx)
        for c in node.named_children:
            _walk(c, language, state, ctx)
        return

    if language == "php" and t == "echo_statement":
        if not ctx.recording:
            _check_php_echo(node, state, findings, path, lines)
        for c in node.named_children:
            _walk(c, language, state, ctx)
        return

    if language == "php" and t in PHP_PSEUDO_SINKS:
        if not ctx.recording:
            _check_php_pseudo_sink(node, state, findings, path, lines)
        for c in node.named_children:
            _walk(c, language, state, ctx)
        return

    if language == "java" and t == "object_creation_expression":
        if not ctx.recording:
            _check_java_path_constructor(node, state, findings, path, lines)
        for c in node.named_children:
            _walk(c, language, state, ctx)
        return

    for c in node.named_children:
        _walk(c, language, state, ctx)


def scan_ast(path: str, language: str, source_bytes: bytes) -> List[ASTFinding]:
    """Entry point: parse `source_bytes` as `language` (must be in
    AST_SUPPORTED_LANGUAGES) and return the findings from walking it.

    Runs the walk twice: the first pass only records which call-site
    arguments into the file's own functions are tainted (see
    _record_call_site_seeds), producing no findings; the second pass
    re-walks from scratch with those seeds available, so a plain helper
    function whose only taint source is what its caller passed in (not a
    route decorator) still gets its parameters seeded correctly."""
    parser = _PARSERS.get(language)
    if parser is None:
        return []
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return []
    lines = source_bytes.decode("utf-8", errors="ignore").splitlines()
    func_defs = _collect_function_defs(tree.root_node, language)
    seeds: dict = {}

    recording_ctx = _Ctx(language, path, lines, func_defs, seeds, [], recording=True)
    _walk(tree.root_node, language, _ScopeState(), recording_ctx)

    findings: List[ASTFinding] = []
    final_ctx = _Ctx(language, path, lines, func_defs, seeds, findings, recording=False)
    _walk(tree.root_node, language, _ScopeState(), final_ctx)
    return findings
