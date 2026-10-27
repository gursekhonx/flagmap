"""
scanner.py — walks a path, applies patterns, returns findings.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

from .patterns import compiled_patterns, EXTENSION_LANGUAGE, SKIP_DIRS, NOISY_IN_TEST_FILES
from .taint import find_tainted_sinks, find_format_string_sinks
from .csrf import find_missing_csrf
from .config_scanner import scan_config_path
from .heredoc import iter_heredoc_sources
from .ast_engine import scan_ast, AST_SUPPORTED_LANGUAGES

# No hand-written vulnerable application code is ever a single line this long —
# only minified/bundled vendor files (tailwindcss.js, jquery.min.js, etc.) are,
# and those commonly contain lines well over 100,000 characters. Running dozens
# of regexes with nested quantifiers (.*, [^)]*, etc.) against such a line is
# catastrophic-backtracking territory and can hang the scan indefinitely with
# no error and no partial output. Skip lines past this length outright — they
# were never going to be real, reviewable source anyway.
MAX_LINE_LEN = 5000


@dataclass
class Finding:
    file: str
    line_no: int
    line_text: str
    vuln_name: str
    severity: str
    why: str
    payload: str
    confidence: str
    kind: str = "vuln"  # "vuln" (code vulnerability) or "misconfig" (config file issue)


def detect_language(filename: str) -> Optional[str]:
    _, ext = os.path.splitext(filename)
    return EXTENSION_LANGUAGE.get(ext.lower())


def is_test_file(path: str) -> bool:
    """Best-effort check for test fixture files, where hardcoded-looking
    'passwords' (testpassword123, etc.) are expected and not real findings."""
    norm = path.replace("\\", "/").lower()
    parts = norm.split("/")
    if any(p in ("test", "tests", "__tests__", "spec", "specs") for p in parts):
        return True
    base = os.path.basename(norm)
    name, _ = os.path.splitext(base)
    return (
        name.startswith("test_") or name.endswith("_test")
        or name.startswith("test.") or name.endswith(".test")
        or name.endswith("_spec") or name.endswith(".spec")
    )


def iter_source_files(root: str, max_file_bytes: int = 2_000_000):
    """Yield (path, language) for every source file under root worth scanning."""
    if os.path.isfile(root):
        lang = detect_language(root)
        if lang:
            yield root, lang
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # prune noisy/irrelevant directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            lang = detect_language(fname)
            if not lang:
                continue
            full = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(full) > max_file_bytes:
                    continue
            except OSError:
                continue
            yield full, lang


def scan_file(path: str, language: str, patterns: list) -> List[Finding]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []
    return scan_lines(path, language, lines, patterns)


def scan_lines(path: str, language: str, lines: List[str], patterns: list) -> List[Finding]:
    """Core line-matching logic, shared by scan_file (reads from disk) and
    anything that hands it source text it extracted some other way — e.g.
    heredoc.py pulling a `RUN cat <<EOF > app.js ... EOF` block's body out of
    a Dockerfile, which never exists as its own file on disk at all."""
    findings: List[Finding] = []

    # Blank out any line over MAX_LINE_LEN in place (keeping the list length/line
    # numbers intact) so every regex-driven pass below — this pattern loop, the
    # taint-lite pass, and the CSRF check — is protected, not just this one.
    lines = [line if len(line) <= MAX_LINE_LEN else "" for line in lines]

    applicable = [p for p in patterns if p["language"] in (language, "generic")]

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*")):
            # still check '#' lines for python since comments start with it too,
            # but a line that is PURELY a comment is unlikely to hold live code.
            # We keep scanning non-comment-only lines only, to cut noise.
            continue
        for pat in applicable:
            if pat["payload"] in NOISY_IN_TEST_FILES and is_test_file(path):
                continue
            if pat["regex"].search(line):
                findings.append(Finding(
                    file=path,
                    line_no=line_no,
                    line_text=stripped[:200],
                    vuln_name=pat["name"],
                    severity=pat["severity"],
                    why=pat["why"],
                    payload=pat["payload"],
                    confidence=pat["confidence"],
                ))

    seen = {(f.line_no, f.vuln_name) for f in findings}

    if language in AST_SUPPORTED_LANGUAGES:
        # Structural taint-flow pass: parses the actual syntax tree instead
        # of matching text, so it doesn't share the regex engine's recurring
        # failure modes (quote-conflict misses, backtracking, multi-line
        # misses, scope/receiver confusion) — see ast_engine.py's docstring.
        source_bytes = "".join(lines).encode("utf-8", errors="ignore")
        for af in scan_ast(path, language, source_bytes):
            key = (af.line_no, af.vuln_name)
            if key in seen:
                continue  # already flagged this exact line+vuln by a direct pattern
            seen.add(key)
            findings.append(Finding(
                file=af.file,
                line_no=af.line_no,
                line_text=af.line_text,
                vuln_name=af.vuln_name,
                severity=af.severity,
                why=af.why,  # ast_engine already folds the tainted-var note in
                payload=af.payload,
                confidence=af.confidence,
            ))
    else:
        # Legacy regex taint-lite pass, for languages not yet ported to the
        # AST engine (Go, Java, Ruby, Lua, Rust — see README).
        for tf in find_tainted_sinks(path, language, lines):
            key = (tf.line_no, tf.vuln_name)
            if key in seen:
                continue  # already flagged this exact line+vuln by a direct pattern
            seen.add(key)
            findings.append(Finding(
                file=tf.file,
                line_no=tf.line_no,
                line_text=tf.line_text,
                vuln_name=tf.vuln_name,
                severity=tf.severity,
                why=f"{tf.why} (tainted var: `{tf.tainted_var}`)",
                payload=tf.payload,
                confidence=tf.confidence,
            ))

        # Format String Injection pass: template-itself-is-tainted shape,
        # distinct from (and independent of) the argument-based taint-lite
        # pass above. (Python's AST-engine equivalent of this lives inside
        # scan_ast via SINKS["python"]["format"] with var_set="built".)
        for tf in find_format_string_sinks(path, language, lines):
            key = (tf.line_no, tf.vuln_name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=tf.file,
                line_no=tf.line_no,
                line_text=tf.line_text,
                vuln_name=tf.vuln_name,
                severity=tf.severity,
                why=f"{tf.why} (tainted var: `{tf.tainted_var}`)",
                payload=tf.payload,
                confidence=tf.confidence,
            ))

    # best-effort CSRF check: PHP/HTML files with a <form method="post">
    # and no sign of a csrf token anywhere in the file
    for cf in find_missing_csrf(path, language, lines):
        findings.append(Finding(
            file=cf.file,
            line_no=cf.line_no,
            line_text=cf.line_text,
            vuln_name="Missing CSRF Protection",
            severity="medium",
            why="A POST form was found with no mention of a CSRF token anywhere in this file — if there's "
                "no CSRF middleware/decorator elsewhere, this form can be submitted cross-site without the "
                "user's knowledge.",
            payload="Host an auto-submitting form on another origin targeting this endpoint while the victim is logged in.",
            confidence="possible",
        ))

    return findings


def scan_path(root: str) -> List[Finding]:
    patterns = compiled_patterns()
    all_findings: List[Finding] = []
    for path, lang in iter_source_files(root):
        all_findings.extend(scan_file(path, lang, patterns))

    # Dockerfile heredocs (`RUN cat <<EOF > app.js ... EOF`) embed real source
    # that never exists as its own file on disk — the extension-based walk
    # above can never find it, however good the patterns are. Pull it back
    # out and run it through the exact same line-matching pipeline.
    for synthetic_path, lang, lines in iter_heredoc_sources(root):
        all_findings.extend(scan_lines(synthetic_path, lang, lines, patterns))

    # separate pass: config/infra misconfigurations (Dockerfile, nginx.conf,
    # .env, vsftpd.conf, etc.) — these aren't "source code" so they're not
    # covered by the language-extension walk above.
    all_findings.extend(scan_config_path(root))

    return all_findings
