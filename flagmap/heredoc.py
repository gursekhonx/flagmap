"""
heredoc.py — pulls embedded source files back out of Dockerfile heredocs.

A surprisingly common pattern for small, single-file CTF challenges is to
skip a separate source file + COPY entirely and just write the whole app
inline in the Dockerfile:

    RUN cat <<EOF > app.js
    const express = require('express');
    ...
    EOF

That heredoc body is real, scannable application source — but it never
exists as its own file on disk, so flagmap's extension-based file walk
(scanner.iter_source_files) can never find it, no matter how good the
patterns themselves are. This module finds those blocks inside Dockerfiles
and hands their body back to the normal pattern-matching/taint pipeline
(scanner.scan_lines), attributed to a synthetic path so findings still show
a useful file:line.

This is deliberately narrow: it only recognizes the common
`RUN cat <<'EOF' > target` / `RUN cat <<EOF > target` shape (optionally with
`-` for `<<-EOF` indentation stripping), not every possible heredoc/shell
quoting variant. Widen DOCKERFILE_HEREDOC_RE if a new shape shows up in
testing.
"""

import os
import re
from typing import List, Tuple

from .patterns import EXTENSION_LANGUAGE, SKIP_DIRS

DOCKERFILE_HEREDOC_RE = re.compile(
    r"""^[ \t]*RUN\s+cat\s*<<-?\s*['"]?(?P<marker>\w+)['"]?\s*>\s*(?P<target>\S+)\s*$""",
    re.MULTILINE,
)


def _detect_language(filename: str):
    _, ext = os.path.splitext(filename)
    return EXTENSION_LANGUAGE.get(ext.lower())


def extract_heredoc_sources(dockerfile_path: str) -> List[Tuple[str, str, List[str]]]:
    """Return a list of (synthetic_path, language, lines) for every
    `RUN cat <<EOF > target ... EOF` block found in this Dockerfile whose
    target filename maps to a known language."""
    try:
        with open(dockerfile_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []

    all_lines = content.splitlines()
    results = []

    for m in DOCKERFILE_HEREDOC_RE.finditer(content):
        marker = m.group("marker")
        target = m.group("target")
        language = _detect_language(target)
        if not language:
            continue  # heredoc writes something we don't have patterns for (a .conf, a key, etc.)

        start_line = content.count("\n", 0, m.end()) + 1  # first line of the heredoc body
        end_marker_re = re.compile(r"^[ \t]*" + re.escape(marker) + r"[ \t]*$")
        body_lines = []
        for line in all_lines[start_line:]:
            if end_marker_re.match(line):
                break
            body_lines.append(line + "\n")

        if body_lines:
            synthetic_path = f"{dockerfile_path} (heredoc -> {target}, from line {start_line})"
            results.append((synthetic_path, language, body_lines))

    return results


def iter_heredoc_sources(root: str):
    """Walk root for Dockerfiles and yield every heredoc-embedded source
    block found inside them, same shape as scanner.iter_source_files."""
    dockerfiles = []
    if os.path.isfile(root):
        if os.path.basename(root).lower().startswith("dockerfile"):
            dockerfiles.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in filenames:
                if fname.lower().startswith("dockerfile"):
                    dockerfiles.append(os.path.join(dirpath, fname))

    for dockerfile_path in dockerfiles:
        for synthetic_path, language, lines in extract_heredoc_sources(dockerfile_path):
            yield synthetic_path, language, lines
