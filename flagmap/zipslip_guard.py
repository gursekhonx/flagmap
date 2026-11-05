r"""
zipslip_guard.py — best-effort "Zip Slip" (a malicious zip entry's own
`filename` escaping the intended extraction directory, via `../` path
traversal or a leading `/`, to write an attacker-chosen file to an
attacker-chosen path on disk) detector for Python.

Found in the real CyberSci nationals-2024-25 "history-stealer" web
challenge's `webapp/app.py` (`/file_upload` route, lines ~111-151). The
challenge accepts an uploaded `.zip`, then manually walks its entries and
writes each one to disk — the file's own comments literally say
"Extracting ZIP (vulnerable to Zip Slip)...". The code TRIES to handle
traversal (`if raw_name.startswith("/") or ".." in raw_name:`), but gets
the fix backwards: instead of rejecting the entry, it computes
`os.path.normpath(os.path.join("/", raw_name))` — which resolves a
traversal-laden name like `../../etc/cron.d/evil` to a normalized
*absolute* path and then happily writes to it:

    if raw_name.startswith("/") or ".." in raw_name:
        dest_path = os.path.normpath(os.path.join("/", raw_name))
    else:
        dest_path = os.path.join(unzip_path, raw_name)
    ...
    with zip_ref.open(member) as src, open(dest_path, "wb") as dst:
        shutil.copyfileobj(src, dst)

That matters for detection: a naive "does this file mention `..` anywhere
near a zip extraction" check would be fooled by this exact bug, since the
file DOES contain a `".." in raw_name` test — it's just answered wrong.
So this check does not treat the mere presence of a traversal-looking
substring test as proof of safety. It only recognizes a short list of
actual containment-verification idioms (`Path(...).resolve()` chained
with `.relative_to(`/`.is_relative_to(`, or `os.path.realpath(` chained
with `.startswith(`, or `os.path.commonpath(`) as evidence the code
really confirms the final path stays under the extraction root — nothing
less specific suppresses it.

Two-signal design, same discipline as every other best-effort guard in
this file:
  1. A variable is assigned from a zip member's own `.filename` (either
     `x = member.filename` from iterating `.infolist()`/`.filelist`, or
     the loop variable itself when iterating `.namelist()`, which yields
     plain name strings directly).
  2. That same variable is later passed into `os.path.join(...)` to build
     a filesystem destination path.
Both signals are required before this ever fires, and the whole-file
absence of a recognized containment idiom (see above) is required too.
Deliberately Python-only and regex/whole-file-text based rather than
AST-integrated: the real bug spans several non-adjacent lines (the
member-filename assignment, the traversal "check", and the eventual
`open(dest_path, "wb")`), which is exactly the kind of shape this file's
sibling guards (`jenkins_pipeline_guard.py`, `sql_construct.py`) already
handle the same way — collect signals from the whole file's text rather
than requiring everything on one line.

Known blind spots, stated plainly: this only recognizes `zipfile`'s own
`.infolist()`/`.namelist()`/`.filelist` entry points, not every third-
party zip-handling library; it does not attempt to verify that the write
sink is actually reached (no interprocedural/control-flow proof) — the
presence of `open(...)`/`shutil.copyfileobj(`/`.write(` ANYWHERE in the
file is treated as evidence the computed path gets written, which is
true in the one real case motivating this check but could in principle
miss a file that only ever reads the member or over-fire if an unrelated
write call happens to share the file; and a correctly-guarded extraction
that uses a containment idiom this module doesn't recognize would be
wrongly flagged. Accepted for the same reason every other guard module
in this project accepts its own known gaps: it's a net improvement on
zero coverage, confirmed true on the real motivating file and confirmed
to produce no stray hits anywhere else in the full 4-snapshot CyberSci
corpus (the only other `zipfile`/`ZipFile` usage anywhere in the corpus
is this same file's own `solve_files/create_zip.py`, which only ever
*creates* a zip, never extracts one, and so touches none of this
module's signals at all).
"""

import re
from typing import List

ZIP_LANGUAGES = {"python"}

_ZIPFILE_USE_RE = re.compile(r"\bimport\s+zipfile\b|\bfrom\s+zipfile\s+import\b|\bzipfile\.ZipFile\b")

# Signal 1a: `x = member.filename` (iterating .infolist()/.filelist, where
# each entry is a ZipInfo object with its own .filename attribute).
_MEMBER_FILENAME_VAR_RE = re.compile(r"\b(\w+)\s*=\s*\w+\.filename\b")
# Signal 1b: `for x in zf.namelist():` — namelist() yields plain strings,
# so the loop variable itself is the untrusted entry name.
_NAMELIST_LOOP_VAR_RE = re.compile(r"\bfor\s+(\w+)\s+in\s+[\w.]+\.namelist\s*\(\s*\)")

# Recognized containment-verification idioms. Presence of ANY of these
# anywhere in the file suppresses this check entirely for that file — see
# module docstring for why a bare "mentions .. somewhere" test is NOT on
# this list.
_SAFE_CONTAINMENT_RE = re.compile(
    r"\.resolve\(\s*\).*?\.(?:relative_to|is_relative_to)\s*\(|"
    r"os\.path\.realpath\s*\([^)]*\).*?\.startswith\s*\(|"
    r"os\.path\.commonpath\s*\(",
    re.DOTALL,
)

_WRITE_SINK_RE = re.compile(r"\bopen\s*\([^)]*,\s*[\"']\s*\w*b\s*[\"']|\bshutil\.copyfileobj\s*\(|\.write\s*\(")


class _ZipSlipFinding:
    __slots__ = ("file", "line_no", "line_text")

    def __init__(self, file, line_no, line_text):
        self.file = file
        self.line_no = line_no
        self.line_text = line_text


def find_zip_slip(path: str, language: str, lines: List[str]) -> List[_ZipSlipFinding]:
    """Best-effort Zip Slip detector — see module docstring. Returns one
    finding per untrusted-entry-name variable that's both assigned from a
    zip member's own name and later joined into a destination path via
    `os.path.join(...)`, provided the file never demonstrates a real
    containment check and does appear to write somewhere. `[]` for any
    non-Python file, any file that never touches `zipfile`, or any file
    that passes the containment check."""
    if language not in ZIP_LANGUAGES:
        return []
    full_text = "".join(lines)
    if not _ZIPFILE_USE_RE.search(full_text):
        return []
    if _SAFE_CONTAINMENT_RE.search(full_text):
        return []
    if not _WRITE_SINK_RE.search(full_text):
        return []

    tainted_names = set(_MEMBER_FILENAME_VAR_RE.findall(full_text))
    tainted_names.update(_NAMELIST_LOOP_VAR_RE.findall(full_text))
    if not tainted_names:
        return []

    findings = []
    seen_lines = set()
    for name in tainted_names:
        join_re = re.compile(r"os\.path\.join\s*\([^)]*\b" + re.escape(name) + r"\b[^)]*\)")
        m = join_re.search(full_text)
        if not m:
            continue
        line_no = full_text.count("\n", 0, m.start()) + 1
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        line_idx = line_no - 1
        line_text = lines[line_idx].strip()[:200] if line_idx < len(lines) else ""
        findings.append(_ZipSlipFinding(file=path, line_no=line_no, line_text=line_text))
    return findings
