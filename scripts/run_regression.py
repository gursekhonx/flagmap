#!/usr/bin/env python3
"""
run_regression.py — self-documenting regression harness for flagmap.

Fixture files under tests/fixtures/<lang>/ carry their own expectations as
trailing comment markers, same idea as semgrep's own test convention:

    cur.execute(f"...{name}...")   # ruleid: SQL Injection
    cur.execute("SELECT 1")        # safe
    echo h($name);                 # safe: XSS

- `# ruleid: <Vuln Name>` (comment char varies by language) asserts flagmap
  MUST report a finding with that exact vuln_name on this line.
- `# safe` asserts flagmap must report ZERO findings on this line at all.
- `# safe: <Vuln Name>` asserts flagmap must NOT report that specific
  vuln_name on this line (other, unrelated findings on the same line are
  still allowed — useful when one line is a false-positive guard for one
  category but legitimately trips something else).

Run it after any change to patterns.py / ast_engine.py / taint.py before
calling the change done — this is the thing that replaces re-running every
old CTF repo by hand every time.

Usage: python3 scripts/run_regression.py [-v]
Exit code 0 = all assertions passed, 1 = at least one failed.
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flagmap.scanner import scan_path  # noqa: E402

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures")

_MARKER_RE = re.compile(r"""(?:\#|//|--)\s*(ruleid|safe)\s*:?\s*(.*?)\s*$""")


def parse_expectations(path):
    """Returns (ruleid_expectations, safe_all_lines, safe_named) —
    ruleid_expectations: {line_no: [vuln_name, ...]}
    safe_all_lines: set of line_nos that must have ZERO findings
    safe_named: {line_no: set(vuln_name)} that must NOT appear (others OK)
    """
    ruleid = {}
    safe_all = set()
    safe_named = {}
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            m = _MARKER_RE.search(line.rstrip("\n"))
            if not m:
                continue
            kind, arg = m.group(1), m.group(2).strip()
            if kind == "ruleid":
                if not arg:
                    raise ValueError(f"{path}:{line_no}: 'ruleid' marker with no vuln name")
                ruleid.setdefault(line_no, []).append(arg)
            elif kind == "safe":
                if arg:
                    safe_named.setdefault(line_no, set()).add(arg)
                else:
                    safe_all.add(line_no)
    return ruleid, safe_all, safe_named


def run_fixture(path, verbose=False):
    """Returns (n_passed, n_failed, failure_lines)."""
    ruleid, safe_all, safe_named = parse_expectations(path)
    findings = scan_path(path)

    by_line = {}
    for f in findings:
        by_line.setdefault(f.line_no, []).append(f.vuln_name)

    passed, failed = 0, 0
    failure_lines = []

    for line_no, expected_names in ruleid.items():
        actual_names = by_line.get(line_no, [])
        for name in expected_names:
            if name in actual_names:
                passed += 1
            else:
                failed += 1
                failure_lines.append(
                    f"  line {line_no}: expected '{name}', got {actual_names or '(nothing)'}"
                )

    for line_no in safe_all:
        actual_names = by_line.get(line_no, [])
        if not actual_names:
            passed += 1
        else:
            failed += 1
            failure_lines.append(
                f"  line {line_no}: expected NO findings, got {actual_names}"
            )

    for line_no, bad_names in safe_named.items():
        actual_names = set(by_line.get(line_no, []))
        overlap = actual_names & bad_names
        if not overlap:
            passed += 1
        else:
            failed += 1
            failure_lines.append(
                f"  line {line_no}: expected NOT {sorted(bad_names)}, but got {sorted(overlap)}"
            )

    return passed, failed, failure_lines


def main():
    verbose = "-v" in sys.argv
    total_passed, total_failed = 0, 0
    any_failures = False

    for lang in sorted(os.listdir(FIXTURES_DIR)):
        lang_dir = os.path.join(FIXTURES_DIR, lang)
        if not os.path.isdir(lang_dir):
            continue
        for fname in sorted(os.listdir(lang_dir)):
            fpath = os.path.join(lang_dir, fname)
            if not os.path.isfile(fpath):
                continue
            passed, failed, failure_lines = run_fixture(fpath)
            total_passed += passed
            total_failed += failed
            status = "PASS" if failed == 0 else "FAIL"
            if failed or verbose:
                print(f"[{status}] {lang}/{fname}  ({passed} ok, {failed} failed)")
            if failure_lines:
                any_failures = True
                for fl in failure_lines:
                    print(fl)

    print(f"\n{total_passed} assertion(s) passed, {total_failed} failed.")
    return 1 if any_failures else 0


if __name__ == "__main__":
    sys.exit(main())
