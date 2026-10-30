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
from flagmap.loot import find_loot  # noqa: E402
from flagmap.deps import find_vulnerable_deps  # noqa: E402
from flagmap.diffscan import find_changed_files  # noqa: E402

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures")

# tests/fixtures/loot/<case>/ each hold an EXPECTED.txt (one vuln_name per
# line) and an app/ subfolder that's the actual tree to scan — a whole-
# directory-presence check like find_loot() has no single "line" to put a
# ruleid/safe marker comment on, so it gets its own assertion convention:
# the SET of vuln_names found in app/ must equal EXACTLY the SET listed in
# EXPECTED.txt, no more and no fewer. Exact-equality (not "at least these")
# is deliberate: it catches a stray new false positive (like loot.py's own
# docstring once tripping its own flag-shaped-string regex during
# development) just as readily as a missed true positive.
LOOT_FIXTURES_DIR = os.path.join(FIXTURES_DIR, "loot")

# Same convention, for deps.py: tests/fixtures/deps/<case>/EXPECTED.txt lists
# "package@version (CVE)" strings (DepFinding's own fields, not the fuller
# "Known-Vulnerable Dependency: ..." text scanner.py wraps them in) that
# find_vulnerable_deps() must return for that case's app/ dir — exact set
# equality again, for the same reason: a new false positive (e.g. a package
# name collision, or a version comparison that's off by one bound) fails
# the suite exactly as loudly as a missed true positive.
DEPS_FIXTURES_DIR = os.path.join(FIXTURES_DIR, "deps")

# tests/fixtures/diffscan/<case>/ each hold an old/ and a new/ directory
# (two snapshots of "the same challenge") plus an EXPECTED.txt listing the
# relative paths (relative to new/) find_changed_files() must report as
# changed — exact set equality again, same reasoning as loot/deps above.
DIFFSCAN_FIXTURES_DIR = os.path.join(FIXTURES_DIR, "diffscan")

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


def run_loot_fixture(case_dir):
    """Returns (n_passed, n_failed, failure_lines) for one tests/fixtures/
    loot/<case>/ directory — see LOOT_FIXTURES_DIR's comment above for the
    exact-set-equality convention this checks."""
    expected_path = os.path.join(case_dir, "EXPECTED.txt")
    app_dir = os.path.join(case_dir, "app")
    with open(expected_path, encoding="utf-8") as f:
        expected = {line.strip() for line in f if line.strip()}

    findings = find_loot(app_dir)
    actual = {f.vuln_name for f in findings}

    if actual == expected:
        return 1, 0, []
    missing = expected - actual
    extra = actual - expected
    lines = []
    if missing:
        lines.append(f"  missing: {sorted(missing)}")
    if extra:
        lines.append(f"  unexpected: {sorted(extra)}")
    return 0, 1, lines


def run_deps_fixture(case_dir):
    """Returns (n_passed, n_failed, failure_lines) for one tests/fixtures/
    deps/<case>/ directory — see DEPS_FIXTURES_DIR's comment above."""
    expected_path = os.path.join(case_dir, "EXPECTED.txt")
    app_dir = os.path.join(case_dir, "app")
    with open(expected_path, encoding="utf-8") as f:
        expected = {line.strip() for line in f if line.strip()}

    findings = find_vulnerable_deps(app_dir)
    actual = {f"{d.package}@{d.version} ({d.cve})" for d in findings}

    if actual == expected:
        return 1, 0, []
    missing = expected - actual
    extra = actual - expected
    lines = []
    if missing:
        lines.append(f"  missing: {sorted(missing)}")
    if extra:
        lines.append(f"  unexpected: {sorted(extra)}")
    return 0, 1, lines


def run_diffscan_fixture(case_dir):
    """Returns (n_passed, n_failed, failure_lines) for one tests/fixtures/
    diffscan/<case>/ directory — see DIFFSCAN_FIXTURES_DIR's comment above."""
    expected_path = os.path.join(case_dir, "EXPECTED.txt")
    old_dir = os.path.join(case_dir, "old")
    new_dir = os.path.join(case_dir, "new")
    with open(expected_path, encoding="utf-8") as f:
        expected = {line.strip() for line in f if line.strip()}

    changed, _n_new, _n_old = find_changed_files(old_dir, new_dir)

    if changed == expected:
        return 1, 0, []
    missing = expected - changed
    extra = changed - expected
    lines = []
    if missing:
        lines.append(f"  missing: {sorted(missing)}")
    if extra:
        lines.append(f"  unexpected: {sorted(extra)}")
    return 0, 1, lines


def main():
    verbose = "-v" in sys.argv
    total_passed, total_failed = 0, 0
    any_failures = False

    for lang in sorted(os.listdir(FIXTURES_DIR)):
        lang_dir = os.path.join(FIXTURES_DIR, lang)
        if not os.path.isdir(lang_dir) or lang_dir in (LOOT_FIXTURES_DIR, DEPS_FIXTURES_DIR, DIFFSCAN_FIXTURES_DIR):
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

    if os.path.isdir(LOOT_FIXTURES_DIR):
        for case in sorted(os.listdir(LOOT_FIXTURES_DIR)):
            case_dir = os.path.join(LOOT_FIXTURES_DIR, case)
            if not os.path.isfile(os.path.join(case_dir, "EXPECTED.txt")):
                continue
            passed, failed, failure_lines = run_loot_fixture(case_dir)
            total_passed += passed
            total_failed += failed
            status = "PASS" if failed == 0 else "FAIL"
            if failed or verbose:
                print(f"[{status}] loot/{case}  ({passed} ok, {failed} failed)")
            if failure_lines:
                any_failures = True
                for fl in failure_lines:
                    print(fl)

    if os.path.isdir(DEPS_FIXTURES_DIR):
        for case in sorted(os.listdir(DEPS_FIXTURES_DIR)):
            case_dir = os.path.join(DEPS_FIXTURES_DIR, case)
            if not os.path.isfile(os.path.join(case_dir, "EXPECTED.txt")):
                continue
            passed, failed, failure_lines = run_deps_fixture(case_dir)
            total_passed += passed
            total_failed += failed
            status = "PASS" if failed == 0 else "FAIL"
            if failed or verbose:
                print(f"[{status}] deps/{case}  ({passed} ok, {failed} failed)")
            if failure_lines:
                any_failures = True
                for fl in failure_lines:
                    print(fl)

    if os.path.isdir(DIFFSCAN_FIXTURES_DIR):
        for case in sorted(os.listdir(DIFFSCAN_FIXTURES_DIR)):
            case_dir = os.path.join(DIFFSCAN_FIXTURES_DIR, case)
            if not os.path.isfile(os.path.join(case_dir, "EXPECTED.txt")):
                continue
            passed, failed, failure_lines = run_diffscan_fixture(case_dir)
            total_passed += passed
            total_failed += failed
            status = "PASS" if failed == 0 else "FAIL"
            if failed or verbose:
                print(f"[{status}] diffscan/{case}  ({passed} ok, {failed} failed)")
            if failure_lines:
                any_failures = True
                for fl in failure_lines:
                    print(fl)

    print(f"\n{total_passed} assertion(s) passed, {total_failed} failed.")
    return 1 if any_failures else 0


if __name__ == "__main__":
    sys.exit(main())
