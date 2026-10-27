"""
cli.py — command-line entry point for flagmap.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

from . import __version__
from .scanner import scan_path, Finding
from .chains import find_chains

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_COLOR = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"

RULE_WIDTH = 64


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def findings_to_dicts(findings):
    return [
        {
            "file": f.file,
            "line": f.line_no,
            "code": f.line_text,
            "vuln": f.vuln_name,
            "severity": f.severity,
            "confidence": f.confidence,
            "why": f.why,
            "payload": f.payload,
            "kind": getattr(f, "kind", "vuln"),
        }
        for f in findings
    ]


def chains_to_dicts(chains):
    return [
        {
            "name": ch.name,
            "severity": ch.severity,
            "steps": ch.steps,
            "why": ch.why,
            "based_on": [{"file": f.file, "line": f.line_no, "vuln": f.vuln_name} for f in ch.findings],
        }
        for ch in chains
    ]


def _rule(use_color: bool) -> str:
    return c("─" * RULE_WIDTH, DIM, use_color)


def _print_group(grouped, use_color: bool, show_payloads: bool, action_label: str):
    def group_rank(name):
        worst = min(SEVERITY_ORDER.get(f.severity, 3) for f in grouped[name])
        return (worst, name)

    for vuln_name in sorted(grouped, key=group_rank):
        items = sorted(grouped[vuln_name], key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
        header_color = SEVERITY_COLOR.get(items[0].severity, "")
        plural = "es" if len(items) != 1 else ""
        print(c(f"▶ {vuln_name}", BOLD + header_color if use_color else "", use_color)
              + c(f"  ({len(items)} match{plural})", DIM, use_color))
        for f in items:
            sev_tag = c(f"[{f.severity.upper()}/{f.confidence}]", SEVERITY_COLOR.get(f.severity, ""), use_color)
            loc = c(f"{f.file}:{f.line_no}", CYAN, use_color)
            print(f"  {sev_tag} {loc}")
            print(f"    {DIM if use_color else ''}{f.line_text}{RESET if use_color else ''}")
            print(f"    why:  {f.why}")
            if show_payloads:
                print(f"    {action_label}:  {c(f.payload, GREEN, use_color)}")
        print()


def _print_chains(chains, use_color: bool):
    print(c("── Attack Chains ──", BOLD, use_color))
    print(c("Correlated from the findings above — a strong hint of what to try first, not a guarantee.",
            DIM, use_color))
    print()
    for ch in sorted(chains, key=lambda x: SEVERITY_ORDER.get(x.severity, 3)):
        sev_tag = c(f"[{ch.severity.upper()}]", SEVERITY_COLOR.get(ch.severity, ""), use_color)
        print(f"⚡ {sev_tag} {c(ch.name, BOLD, use_color)}")
        print(f"    path: {ch.steps}")
        print(f"    why:  {ch.why}")
        based_on = ", ".join(f"{f.file}:{f.line_no} ({f.vuln_name})" for f in ch.findings)
        print(f"    based on: {c(based_on, DIM, use_color)}")
        print()


def _print_start_here(findings, chained_ids, use_color: bool, limit: int = 5):
    if not findings:
        return

    def rank_key(f):
        sev = SEVERITY_ORDER.get(f.severity, 3)
        conf = 0 if f.confidence == "likely" else 1
        chained = 0 if id(f) in chained_ids else 1
        return (chained, sev, conf)

    top = sorted(findings, key=rank_key)[:limit]
    print(c("── Start Here ──", BOLD, use_color))
    print(c("Highest-value findings first (severity + confidence + whether they're part of a detected chain).",
            DIM, use_color))
    print()
    for i, f in enumerate(top, start=1):
        sev_tag = c(f"[{f.severity.upper()}/{f.confidence}]", SEVERITY_COLOR.get(f.severity, ""), use_color)
        loc = c(f"{f.file}:{f.line_no}", CYAN, use_color)
        tag = c("  (part of an attack chain)", MAGENTA, use_color) if id(f) in chained_ids else ""
        print(f"  {i}. {sev_tag} {f.vuln_name} — {loc}{tag}")
    print()


def print_report(findings, use_color: bool, show_payloads: bool = True, show_chains: bool = True,
                  show_start_here: bool = True, scanned_path: str = ""):
    header_label = f" flagmap {__version__} "
    print()
    print(c(header_label.center(RULE_WIDTH, "─"), BOLD + CYAN if use_color else "", use_color))

    if not findings:
        if scanned_path:
            print(c(f" scanned: {scanned_path}", DIM, use_color))
        print(c(" No known vulnerable patterns or misconfigurations found.", BOLD, use_color))
        print(c(" (Doesn't mean it's safe — stay sharp.)", DIM, use_color))
        print(_rule(use_color))
        print()
        return

    code_findings = [f for f in findings if getattr(f, "kind", "vuln") == "vuln"]
    config_findings = [f for f in findings if getattr(f, "kind", "vuln") == "misconfig"]
    chains = find_chains(findings) if show_chains else []

    n_classes = len({f.vuln_name for f in findings})
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1
    sev_summary = " · ".join(
        c(f"{sev_counts[s]} {s}", SEVERITY_COLOR.get(s, ""), use_color)
        for s in ("high", "medium", "low") if sev_counts[s]
    )

    if scanned_path:
        print(c(f" scanned: {scanned_path}", DIM, use_color))
    chain_note = f" · {len(chains)} attack chain{'s' if len(chains) != 1 else ''} detected" if chains else ""
    print(f" {len(findings)} finding(s) across {n_classes} class(es)  [{sev_summary}]{chain_note}")
    print(_rule(use_color))
    print()

    if code_findings:
        print(c("── Code Vulnerabilities ──", BOLD, use_color))
        grouped = defaultdict(list)
        for f in code_findings:
            grouped[f.vuln_name].append(f)
        _print_group(grouped, use_color, show_payloads, action_label="try")

    if config_findings:
        print(c("── Misconfigurations ──", BOLD, use_color))
        grouped = defaultdict(list)
        for f in config_findings:
            grouped[f.vuln_name].append(f)
        _print_group(grouped, use_color, show_payloads, action_label="fix")

    chained_ids = set()
    for ch in chains:
        for f in ch.findings:
            chained_ids.add(id(f))

    if chains:
        _print_chains(chains, use_color)

    if show_start_here:
        _print_start_here(findings, chained_ids, use_color)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="flagmap",
        description="Scan CTF challenge source code for common web-exploitation vuln patterns, "
                    "with suggested payloads. Supports PHP, Python, JS/Node, C#, Java, Go, Ruby, Lua, Rust.",
    )
    parser.add_argument("path", help="File or directory to scan (e.g. the extracted challenge source folder)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON instead of a terminal report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--no-payloads", action="store_true", help="Hide suggested payloads in the report")
    parser.add_argument("--no-chains", action="store_true", help="Skip the attack-chain correlation section")
    parser.add_argument("--no-start-here", action="store_true", help="Skip the \"Start Here\" shortlist section")
    parser.add_argument(
        "--severity",
        choices=["high", "medium", "low"],
        help="Only show findings at or above this severity",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["likely", "possible"],
        default="possible",
        help="Minimum confidence to include (default: possible, i.e. show everything)",
    )
    parser.add_argument("--version", action="version", version=f"flagmap {__version__}")
    return parser


def filter_findings(findings, min_severity, min_confidence):
    sev_cutoff = SEVERITY_ORDER.get(min_severity, 2) if min_severity else 2
    conf_rank = {"likely": 0, "possible": 1}
    conf_cutoff = conf_rank.get(min_confidence, 1)
    out = []
    for f in findings:
        if SEVERITY_ORDER.get(f.severity, 3) > sev_cutoff:
            continue
        if conf_rank.get(f.confidence, 1) > conf_cutoff:
            continue
        out.append(f)
    return out


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 1

    findings = scan_path(args.path)
    findings = filter_findings(findings, args.severity, args.min_confidence)

    if args.json:
        chains = [] if args.no_chains else find_chains(findings)
        print(json.dumps({"findings": findings_to_dicts(findings), "chains": chains_to_dicts(chains)}, indent=2))
    else:
        use_color = supports_color() and not args.no_color
        print_report(
            findings,
            use_color,
            show_payloads=not args.no_payloads,
            show_chains=not args.no_chains,
            show_start_here=not args.no_start_here,
            scanned_path=args.path,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
