"""
config_scanner.py — walks a path looking for config/infra files (Dockerfile,
docker-compose.yml, nginx/apache conf, .env, vsftpd.conf, redis.conf,
my.cnf, php.ini, sshd_config, Kubernetes manifests) and flags common
misconfigurations.

This is a separate, best-effort pass from the main source-code scanner:
config files aren't "code" in the language-pattern sense, but misconfigured
infra is one of the most common ways a CTF (and real-world) target gets
popped, so it gets its own category of findings (kind="misconfig").
"""

import os
import re
from dataclasses import dataclass
from typing import List, Optional

from .config_patterns import compiled_line_checks
from .patterns import SKIP_DIRS

MAX_FILE_BYTES = 1_000_000
# See scanner.MAX_LINE_LEN — same catastrophic-backtracking protection for
# the config-file line checks (a vendored/minified asset misclassified as a
# generic .conf/.yml is unlikely but cheap to guard against regardless).
MAX_LINE_LEN = 5000


@dataclass
class ConfigFinding:
    file: str
    line_no: int
    line_text: str
    name: str
    severity: str
    why: str
    fix: str
    confidence: str


def _basename_lower(path: str) -> str:
    return os.path.basename(path).lower()


def classify_config_file(path: str, content: str) -> List[str]:
    """Return the list of check categories applicable to this file, based on
    filename first, then light content sniffing for generically-named files
    (.conf, .yml/.yaml)."""
    name = _basename_lower(path)
    _, ext = os.path.splitext(name)

    categories = []

    if name == "dockerfile" or name.startswith("dockerfile."):
        categories.append("dockerfile")

    elif "docker-compose" in name and ext in (".yml", ".yaml"):
        categories.append("compose")

    elif name == "vsftpd.conf":
        categories.append("ftp")

    elif name == "redis.conf":
        categories.append("redis")

    elif name in ("my.cnf", "mysql.cnf", "mariadb.cnf"):
        categories.append("mysql")

    elif name == "php.ini":
        categories.append("php_ini")

    elif name == "sshd_config":
        categories.append("sshd")

    elif name == ".htaccess":
        categories.append("apache")

    elif name == ".env" or name.endswith(".env"):
        categories.append("env")

    elif ext == ".conf":
        # generic .conf — sniff content to decide nginx vs apache-style
        if re.search(r"\bserver\s*\{|\blocation\s+", content):
            categories.append("nginx")
        elif re.search(r"VirtualHost|DocumentRoot|<Directory", content, re.IGNORECASE):
            categories.append("apache")

    elif ext in (".yml", ".yaml"):
        if re.search(r"^apiVersion:\s*\S+", content, re.MULTILINE) and "docker-compose" not in name:
            categories.append("k8s")

    elif ext == ".tf":
        categories.append("terraform")

    elif ext == ".sh":
        categories.append("shell_script")

    elif ext == ".map":
        categories.append("source_map")

    return categories


def _whole_file_checks(path: str, category: str, content: str, lines: List[str]) -> List[ConfigFinding]:
    """Checks that depend on the ABSENCE of something, or a combination of
    two lines, rather than a single matching line — can't be expressed as a
    simple per-line regex."""
    findings: List[ConfigFinding] = []

    if category == "dockerfile":
        if not re.search(r"^\s*USER\s+(?!root\b)\S+", content, re.MULTILINE):
            # find the line of the last FROM/ENTRYPOINT/CMD to anchor the finding somewhere useful
            anchor_line = 1
            for i, line in enumerate(lines, start=1):
                if re.match(r"^\s*FROM\s+", line):
                    anchor_line = i
            findings.append(ConfigFinding(
                file=path, line_no=anchor_line, line_text="(no USER directive found in this Dockerfile)",
                name="Container Runs as Root",
                severity="medium",
                why="No USER directive switches away from root — if the app is compromised, the attacker's "
                    "shell is root inside the container, maximizing blast radius for any container-escape bug.",
                fix="Add a non-root USER before the final CMD/ENTRYPOINT, e.g. `USER appuser`.",
                confidence="possible",
            ))

    elif category == "ftp":
        has_anon = re.search(r"^\s*anonymous_enable\s*=\s*YES", content, re.MULTILINE | re.IGNORECASE)
        has_write = re.search(r"^\s*write_enable\s*=\s*YES", content, re.MULTILINE | re.IGNORECASE)
        if has_anon and has_write:
            line_no = 1
            for i, line in enumerate(lines, start=1):
                if re.match(r"^\s*write_enable\s*=\s*YES", line, re.IGNORECASE):
                    line_no = i
            findings.append(ConfigFinding(
                file=path, line_no=line_no, line_text=lines[line_no - 1].strip() if lines else "",
                name="Anonymous FTP With Write Access",
                severity="high",
                why="Both anonymous_enable and write_enable are YES — anyone can log in with no credentials "
                    "AND upload/overwrite files on this server.",
                fix="Disable write_enable for anonymous sessions, or disable anonymous_enable entirely.",
                confidence="likely",
            ))

    elif category == "redis":
        has_bind_local = re.search(r"^\s*bind\s+127\.0\.0\.1", content, re.MULTILINE)
        has_requirepass = re.search(r"^\s*requirepass\s+\S+", content, re.MULTILINE)
        if not has_requirepass:
            findings.append(ConfigFinding(
                file=path, line_no=1, line_text="(no requirepass directive found)",
                name="Redis Has No Authentication",
                severity="high" if not has_bind_local else "medium",
                why="No requirepass is set — anyone who can reach this Redis instance over the network can "
                    "read/write all data with no authentication at all.",
                fix="Set `requirepass <strong-random-value>` (and reference it via config/secret, not hardcoded in git).",
                confidence="possible",
            ))

    elif category == "terraform":
        # Find `output "name" { ... }` blocks and flag ones whose name suggests
        # a credential but whose body has no `sensitive = true` anywhere in it.
        # Unmarked sensitive outputs are written in cleartext to terraform.tfstate
        # and printed on every `apply`/`output` — a common real-world leak vector.
        sensitive_name_re = re.compile(r"(?:password|secret|token|key|credential)", re.IGNORECASE)
        for m in re.finditer(r'output\s+"([^"]+)"\s*\{([^}]*)\}', content, re.DOTALL):
            out_name, body = m.group(1), m.group(2)
            if not sensitive_name_re.search(out_name):
                continue
            if re.search(r"sensitive\s*=\s*true", body, re.IGNORECASE):
                continue
            # locate the line the `output "name"` declaration starts on
            line_no = content.count("\n", 0, m.start()) + 1
            findings.append(ConfigFinding(
                file=path, line_no=line_no, line_text=f'output "{out_name}" {{ ... }}',
                name="Terraform Output Missing sensitive=true",
                severity="medium",
                why="This output's name suggests it holds a credential, but it isn't marked `sensitive = "
                    "true` — its value is written in cleartext into terraform.tfstate and printed to the "
                    "console/CI logs on every apply/output.",
                fix="Add `sensitive = true` inside the output block, and make sure the state file itself "
                    "is stored encrypted with restricted access.",
                confidence="possible",
            ))

    elif category == "source_map":
        # Sniff for the actual sourcemap JSON shape rather than trusting the
        # extension alone, to avoid false-positiving on an unrelated .map file.
        if re.search(r'"mappings"\s*:', content) and re.search(r'"sources"\s*:', content):
            findings.append(ConfigFinding(
                file=path, line_no=1, line_text="(sourcemap file present)",
                name="Source Map File Present in Build Output",
                severity="high",
                why="A JavaScript sourcemap is shipped alongside the production build — anyone can unmap the "
                    "minified JS back into readable source (e.g. with sourcemapper), which commonly exposes "
                    "internal logic, comments, or hardcoded/obfuscated secrets never meant to be client-visible.",
                fix="Exclude .map files from the production build/deploy step, or restrict access to them.",
                confidence="likely",
            ))

    return findings


def iter_config_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d != ".")]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield full


def scan_config_file(path: str, line_checks: dict) -> List[ConfigFinding]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return []

    categories = classify_config_file(path, content)
    if not categories:
        return []

    lines = content.splitlines()
    findings: List[ConfigFinding] = []

    for category in categories:
        rules = line_checks.get(category, [])
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if len(line) > MAX_LINE_LEN:
                continue
            for rule in rules:
                if rule["regex"].search(line):
                    findings.append(ConfigFinding(
                        file=path,
                        line_no=line_no,
                        line_text=stripped[:200],
                        name=rule["name"],
                        severity=rule["severity"],
                        why=rule["why"],
                        fix=rule["fix"],
                        confidence=rule["confidence"],
                    ))
        findings.extend(_whole_file_checks(path, category, content, lines))

    return findings


def scan_config_path(root: str):
    """Returns a list of scanner.Finding-compatible objects (kind='misconfig')."""
    from .scanner import Finding  # local import to avoid a circular import at module load time

    line_checks = compiled_line_checks()
    results = []
    for path in iter_config_files(root):
        for cf in scan_config_file(path, line_checks):
            results.append(Finding(
                file=cf.file,
                line_no=cf.line_no,
                line_text=cf.line_text,
                vuln_name=cf.name,
                severity=cf.severity,
                why=cf.why,
                payload=cf.fix,
                confidence=cf.confidence,
                kind="misconfig",
            ))
    return results
