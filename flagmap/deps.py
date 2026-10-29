"""
deps.py — known-vulnerable pinned dependency scanner.

This is a fourth, deliberately narrow category of finding, next to code
vulnerabilities (patterns.py/ast_engine.py/taint.py), misconfigurations
(config_scanner.py), and loot/recon (loot.py). It answers one question:
"does this manifest/lockfile pin an exact version of something with a
well-known, high-confidence CVE?" — the kind of thing a CTF "vulnerable
dependency" challenge is built around (ship an old Log4j/SnakeYAML/
PHPMailer/etc. on purpose, player's job is to recognize it and use the
known exploit).

What this deliberately is NOT:
  - Not a general SCA (software composition analysis) tool. Real SCA
    tools cross-reference every dependency in every manifest against a
    live, constantly-updated CVE/OSV database covering tens of thousands
    of packages. That needs network access to a (often paid, or at best
    rate-limited free-tier) vulnerability API — which the no-paid-
    software / best-effort-offline constraint on this whole project rules
    out, and which would also make scan results silently depend on
    whatever happens to be reachable at scan time rather than being
    reproducible.
  - Instead, this ships a small, curated, offline, hand-picked table
    (CVE_TABLE below) of maybe a dozen CVEs that come up again and again
    specifically in CTF/training contexts: Log4Shell, SnakeYAML/PyYAML
    unsafe-load RCE, old PHPMailer, Struts2 CVE-2017-5638 (the Equifax
    bug), a couple of Rails/Django SQLi-or-RCE-class bugs, and a couple
    of well-known npm prototype-pollution bugs (minimist, lodash). This
    table will go stale — it reflects what's well-known as of this
    writing, nothing more. Treat it as "here are some obvious ones",
    never as "this dependency tree is clean."
  - Never flags a *range* as vulnerable, only an *exact, resolved*
    version. requirements.txt's `flask>=1.0` tells you nothing about what
    actually got installed, so it's skipped outright — only an exact pin
    (`flask==1.1.2`) or a lockfile's resolved version (which is always
    exact, that's the point of a lockfile) is matched against the table.
    Guessing "well, >=1.0 COULD resolve to a vulnerable version" would
    produce a flood of noise with no way to tell a real hit from a false
    one, which is worse than saying nothing.
  - A version string that can't be parsed as a dotted-numeric version at
    all (or a pom.xml <version> that's actually a `${property}`
    placeholder with no literal value in this file) is skipped, not
    guessed at either direction.

Supported manifests/lockfiles (parsed with regex/line-scanning, same
general style as the rest of flagmap, rather than full JSON/XML parsing —
partly for consistency, partly because a regex-based line scan degrades
gracefully and still gives a line number, where json.loads either parses
the whole file or gives you nothing):
  - requirements.txt          (Python, exact `==` pins only)
  - Pipfile.lock               (Python, exact resolved versions)
  - package-lock.json          (Node, npm v1 "dependencies" tree and
                                 v2/v3 "packages" object, best-effort)
  - yarn.lock                  (Node, exact resolved versions)
  - Gemfile.lock                (Ruby, top-level "specs:" entries)
  - composer.lock               (PHP, exact resolved versions)
  - pom.xml                     (Java/Maven, literal <version> only)

Not supported (see README roadmap): go.mod/go.sum (no Go CVEs in the
table yet, so there's nothing for a parser to match against — not worth
the added surface area until that changes).
"""

import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .patterns import SKIP_DIRS

# Lockfiles legitimately run bigger than regular source/config files
# (a package-lock.json for a real project is routinely several MB), so
# this gets its own, larger cap than scanner.py's/config_scanner.py's.
MAX_FILE_BYTES = 5_000_000


@dataclass
class DepFinding:
    file: str
    line_no: int
    line_text: str
    package: str
    version: str
    ecosystem: str
    cve: str
    severity: str
    why: str
    fix: str


# ---------------------------------------------------------------------------
# Curated CVE table.
#
# Keyed by ecosystem -> normalized package name -> list of entries. Each
# entry is checked as: vulnerable if min_version <= version < fixed_in
# (min_version=None means "no lower bound", i.e. any version below
# fixed_in"). Multiple entries per package let one package have several
# independently-fixed CVEs across different branches/eras — all entries
# that match are reported, since that's an accurate (if cluttered) picture
# of "all the known-bad things about the exact version you shipped."
#
# NOTE: severities here are capped at "high" — flagmap's existing severity
# scheme everywhere else (SEVERITY_ORDER/SEVERITY_COLOR in cli.py) only
# has three tiers (high/medium/low). Introducing a fourth "critical" tier
# here would silently break sort order elsewhere (SEVERITY_ORDER.get with
# a default of 3 would sort an unrecognized "critical" as *less* urgent
# than "low", not more) rather than doing anything useful, so even
# Log4Shell-class bugs are filed as "high", the ceiling of the existing
# scale, not a new tier of their own.
# ---------------------------------------------------------------------------

CVE_TABLE = {
    "python": {
        "pyyaml": [
            {"min_version": None, "fixed_in": "5.1", "cve": "CVE-2017-18342", "severity": "high",
             "why": "yaml.load() with the default Loader lets crafted YAML construct arbitrary Python "
                    "objects on load (e.g. `!!python/object/apply:os.system`) — effectively "
                    "deserialization RCE.",
             "fix": "Upgrade to pyyaml>=5.1, and use yaml.safe_load() / an explicit SafeLoader regardless "
                    "of version."},
        ],
        "pillow": [
            {"min_version": None, "fixed_in": "9.0.0", "cve": "CVE-2022-22817", "severity": "high",
             "why": "PIL.ImageMath.eval() evaluates attacker-controlled expressions with eval() under the "
                    "hood — arbitrary code execution if untrusted input reaches it.",
             "fix": "Upgrade to Pillow>=9.0.0."},
        ],
        "urllib3": [
            {"min_version": None, "fixed_in": "1.26.5", "cve": "CVE-2021-33503", "severity": "medium",
             "why": "A catastrophic-backtracking regex in authority/URL parsing allows a ReDoS from an "
                    "attacker-controlled URL string.",
             "fix": "Upgrade to urllib3>=1.26.5."},
        ],
        "django": [
            {"min_version": "2.2", "fixed_in": "2.2.28", "cve": "CVE-2022-28346", "severity": "high",
             "why": "QuerySet.annotate()/aggregate()/extra() can be used for SQL injection via a "
                    "maliciously crafted dict used as a column alias, if that dict is attacker-influenced.",
             "fix": "Upgrade to Django>=2.2.28 on the 2.2 branch."},
            {"min_version": "3.2", "fixed_in": "3.2.13", "cve": "CVE-2022-28346", "severity": "high",
             "why": "Same QuerySet SQL-injection issue as above, 3.2 branch.",
             "fix": "Upgrade to Django>=3.2.13 on the 3.2 branch."},
            {"min_version": "4.0", "fixed_in": "4.0.4", "cve": "CVE-2022-28346", "severity": "high",
             "why": "Same QuerySet SQL-injection issue as above, 4.0 branch.",
             "fix": "Upgrade to Django>=4.0.4 on the 4.0 branch."},
        ],
    },
    "node": {
        "lodash": [
            {"min_version": None, "fixed_in": "4.17.21", "cve": "CVE-2021-23337", "severity": "high",
             "why": "lodash's template() allows command injection via the 'variable' option / a crafted "
                    "template string, and this release also folds in fixes for earlier prototype-pollution "
                    "bugs (merge/mergeWith/defaultsDeep).",
             "fix": "Upgrade to lodash>=4.17.21."},
        ],
        "minimist": [
            {"min_version": None, "fixed_in": "1.2.3", "cve": "CVE-2020-7598", "severity": "medium",
             "why": "Prototype pollution via crafted argument keys such as `--__proto__.x=y`.",
             "fix": "Upgrade to minimist>=1.2.3 (then >=1.2.6 — see the other minimist finding if present)."},
            {"min_version": "1.2.3", "fixed_in": "1.2.6", "cve": "CVE-2021-44906", "severity": "high",
             "why": "A second, more severe prototype-pollution bug in the same argument-parsing code path — "
                    "exploitable for property injection, and RCE depending on how the parsed object is used "
                    "downstream.",
             "fix": "Upgrade to minimist>=1.2.6."},
        ],
    },
    "ruby": {
        "rails": [
            {"min_version": "5.2.0", "fixed_in": "5.2.4.3", "cve": "CVE-2020-8165", "severity": "high",
             "why": "MemCacheStore/RedisCacheStore deserialize cached values with Marshal.load by default — "
                    "if an attacker can write to the cache store (often easier than it sounds), this is "
                    "deserialization RCE.",
             "fix": "Upgrade to rails>=5.2.4.3 on the 5.2 branch, and set `serializer: :json` on the cache "
                    "store regardless of version."},
            {"min_version": "6.0.0", "fixed_in": "6.0.3.1", "cve": "CVE-2020-8165", "severity": "high",
             "why": "Same Marshal-based cache deserialization RCE as above, 6.0 branch.",
             "fix": "Upgrade to rails>=6.0.3.1 on the 6.0 branch."},
        ],
    },
    "php": {
        "phpmailer/phpmailer": [
            {"min_version": None, "fixed_in": "5.2.18", "cve": "CVE-2016-10033", "severity": "high",
             "why": "Sendmail/mail() transport RCE via a crafted sender address — the classic CTF "
                    "\"old PHPMailer\" RCE.",
             "fix": "Upgrade to phpmailer/phpmailer>=5.2.18 (then keep going — see the other findings if "
                    "present)."},
            {"min_version": "5.2.18", "fixed_in": "5.2.22", "cve": "CVE-2017-5223", "severity": "high",
             "why": "XML External Entity (XXE) injection via a crafted DKIM-related or embedded-image path.",
             "fix": "Upgrade to phpmailer/phpmailer>=5.2.22."},
            {"min_version": "5.2.22", "fixed_in": "6.0.6", "cve": "CVE-2018-19296", "severity": "high",
             "why": "A second Sendmail-transport RCE, same family as CVE-2016-10033 but through an "
                    "injection point the first patch missed.",
             "fix": "Upgrade to phpmailer/phpmailer>=6.0.6."},
        ],
    },
    "java": {
        "org.apache.logging.log4j:log4j-core": [
            {"min_version": None, "fixed_in": "2.17.1", "cve": "CVE-2021-44228 (\"Log4Shell\") + follow-ons",
             "severity": "high",
             "why": "JNDI message-lookup RCE (Log4Shell), plus the follow-on CVE-2021-45046 (incomplete "
                    "fix via thread-context map lookups), CVE-2021-45105 (DoS) and CVE-2021-44832 (RCE via "
                    "JDBCAppender) — fixed incrementally across 2.15.0 through 2.17.1. Anything below "
                    "2.17.1 is worth assuming is exploitable via the original Log4Shell payload first.",
             "fix": "Upgrade to log4j-core>=2.17.1."},
        ],
        "org.yaml:snakeyaml": [
            {"min_version": None, "fixed_in": "1.26", "cve": "CVE-2017-18640", "severity": "high",
             "why": "The default Constructor lets crafted YAML instantiate arbitrary Java types on load — "
                    "deserialization-style RCE/DoS, same family as PyYAML's unsafe load.",
             "fix": "Upgrade to snakeyaml>=1.26 (then >=1.31 — see the other finding if present), and prefer "
                    "SafeConstructor regardless of version."},
            {"min_version": "1.26", "fixed_in": "1.31", "cve": "CVE-2022-1471", "severity": "high",
             "why": "A second, more directly RCE-capable unsafe-deserialization bug via the Constructor "
                    "class.",
             "fix": "Upgrade to snakeyaml>=1.31."},
        ],
        "org.apache.struts:struts2-core": [
            {"min_version": "2.3.0", "fixed_in": "2.3.32", "cve": "CVE-2017-5638", "severity": "high",
             "why": "The Jakarta Multipart parser evaluates the Content-Type header as an OGNL expression — "
                    "unauthenticated RCE (the Equifax-breach bug).",
             "fix": "Upgrade to struts2-core>=2.3.32 on the 2.3 branch."},
            {"min_version": "2.5.0", "fixed_in": "2.5.10.1", "cve": "CVE-2017-5638", "severity": "high",
             "why": "Same Content-Type OGNL RCE as above, 2.5 branch.",
             "fix": "Upgrade to struts2-core>=2.5.10.1 on the 2.5 branch."},
        ],
    },
}


def _normalize_name(ecosystem: str, name: str) -> str:
    name = name.strip()
    if ecosystem == "python":
        return name.lower().replace("_", "-")
    if ecosystem in ("node", "ruby", "php"):
        return name.lower()
    return name  # java keys are "group:artifact", case-sensitive by convention


_VERSION_PREFIX_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def _parse_version(v: str) -> Optional[Tuple[int, ...]]:
    """Best-effort: take the leading dotted-numeric run and ignore anything
    after it (pre-release tags, build metadata, etc.). Returns None if the
    string doesn't even start with a digit — e.g. a pom.xml `${property}`
    placeholder, or a git-ref-style npm version — so the caller can skip
    it rather than guess."""
    v = v.strip()
    if v[:1].lower() == "v":
        v = v[1:]
    m = _VERSION_PREFIX_RE.match(v)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp_padded(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    ap = a + (0,) * (length - len(a))
    bp = b + (0,) * (length - len(b))
    if ap < bp:
        return -1
    if ap > bp:
        return 1
    return 0


def _matches_entry(version: str, entry: dict) -> bool:
    vt = _parse_version(version)
    ft = _parse_version(entry["fixed_in"])
    if vt is None or ft is None:
        return False
    if _cmp_padded(vt, ft) >= 0:
        return False  # version >= fixed_in: not vulnerable to this entry
    if entry["min_version"] is not None:
        mt = _parse_version(entry["min_version"])
        if mt is not None and _cmp_padded(vt, mt) < 0:
            return False  # version predates this entry's branch, doesn't apply
    return True


def _lookup(ecosystem: str, raw_name: str, version: str) -> List[dict]:
    table = CVE_TABLE.get(ecosystem, {})
    key = _normalize_name(ecosystem, raw_name)
    entries = table.get(key, [])
    return [e for e in entries if _matches_entry(version, e)]


# ---------------------------------------------------------------------------
# Manifest/lockfile parsers. Each yields (package_name, version, line_no).
# Deliberately regex/line-scan based rather than json.loads/XML-parse: a
# partial or slightly malformed file still yields whatever lines DO match
# instead of raising, and every hit keeps a real line number for free.
# ---------------------------------------------------------------------------

def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


_REQUIREMENTS_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-\[\]]*?)\s*==\s*([0-9][0-9A-Za-z.\-+]*)\s*(?:[;#].*)?$"
)


def parse_requirements_txt(content: str):
    for line_no, line in enumerate(content.splitlines(), start=1):
        m = _REQUIREMENTS_RE.match(line)
        if not m:
            continue
        name = m.group(1).split("[")[0]  # strip extras like requests[security]
        yield name, m.group(2), line_no, line.strip()


_PIPFILE_LOCK_KEY_RE = re.compile(r'^\s*"([A-Za-z0-9][A-Za-z0-9_.\-]*)"\s*:\s*\{\s*$')
_PIPFILE_LOCK_VERSION_RE = re.compile(r'^\s*"version"\s*:\s*"==?\s*([0-9][^"]*)"')
_PIPFILE_LOCK_STRUCTURAL_KEYS = {"_meta", "default", "develop", "sources", "requires"}


def parse_pipfile_lock(content: str):
    current_pkg = None
    for line_no, line in enumerate(content.splitlines(), start=1):
        km = _PIPFILE_LOCK_KEY_RE.match(line)
        if km:
            name = km.group(1)
            current_pkg = None if name in _PIPFILE_LOCK_STRUCTURAL_KEYS else name
            continue
        vm = _PIPFILE_LOCK_VERSION_RE.match(line)
        if vm and current_pkg:
            yield current_pkg, vm.group(1), line_no, line.strip()
            current_pkg = None  # one version line consumes the pending package


# npm package-lock.json v2/v3: "packages": { "node_modules/foo": {"version": "1.2.3"}, ... }
_NPM_PACKAGES_KEY_RE = re.compile(
    r'^\s*"((?:node_modules/)+(?:@[\w.\-]+/)?[\w.\-]+)"\s*:\s*\{\s*$'
)
# npm package-lock.json v1 (and the generic fallback): any `"name": {` followed
# shortly by a `"version": "..."` line, excluding known structural keys.
_NPM_GENERIC_KEY_RE = re.compile(r'^\s*"(@?[\w.\-][\w.\-/]*)"\s*:\s*\{\s*$')
_NPM_VERSION_RE = re.compile(r'^\s*"version"\s*:\s*"([0-9][^"]*)"')
_NPM_STRUCTURAL_KEYS = {
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
    "requires", "packages", "engines", "scripts", "bin", "exports", "imports", "",
}


def parse_package_lock_json(content: str):
    lines = content.splitlines()
    for line_no, line in enumerate(lines, start=1):
        pm = _NPM_PACKAGES_KEY_RE.match(line)
        if pm:
            full_key = pm.group(1)
            name = full_key.rsplit("node_modules/", 1)[-1]
            # version is expected within the next few lines of this same block
            for look in lines[line_no:line_no + 8]:
                vm = _NPM_VERSION_RE.match(look)
                if vm:
                    yield name, vm.group(1), line_no, line.strip()
                    break
            continue

    # v1-style fallback: generic key-then-version pairing, windowed so an
    # unrelated nested object in between doesn't get misattributed.
    current_pkg = None
    current_pkg_line = 0
    for line_no, line in enumerate(lines, start=1):
        km = _NPM_GENERIC_KEY_RE.match(line)
        if km:
            name = km.group(1)
            if name in _NPM_STRUCTURAL_KEYS or name.startswith("node_modules/"):
                continue
            current_pkg = name
            current_pkg_line = line_no
            continue
        vm = _NPM_VERSION_RE.match(line)
        if vm and current_pkg and line_no - current_pkg_line <= 5:
            yield current_pkg, vm.group(1), current_pkg_line, line.strip()
            current_pkg = None


_YARN_VERSION_RE = re.compile(r'^\s*version\s+"([0-9][^"]*)"')


def parse_yarn_lock(content: str):
    lines = content.splitlines()
    header_name = None
    header_line = 0
    for line_no, line in enumerate(lines, start=1):
        if line.rstrip().endswith(":") and not line.startswith((" ", "\t", "#")) and line.strip() != ":":
            # new block header, e.g.: `lodash@^4.17.0, lodash@^4.17.21:`
            first_spec = line.split(",", 1)[0].strip().rstrip(":").strip('"')
            m = re.match(r'^(@?[^@]+)@', first_spec)
            header_name = m.group(1) if m else None
            header_line = line_no
            continue
        vm = _YARN_VERSION_RE.match(line)
        if vm and header_name:
            yield header_name, vm.group(1), header_line, line.strip()
            header_name = None  # one version per block


_GEMFILE_LOCK_SPECS_START_RE = re.compile(r"^\s*specs:\s*$")
_GEMFILE_LOCK_ENTRY_RE = re.compile(r"^    ([a-zA-Z0-9_\-]+) \(([0-9][\w.\-]*)\)\s*$")


def parse_gemfile_lock(content: str):
    in_specs = False
    for line_no, line in enumerate(content.splitlines(), start=1):
        if _GEMFILE_LOCK_SPECS_START_RE.match(line):
            in_specs = True
            continue
        if in_specs and line and not line[0].isspace():
            in_specs = False  # left the GEM block entirely (next top-level section)
            continue
        if not in_specs:
            continue
        m = _GEMFILE_LOCK_ENTRY_RE.match(line)
        if m:
            yield m.group(1), m.group(2), line_no, line.strip()


_COMPOSER_NAME_RE = re.compile(r'^\s*"name"\s*:\s*"([^"]+/[^"]+)"')
_COMPOSER_VERSION_RE = re.compile(r'^\s*"version"\s*:\s*"v?([0-9][^"]*)"')


def parse_composer_lock(content: str):
    lines = content.splitlines()
    pending_name = None
    pending_line = 0
    for line_no, line in enumerate(lines, start=1):
        nm = _COMPOSER_NAME_RE.match(line)
        if nm:
            pending_name = nm.group(1)
            pending_line = line_no
            continue
        vm = _COMPOSER_VERSION_RE.match(line)
        if vm and pending_name and line_no - pending_line <= 10:
            yield pending_name, vm.group(1), pending_line, line.strip()
            pending_name = None


_POM_DEPENDENCY_RE = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL)
_POM_GROUP_RE = re.compile(r"<groupId>\s*([^<]+?)\s*</groupId>")
_POM_ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<]+?)\s*</artifactId>")
_POM_VERSION_RE = re.compile(r"<version>\s*([^<]+?)\s*</version>")


def parse_pom_xml(content: str):
    for m in _POM_DEPENDENCY_RE.finditer(content):
        block = m.group(1)
        gm, am, vm = _POM_GROUP_RE.search(block), _POM_ARTIFACT_RE.search(block), _POM_VERSION_RE.search(block)
        if not (gm and am and vm):
            continue
        version = vm.group(1).strip()
        if "${" in version:
            continue  # unresolved Maven property placeholder — can't determine the real version, don't guess
        line_no = content.count("\n", 0, m.start()) + 1
        name = f"{gm.group(1).strip()}:{am.group(1).strip()}"
        yield name, version, line_no, f"<dependency>{gm.group(1).strip()}:{am.group(1).strip()}:{version}</dependency>"


_MANIFEST_PARSERS = {
    "requirements.txt": ("python", parse_requirements_txt),
    "Pipfile.lock": ("python", parse_pipfile_lock),
    "package-lock.json": ("node", parse_package_lock_json),
    "yarn.lock": ("node", parse_yarn_lock),
    "Gemfile.lock": ("ruby", parse_gemfile_lock),
    "composer.lock": ("php", parse_composer_lock),
    "pom.xml": ("java", parse_pom_xml),
}


def _iter_manifest_files(root: str):
    if os.path.isfile(root):
        if os.path.basename(root) in _MANIFEST_PARSERS:
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            if fname in _MANIFEST_PARSERS:
                yield os.path.join(dirpath, fname)


def find_vulnerable_deps(root: str) -> List[DepFinding]:
    findings: List[DepFinding] = []
    for path in _iter_manifest_files(root):
        ecosystem, parser = _MANIFEST_PARSERS[os.path.basename(path)]
        content = _read(path)
        if content is None:
            continue
        for name, version, line_no, line_text in parser(content):
            for entry in _lookup(ecosystem, name, version):
                findings.append(DepFinding(
                    file=path,
                    line_no=line_no,
                    line_text=line_text[:200],
                    package=name,
                    version=version,
                    ecosystem=ecosystem,
                    cve=entry["cve"],
                    severity=entry["severity"],
                    why=entry["why"],
                    fix=entry["fix"],
                ))
    return findings
