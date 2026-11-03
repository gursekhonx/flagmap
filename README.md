# flagmap

A CLI tool that scans CTF challenge source code (PHP, Python, Node/JS, C#/
ASP.NET Core, Java, Go, Ruby, Lua, Rust) and flags common web-exploitation
vulnerability patterns, misconfigurations, exposed secrets/loot (`.git`,
flag-shaped strings, stray keys), and known-CVE pinned dependencies
(Log4Shell, old PHPMailer, etc.) — with a short explanation and a
suggested starting payload or action for each one. It also correlates
findings into likely **attack chains** (e.g. an upload bug plus an Apache
misconfig = RCE) and ranks a **"Start Here"** shortlist so you know what
to try first.

Built for jeopardy-style CTFs (like CyberSci regionals) where web challenges
sometimes hand you the source code. Instead of eyeballing every file, point
flagmap at the folder and get a triaged list of what's worth trying first.

Current version: **v1.22.0** (see [CHANGELOG.md](CHANGELOG.md)).

This README covers install, usage, and a quick orientation. For more detail:

| Doc | What's in it |
|---|---|
| [CAPABILITIES.md](CAPABILITIES.md) | Every vuln class, misconfig, loot check, and CVE flagmap looks for — and what it deliberately does *not* try to catch. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the detection engine works (AST taint-tracking vs. regex), the false positives/negatives found testing against real CTF repos, and how to extend it. |
| [CHANGELOG.md](CHANGELOG.md) | Every shipped change, in order, with the real bug/repo that motivated it. |

## Install

As of v1.3.0, flagmap depends on `tree-sitter` plus a grammar package for
each of its 8 supported languages for the structural matching engine (see
[ARCHITECTURE.md](ARCHITECTURE.md)). It still *works* without them — any
language whose grammar isn't installed falls back to the regex engine (see
ARCHITECTURE.md for what that costs) — but install them to get the accuracy
improvement:

```bash
cd flagmap
pip install -e .
```

`pip install -e .` pulls in `tree-sitter` and all 8 grammar packages
(`tree-sitter-python`/`-javascript`/`-php`/`-go`/`-java`/`-ruby`/`-lua`/
`-rust`) automatically via `install_requires` in `setup.py`. This gives you
a `flagmap` command. Or just run it without installing:

```bash
python3 -m flagmap <path>
```

## Usage

```bash
# scan a folder (the extracted challenge source)
flagmap ./challenge_source

# scan a single file
flagmap ./challenge_source/app.py

# only show high-severity, high-confidence findings
flagmap ./challenge_source --severity high --min-confidence likely

# machine-readable output (includes both "findings" and "chains")
flagmap ./challenge_source --json

# no color (for piping/logging)
flagmap ./challenge_source --no-color

# skip the attack-chain correlation and/or the Start Here shortlist
flagmap ./challenge_source --no-chains --no-start-here

# also write a shareable Markdown writeup (e.g. to paste/drop for your team)
flagmap ./challenge_source --export-md report.md

# only show findings in files that changed since an earlier snapshot
# (e.g. the organizers just pushed a patched "v2" of the challenge)
flagmap ./challenge_source_v2 --diff-against ./challenge_source_v1

# print the installed version
flagmap --version
```

Output is split into up to six sections (plus `--export-md`, which renders
the same findings/chains as a standalone Markdown file alongside whatever
else you asked for — see "Sharing results with a team" below — and
`--diff-against`, which narrows all of them to files changed since a
previous snapshot — see "Re-scanning a patched challenge" below):

1. **Loot / Recon** — exposed `.git`, `.env`/keys, backup files, hardcoded
   flag-shaped strings. Needs zero exploitation, so it's printed first and
   ranked first in "Start Here" regardless of severity. See CAPABILITIES.md.
2. **Vulnerable Dependencies** — a manifest/lockfile pins an exact version
   with a well-known CVE (Log4Shell, old PHPMailer, ...), each with a
   suggested upgrade under `fix:`. Ranked second in "Start Here", after
   loot. See CAPABILITIES.md.
3. **Code Vulnerabilities** — exploitable bugs in the app's source, each
   with a suggested payload under `try:`.
4. **Misconfigurations** — infra/config issues like a Dockerfile running as
   root or a wildcard CORS origin, each with a suggested remediation under
   `fix:`. This scan runs automatically alongside the code scan — no
   separate flag needed.
5. **Attack Chains** — findings correlated into a likely exploit path (e.g.
   an upload bug + a dangerous Apache `AddType` = direct RCE, or a root
   container + any RCE primitive = no privilege-escalation step needed).
   This is a plain co-occurrence check over the findings already produced —
   not new scanning or dataflow analysis — so treat a chain like any other
   `possible`-confidence finding: a strong hint of where to look first, not
   a guarantee the path is real. See `chains.py`.
6. **Start Here** — a ranked shortlist of the 3-5 highest-value findings:
   loot first, then known-CVE dependencies, then everything else by
   attack-chain membership, severity, and confidence. Built for the moment
   you open a report and just want to know what to click on first.

### Sharing results with a team (`--export-md`, added v1.10.0)

`--export-md FILE` renders the exact same findings and chains as a
standalone `.md` file (`report_md.py`) — same sections, same grouping,
same "Start Here" ranking, just Markdown instead of ANSI-colored terminal
text — in addition to whatever the normal run already prints (works
alongside `--json` too; they're independent outputs from the same scan).
Built because CyberSci and most jeopardy CTFs are played in teams, usually
over Discord/Slack, under a clock: the person who ran flagmap is rarely
the only one who needs the results, and reading them off a terminal means
re-describing them by hand in chat. This makes "paste it in Discord" or
"drop it in the team's shared doc" a straight file hand-off instead.

### Re-scanning a patched challenge (`--diff-against`, added v1.12.0)

`--diff-against OLD_PATH` restricts the report to findings in files that
are new or changed (by byte content, not mtime) relative to a previous
snapshot of the same challenge — built for the specific moment an
organizer announces a patch mid-competition ("v2 is up, the old bug is
fixed") and the real question is "what did they touch, and is there
anything NEW in exactly those files" (a patch is itself a common place
for a *second* bug to slip in). Re-reading a full report by eye to spot
that defeats the point of having a scanner.

Deliberately diffs two plain directory snapshots (`diffscan.py`), not two
git refs: a CTF handout is essentially never its own git repository — if
one WERE shipped, that's itself a loot/recon finding (see
CAPABILITIES.md) — so there's nothing to assume the player has been
committing to. "Point it at the folder you already downloaded" needs no setup.
Works alongside every other flag, including `--json` (the summary lands
in a top-level `"diff"` key) and `--export-md`.

## What it catches

Four broad categories — full detail, exact detection logic, and known
false-positive guards for each are in [CAPABILITIES.md](CAPABILITIES.md):

- **Loot / Recon** — exposed `.git`, `.env`, SSH keys, backup files,
  hardcoded flag-shaped strings. Needs zero exploitation, so it's always
  ranked first.
- **Vulnerable Dependencies** — exact-version manifest/lockfile pins
  matching a curated table of well-known CVEs (Log4Shell, old PHPMailer,
  Struts2, SnakeYAML, PyYAML, lodash/minimist, Pillow/urllib3, ReportLab,
  Rails, Django).
- **Code Vulnerabilities** — across PHP, Python, Node/JS, C#/ASP.NET Core,
  Java, Go, Ruby/Rails, Lua, and Rust: SQL/NoSQL/LDAP/GraphQL Injection,
  Command Injection/RCE, Unsafe Deserialization, Path Traversal/LFI/Zip
  Slip, SSTI, SSRF, Unrestricted File Upload, XSS (reflected/stored/
  DOM-based), XXE, Open Redirect, Mass Assignment, Prototype Pollution,
  JWT/Auth Token weaknesses, Weak Crypto, Insecure Randomness, CORS
  misconfig, Host Header Injection, Debug Mode, Weak Auth Logic, Missing
  CSRF Protection, Missing Authorization/IDOR, Missing Authentication
  Check, Format String Injection, Integer Overflow/Truncation, and several
  language-specific checks (C# JWT/EF Core/deserialization, Go map-based
  mass assignment, Ruby `.constantize`, JSP direct-output XSS, source code
  embedded in a Dockerfile heredoc).
- **Misconfigurations** — Dockerfiles, docker-compose, nginx/Apache,
  `.env`, vsftpd/redis/MySQL/SSH configs, Kubernetes manifests, Terraform,
  provisioning scripts, and leaked JS sourcemaps.

Every finding is tagged `likely` or `possible` confidence, has a one-line
`why`, and a suggested starting `try:`/`fix:`. Findings are also correlated
into **attack chains** and ranked into a **"Start Here"** shortlist (see
"Usage" below).

## What it can't catch (on purpose)

A handful of real, recurring bug shapes are deliberately **not** turned
into a check, because doing so would either be a no-op or a
false-positive generator — things like precise IDOR (vs. the best-effort
heuristic actually shipped), client-controlled price/amount tampering, and
TOCTOU/race-condition balance checks. See
[CAPABILITIES.md](CAPABILITIES.md#what-it-cant-catch-on-purpose) for the
full list and the reasoning behind each one. Treat flagmap as a fast
triage pass, not ground truth — always verify the actual code path.

## Example output

```
──────────────────────── flagmap 1.0.0 ─────────────────────────
 scanned: ./challenge_source
 3 finding(s) across 2 class(es)  [2 high · 1 medium] · 1 attack chain detected
────────────────────────────────────────────────────────────────

── Code Vulnerabilities ──
▶ SQL Injection  (1 match)
  [HIGH/possible] app.php:9
    $result = $conn->query($sql);
    why:  Variable assigned from user input earlier in the file is used
          inside a query call here. (tainted var: `sql`)
    try:  ' OR 1=1 -- 

── Attack Chains ──
⚡ [HIGH] SQLi -> Dump Weak-Hashed Credentials -> Crack Offline
    path: Use the SQLi to dump the users table -> crack the weak hashes -> log in as that user
    why:  The SQL injection gives you the password-hash column; the weak-hashing
          finding means those hashes are cheap to crack offline.
    based on: app.php:9 (SQL Injection), register.php:40 (Weak Cryptography)

── Start Here ──
  1. [HIGH/possible] SQL Injection — app.php:9  (part of an attack chain)
  2. [MEDIUM/possible] Weak Cryptography — register.php:40  (part of an attack chain)
```

## Project layout

```
flagmap/
  flagmap/
    __init__.py
    __main__.py          # python -m flagmap entry point
    cli.py                # argparse CLI, report formatting
    scanner.py            # file walking + dispatch to the AST engine (all 8 langs) or regex-only fallback (if a grammar's missing)
    ast_engine.py          # tree-sitter structural matching + scoped taint tracking (all 8 supported languages)
    patterns.py            # the code vuln pattern database (regex; all languages, runs alongside the AST engine too)
    taint.py              # severity/why/payload maps (shared by both engines) + legacy regex taint-lite, now fallback-only (py/js/php)
    heredoc.py             # pulls source embedded in Dockerfile heredocs back out for scanning
    csrf.py                 # best-effort missing-CSRF form check
    idor.py                # best-effort missing-authorization/IDOR check (see "Best-effort heuristics")
    loot.py                # recon: exposed .git/.env/keys/flag-shaped strings (see "Loot / Recon")
    deps.py                # curated known-CVE pinned-dependency table + manifest/lockfile parsers (see "Vulnerable Dependencies")
    xxe_guard.py            # whole-file XXE false-positive suppression (see "Best-effort heuristics")
    report_md.py            # standalone Markdown report renderer (--export-md, see "Sharing results with a team")
    diffscan.py              # two-snapshot file-diffing (--diff-against, see "Re-scanning a patched challenge")
    vendor_guard.py          # suppresses the noisiest rules on vendored/third-party library files (see "Architecture", added v1.14.0)
    authn_guard.py           # best-effort missing-authentication-check check (see "Best-effort heuristics", added v1.15.0)
    pickle_guard.py          # rewrites Unsafe Deserialization advice when a validator guards the pickle call (see "Best-effort heuristics", added v1.15.0)
    sql_construct.py         # PHP SQL-construction-site matching for "." concatenation / inline interpolation (see "Architecture", added v1.15.0)
    owner_param_guard.py     # upgrades an IDOR finding when the ownership filter itself is request-sourced (see "Best-effort heuristics", added v1.16.0)
    migration_guard.py       # suppresses loot.py's dump-file finding for recognized versioned-migration scripts (see "Best-effort heuristics", added v1.18.0)
    jquery_dom_guard.py      # suppresses idor.py's fallback IDOR finding when it's really a jQuery DOM-method collision (see "Best-effort heuristics", added v1.19.0)
    js_clientside_guard.py   # shared "is this JS file unambiguously client-side" predicate, used by jquery_dom_guard.py and ssrf_fetch_guard.py (added v1.20.0)
    ssrf_fetch_guard.py      # suppresses the taint-blind SSRF regex on a plain client-side fetch() call (see "Best-effort heuristics", added v1.20.0)
    log_message_guard.py     # suppresses the JS sensitive-log regex when the keyword match is inside message text, not a real reference (see "Best-effort heuristics", added v1.21.0)
    chains.py              # attack-path correlation over a scan's findings
    config_patterns.py    # the misconfiguration pattern database
    config_scanner.py      # file walking + checks (Dockerfile/nginx/.env/etc.)
  setup.py
  sample_challenge/       # sample vulnerable files for testing
```

## How it decides what to flag

Two layers, per language: **direct regex patterns** matched line-by-line,
and an **AST-based taint-tracking engine** (via `tree-sitter`) that follows
a variable from a request-input source to a dangerous sink across
statements and one function call. This is *not* full dataflow analysis —
no control-flow, no general sanitizer detection — it's built to catch the
specific patterns that show up constantly in intentionally-vulnerable CTF
code. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, every
false positive it was tuned against, and exactly which heuristics
(`is_test_file()`, `vendor_guard.py`, etc.) suppress known-noisy shapes.

## Testing

```bash
python3 scripts/run_regression.py -v
```

runs the full fixture-based regression suite (`tests/fixtures/<language>/`,
with `ruleid`/`safe` trailing-comment markers) — run it after any change to
the detection engine, before calling the change done. See
[ARCHITECTURE.md](ARCHITECTURE.md#testing) for the fixture conventions and
the specific cases that have no standard fixture category (and why).

## Extending it

See [ARCHITECTURE.md](ARCHITECTURE.md#extending-it) for exactly where to
add a new sink, regex rule, misconfig check, attack chain, or a new
best-effort heuristic.
