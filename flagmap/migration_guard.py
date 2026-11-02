"""
migration_guard.py — best-effort suppression of loot.py's "Database dump
file present" / "SQLite database file present" findings when the .sql/
.sqlite/.sqlite3 file is actually a version-controlled schema-migration
script, not a leaked data dump.

Found via real-world testing against WebGoat (OWASP's official Java
training platform), which ships each lesson's own schema setup as
Flyway migrations, e.g.:

    src/main/resources/lessons/sqlinjection/db/migration/V2019_09_26_5__challenge_assignment.sql
    src/main/resources/db/container/V1__init.sql

loot.py's ".sql" extension-hint rule assumes any stray .sql file in a
tarball is a leaked table dump worth opening directly — a fair default
assumption, but wrong here: these are the challenge author's own,
intentionally-committed DDL/seed scripts, following Flyway's standard
`V<version>__<description>.sql` naming convention, sitting inside a
`db/migration`-style directory. 15 of these fired as false positives
against WebGoat alone, none of them containing anything resembling a
real data dump.

Two independent, deliberately conservative signals, BOTH required
(unlike vendor_guard.py's four, where any ONE signal is enough to
suppress) — a dump file genuinely abandoned in a webroot is extremely
unlikely to satisfy both at once, and requiring both is what keeps a
real leaked dump from being hidden by accident:

  1. The file's own name follows a recognized migration-tool versioned-
     naming convention: Flyway's `V<version>__<description>.sql` (the
     version is digits, optionally dot/underscore-separated, e.g.
     `V1__init.sql`, `V2019_09_26_5__challenge_assignment.sql`), or the
     bare numeric-prefix convention other raw-SQL migration tools use
     (`001_create_users.sql`).
  2. The file sits inside a directory path containing a database-
     scripting-convention segment: `db`, `migration(s)`, or `migrate`
     (case-insensitive). `db/migration/` and `db/migrate/` are the
     common Flyway/Rails spellings, but Flyway only defaults to
     `db/migration` — a project is free to point it at any classpath
     location, and in practice schema/seed scripts for a secondary
     purpose (e.g. an integration-test container's own init script) are
     still kept under the same `db/` tree without "migration" in the
     path at all. The plain `db` segment is the broader, still-
     conservative net that catches that case too: it's confirmed via
     real-world testing to NOT be a terminal/standalone directory
     anyone drops a stray, abandoned dump into — see the WebGoat
     example below.

Both conditions are about NAMING CONVENTION ONLY — this module never
opens or reads the file's content. A real dump someone renamed to look
like a migration and dropped into a migrations/-named folder would slip
past this undetected; that's a deliberate tradeoff in favor of never
hiding a true positive, the same "when in doubt, don't suppress"
discipline every other precision guard in this project already accepts
(vendor_guard.py's filename signals have the identical limitation;
xxe_guard.py and owner_param_guard.py accept the equivalent for their
own narrow, additive signals).

Only ever applies to loot.py's two extension-hint findings this module
exists for; never touches any other loot.py check (`.git` presence,
`.env`, flag-shaped strings, PEM keys, ...), and never touches
patterns.py/ast_engine.py's code-vulnerability findings at all.
"""

import re

# Flyway: V<version>__<description>.sql, version = digits with optional
# "." or "_" separators (Flyway accepts both as version-part separators).
_FLYWAY_NAME_RE = re.compile(r"""^[Vv][0-9]+(?:[._][0-9]+)*__.+\.sql$""")

# Plain numeric-prefix convention (Django raw-SQL migrations, some
# in-house tools): 001_create_users.sql, 2__add_index.sql.
_NUMERIC_PREFIX_NAME_RE = re.compile(r"""^[0-9]{1,6}_.+\.sql$""")

# Directory path contains a /db/, /migration(s)/, or /migrate/ segment,
# any depth, either slash style.
_MIGRATION_DIR_RE = re.compile(
    r"""(?:^|[\\/])(?:db|migrations?|migrate)(?:[\\/]|$)""",
    re.IGNORECASE,
)


def is_versioned_migration(dirpath: str, fname: str) -> bool:
    """True only when `fname` follows a recognized migration-tool naming
    convention AND `dirpath` contains a migration-convention directory
    segment. See this module's docstring for exactly why both signals
    are required together rather than either alone."""
    if not (_FLYWAY_NAME_RE.match(fname) or _NUMERIC_PREFIX_NAME_RE.match(fname)):
        return False
    return bool(_MIGRATION_DIR_RE.search(dirpath))
