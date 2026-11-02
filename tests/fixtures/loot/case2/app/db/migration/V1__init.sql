-- migration_guard.py's motivating shape: a Flyway-style versioned
-- migration script, sitting inside a db/migration/ directory, following
-- the V<version>__<description>.sql naming convention. This is the
-- challenge author's own, intentionally-committed schema setup — not a
-- leaked data dump — so loot.py's "Database dump file present" check
-- must NOT fire on this file (see EXPECTED.txt: only dump.sql's finding
-- is listed for this case).
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);
