-- Same migration_guard.py motivating shape, but under a db/container/
-- directory rather than db/migration/ — covers the real WebGoat case
-- where Flyway-style scripts for a secondary purpose (an integration-
-- test container's own init script) are kept under the broader db/
-- tree without "migration" literally in the path. Must also be
-- suppressed: the plain "db" directory segment is the broader signal
-- migration_guard.py's _MIGRATION_DIR_RE matches, not just
-- "migration"/"migrations"/"migrate".
INSERT INTO accounts (id, username, password_hash) VALUES (2, 'seed_user', 'abc123abc123abc123abc123abc123ab');
