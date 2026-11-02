-- Right FILENAME convention, wrong directory (no "db"/"migration"/
-- "migrate" segment anywhere in the path) — migration_guard.py requires
-- BOTH signals together, so this must still fire "Database dump file
-- present" even though the name alone looks like a Flyway migration.
-- Guards against a regression that drops the directory check and
-- suppresses on filename alone.
INSERT INTO accounts (id, username, password_hash) VALUES (3, 'uploaded', 'feedfeedfeedfeedfeedfeedfeedfeed');
