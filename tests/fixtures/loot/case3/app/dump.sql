-- A loose .sql file sitting at the webroot, no migration-tool naming
-- convention and no db/migration-style directory around it — the real
-- leaked-dump shape migration_guard.py must NEVER suppress. Must still
-- fire "Database dump file present".
INSERT INTO accounts (id, username, password_hash) VALUES (1, 'admin', 'deadbeefdeadbeefdeadbeefdeadbeef');
