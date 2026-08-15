CREATE TABLE IF NOT EXISTS github_users (
    github_user_id INTEGER PRIMARY KEY,
    login TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_exchanges (
    code_hash BLOB PRIMARY KEY,
    github_user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY(github_user_id) REFERENCES github_users(github_user_id)
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    github_user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    public_recipient TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    FOREIGN KEY(github_user_id) REFERENCES github_users(github_user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    github_user_id INTEGER NOT NULL,
    device_id TEXT NULL,
    created_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    FOREIGN KEY(github_user_id) REFERENCES github_users(github_user_id),
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE INDEX IF NOT EXISTS sessions_active_by_user ON sessions(github_user_id, expires_at);
CREATE INDEX IF NOT EXISTS devices_active_by_user ON devices(github_user_id, revoked_at);
