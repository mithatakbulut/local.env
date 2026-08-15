CREATE TABLE IF NOT EXISTS secret_versions (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('baseline', 'pull_request')),
    scope_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    key_epoch INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_by_user_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    archived_at DATETIME NULL,
    promoted_at DATETIME NULL,
    UNIQUE(repository_id, file_id, key_name, scope, scope_id, version),
    FOREIGN KEY(repository_id) REFERENCES repositories(id)
);

CREATE INDEX IF NOT EXISTS secret_versions_current
    ON secret_versions(repository_id, file_id, key_name, scope, scope_id, archived_at, version DESC);

CREATE TABLE IF NOT EXISTS repo_revisions (
    repository_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY(repository_id) REFERENCES repositories(id)
);
