CREATE TABLE IF NOT EXISTS repositories (
    id TEXT PRIMARY KEY,
    github_repo_id INTEGER UNIQUE NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    active_key_epoch INTEGER NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS repo_files (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    schema_path TEXT NOT NULL,
    target_path TEXT NOT NULL,
    UNIQUE(repository_id, schema_path, target_path),
    FOREIGN KEY(repository_id) REFERENCES repositories(id)
);
