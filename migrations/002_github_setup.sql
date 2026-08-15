CREATE TABLE IF NOT EXISTS instance (
    id TEXT PRIMARY KEY,
    github_org_id INTEGER NOT NULL,
    github_org_login TEXT NOT NULL,
    github_app_id INTEGER NOT NULL,
    public_url TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS github_installations (
    id INTEGER PRIMARY KEY,
    github_installation_id INTEGER UNIQUE NOT NULL,
    github_org_id INTEGER,
    github_org_login TEXT,
    deleted_at DATETIME NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS github_installation_repositories (
    github_repo_id INTEGER PRIMARY KEY,
    github_installation_id INTEGER NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY(github_installation_id) REFERENCES github_installations(github_installation_id)
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    github_delivery_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    received_at DATETIME NOT NULL,
    processed_at DATETIME NULL,
    status TEXT NOT NULL
);
