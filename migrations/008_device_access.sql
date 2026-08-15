CREATE TABLE IF NOT EXISTS device_access_requests (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    code_hash BLOB NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'revoked')),
    created_at DATETIME NOT NULL,
    approved_at DATETIME NULL,
    approved_by_device_id TEXT NULL,
    revoked_at DATETIME NULL,
    FOREIGN KEY(repository_id) REFERENCES repositories(id),
    FOREIGN KEY(device_id) REFERENCES devices(id),
    FOREIGN KEY(approved_by_device_id) REFERENCES devices(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS device_access_one_pending_per_device
    ON device_access_requests(repository_id, device_id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT NULL,
    actor_device_id TEXT NULL,
    repository_id TEXT NULL,
    event_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY(actor_device_id) REFERENCES devices(id),
    FOREIGN KEY(repository_id) REFERENCES repositories(id)
);

CREATE INDEX IF NOT EXISTS audit_events_repository_created
    ON audit_events(repository_id, created_at);
