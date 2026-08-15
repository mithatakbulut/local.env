ALTER TABLE instance ADD COLUMN crypto_instance_id TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS repo_key_epochs (
    repository_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    created_at DATETIME NOT NULL,
    retired_at DATETIME NULL,
    PRIMARY KEY(repository_id, epoch),
    FOREIGN KEY(repository_id) REFERENCES repositories(id)
);

CREATE TABLE IF NOT EXISTS wrapped_repo_keys (
    repository_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    wrapped_key BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY(repository_id, epoch, device_id),
    FOREIGN KEY(repository_id, epoch) REFERENCES repo_key_epochs(repository_id, epoch),
    FOREIGN KEY(device_id) REFERENCES devices(id)
);
