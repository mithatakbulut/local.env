CREATE TABLE IF NOT EXISTS pull_requests (
    repository_id TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    head_sha TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    author_github_user_id INTEGER NOT NULL,
    state TEXT NOT NULL,
    merged_at DATETIME NULL,
    github_check_run_id INTEGER NULL,
    github_comment_id INTEGER NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY(repository_id, pr_number),
    FOREIGN KEY(repository_id) REFERENCES repositories(id)
);

CREATE TABLE IF NOT EXISTS pr_requirements (
    repository_id TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    file_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    requirement_state TEXT NOT NULL CHECK(requirement_state IN ('missing', 'ready', 'removed')),
    PRIMARY KEY(repository_id, pr_number, file_id, key_name),
    FOREIGN KEY(repository_id, pr_number) REFERENCES pull_requests(repository_id, pr_number)
);
