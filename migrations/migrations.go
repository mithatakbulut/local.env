// Package migrations embeds the ordered SQLite schema migrations.
package migrations

import "embed"

// FS holds SQL migration assets built into localenv-server.
//
//go:embed *.sql
var FS embed.FS

// Names is the ordered, append-only migration list. Schema downgrades are not
// supported by the server.
var Names = []string{"001_initial.sql", "002_github_setup.sql", "003_repository_contract.sql", "004_pr_readiness.sql", "005_cli_identity.sql", "006_repo_crypto.sql", "007_secret_versions.sql", "008_device_access.sql"}
