// Package migrations embeds the ordered SQLite schema migrations.
package migrations

import "embed"

// FS holds SQL migration assets built into localenv-server.
//
//go:embed *.sql
var FS embed.FS

// Names is the ordered, append-only migration list. Schema downgrades are not
// supported by the server.
var Names = []string{"001_initial.sql", "002_github_setup.sql"}
