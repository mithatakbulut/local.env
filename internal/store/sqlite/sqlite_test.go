package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/migrations"
)

func TestOpenAppliesMigrationsWALAndPermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, databaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("database permissions = %o, want %o", got, want)
	}

	row := store.db.QueryRow(`PRAGMA journal_mode`)
	var mode string
	if err := row.Scan(&mode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}

	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if count != len(migrations.Names) {
		t.Errorf("migration count = %d, want %d", count, len(migrations.Names))
	}
}

func TestPullRequestRequirementsPersistWithoutSchemaValuesAndKeepPublicationIDs(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveRepositoryConfigSnapshot(context.Background(), RepositoryConfigSnapshot{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main", Files: []RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}}); err != nil {
		t.Fatal(err)
	}
	pull := githubapp.PullRequest{Number: 100, BaseSHA: "base", HeadSHA: "head", AuthorID: 5, State: "open", Repository: githubapp.Repository{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main"}}
	requirements := []pranalysis.Requirement{{FileID: pranalysis.FileID(17, ".env.example", ".env.local"), KeyName: "STRIPE_SECRET_KEY", State: pranalysis.StateMissing}}
	readiness, err := store.SavePullRequestRequirements(context.Background(), pull, requirements)
	if err != nil || readiness.CheckRunID != 0 || readiness.CommentID != 0 {
		t.Fatalf("SavePullRequestRequirements() = (%#v, %v), want no publication IDs", readiness, err)
	}
	if err := store.SaveReadinessPublication(context.Background(), 17, 100, 101, 202); err != nil {
		t.Fatal(err)
	}
	readiness, err = store.SavePullRequestRequirements(context.Background(), pull, requirements)
	if err != nil || readiness.CheckRunID != 101 || readiness.CommentID != 202 {
		t.Fatalf("re-saved readiness = (%#v, %v), want retained IDs", readiness, err)
	}
	if err := store.ClosePullRequest(context.Background(), githubapp.PullRequest{Number: 100, BaseSHA: "base", HeadSHA: "head", AuthorID: 5, State: "merged", Repository: pull.Repository}); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := store.db.QueryRow(`SELECT state FROM pull_requests WHERE repository_id = 'github:17' AND pr_number = 100`).Scan(&state); err != nil || state != "merged" {
		t.Fatalf("stored PR state = %q, %v; want merged", state, err)
	}
	var schemaDefaultCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pr_requirements WHERE key_name LIKE '%non-secret-schema-default%'`).Scan(&schemaDefaultCount); err != nil || schemaDefaultCount != 0 {
		t.Fatalf("schema defaults persisted in requirements = %d, %v", schemaDefaultCount, err)
	}
}

func TestOpenRefusesDatabaseNewerThanCompiledMigrations(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("initial Open() error = %v", err)
	}
	if _, err := store.db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (999, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("Open() succeeded with a newer database schema")
	}
}

func TestRepositoryConfigSnapshotPersistsOnlyFileMappings(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	snapshot := RepositoryConfigSnapshot{
		GitHubRepoID:  42,
		Owner:         "acme",
		Name:          "api",
		DefaultBranch: "main",
		Files: []RepositoryFile{
			{SchemaPath: ".env.example", TargetPath: ".env.local"},
			{SchemaPath: "apps/web/.env.example", TargetPath: "apps/web/.env.local"},
		},
	}
	if err := store.SaveRepositoryConfigSnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("SaveRepositoryConfigSnapshot() error = %v", err)
	}
	got, err := store.RepositoryConfigSnapshot(context.Background(), 42)
	if err != nil {
		t.Fatalf("RepositoryConfigSnapshot() error = %v", err)
	}
	if got.GitHubRepoID != snapshot.GitHubRepoID || got.Owner != snapshot.Owner || got.Name != snapshot.Name || got.DefaultBranch != snapshot.DefaultBranch || len(got.Files) != 2 {
		t.Errorf("stored snapshot = %#v, want repository metadata and two mappings", got)
	}

	snapshot.Files = []RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}
	if err := store.SaveRepositoryConfigSnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("replace config snapshot: %v", err)
	}
	got, err = store.RepositoryConfigSnapshot(context.Background(), 42)
	if err != nil || len(got.Files) != 1 {
		t.Fatalf("replaced snapshot = %#v, %v; want one mapping", got, err)
	}
}

func TestRepositoryConfigSnapshotRejectsEscapingPath(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	err = store.SaveRepositoryConfigSnapshot(context.Background(), RepositoryConfigSnapshot{
		GitHubRepoID:  1,
		Owner:         "acme",
		Name:          "api",
		DefaultBranch: "main",
		Files:         []RepositoryFile{{SchemaPath: "../.env.example", TargetPath: ".env.local"}},
	})
	if err == nil {
		t.Fatal("SaveRepositoryConfigSnapshot() accepted escaping path")
	}
}
