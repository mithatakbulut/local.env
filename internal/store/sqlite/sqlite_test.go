package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/localenv/localenv/internal/cryptokit"
	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/migrations"
)

func TestCLIAuthStoresOnlyHashedCodesAndSessionTokens(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	user := githubapp.User{ID: 41, Login: "developer"}
	exchangeCode := "non-secret-test-exchange-code"
	if err := store.CreateAuthExchange(ctx, user, exchangeCode, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthExchange(ctx, exchangeCode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthExchange(ctx, exchangeCode); err == nil {
		t.Fatal("exchange code was accepted twice")
	}
	sessionToken := "non-secret-test-opaque-session-token"
	if err := store.CreateSession(ctx, user, sessionToken, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.RegisterDevice(ctx, sessionToken, "device-test-id", "test-device", identity.Recipient().String(), "sha256:0000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := store.AuthenticateSession(ctx, sessionToken)
	if err != nil || authenticated.User.Login != user.Login || authenticated.Device.ID != device.ID {
		t.Fatalf("AuthenticateSession() = %#v, %v", authenticated, err)
	}
	var storedTokens string
	if err := store.db.QueryRow(`SELECT CAST(token_hash AS TEXT) FROM sessions LIMIT 1`).Scan(&storedTokens); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedTokens, sessionToken) {
		t.Fatal("plaintext session token was persisted")
	}
	var storedExchanges string
	if err := store.db.QueryRow(`SELECT CAST(code_hash AS TEXT) FROM auth_exchanges LIMIT 1`).Scan(&storedExchanges); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedExchanges, exchangeCode) {
		t.Fatal("plaintext exchange code was persisted")
	}
	if err := store.RevokeSession(ctx, sessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateSession(ctx, sessionToken); err == nil {
		t.Fatal("revoked session authenticated")
	}
}

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

func TestRepositoryCryptoBootstrapStoresOnlyWrappedREK(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.ConfigureGitHubInstance(ctx, 2, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRepositoryConfigSnapshot(ctx, RepositoryConfigSnapshot{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main", Files: []RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO github_installations(github_installation_id, created_at) VALUES (7, ?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO github_installation_repositories(github_repo_id, github_installation_id, owner, name, default_branch, active, updated_at) VALUES (17, 7, 'acme', 'api', 'main', 1, ?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	user := githubapp.User{ID: 41, Login: "developer"}
	if err := store.CreateSession(ctx, user, "non-secret-test-session", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.RegisterDevice(ctx, "non-secret-test-session", "device-test-id", "test-device", identity.Recipient().String(), "sha256:0000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	// This explicit non-secret sentinel is a stand-in for the client-only REK;
	// the assertion below proves it never reaches SQLite in plaintext.
	rek := []byte("non-secret-test-rek-sentinel-000")
	if len(rek) != cryptokit.REKSize {
		t.Fatalf("test REK length = %d", len(rek))
	}
	wrapped, err := cryptokit.WrapREK(rek, identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.InitializeRepositoryCrypto(ctx, "acme", "api", user.ID, device.ID, wrapped)
	if err != nil || !state.Initialized || state.ActiveKeyEpoch != 1 || state.InstanceID == "" {
		t.Fatalf("InitializeRepositoryCrypto() = %#v, %v", state, err)
	}
	var storedWrapped string
	if err := store.db.QueryRow(`SELECT CAST(wrapped_key AS TEXT) FROM wrapped_repo_keys WHERE repository_id = 'github:17' AND epoch = 1 AND device_id = ?`, device.ID).Scan(&storedWrapped); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedWrapped, string(rek)) {
		t.Fatal("plaintext repository key was persisted")
	}
	if _, err := store.InitializeRepositoryCrypto(ctx, "acme", "api", user.ID, device.ID, wrapped); !errors.Is(err, ErrRepositoryAlreadyInitialized) {
		t.Fatalf("second bootstrap error = %v, want already initialized", err)
	}
}

func TestEncryptedPullSecretUpdatePromotesOrDiscardsWithoutPlaintext(t *testing.T) {
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.ConfigureGitHubInstance(ctx, 2, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRepositoryConfigSnapshot(ctx, RepositoryConfigSnapshot{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main", Files: []RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO github_installations(github_installation_id, created_at) VALUES (7, ?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO github_installation_repositories(github_repo_id, github_installation_id, owner, name, default_branch, active, updated_at) VALUES (17, 7, 'acme', 'api', 'main', 1, ?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	user := githubapp.User{ID: 41, Login: "developer"}
	if err := store.CreateSession(ctx, user, "non-secret-test-session", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.RegisterDevice(ctx, "non-secret-test-session", "device-test-id", "test-device", identity.Recipient().String(), "sha256:0000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	rek := []byte("non-secret-test-rek-sentinel-000")
	wrapped, err := cryptokit.WrapREK(rek, identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.InitializeRepositoryCrypto(ctx, "acme", "api", user.ID, device.ID, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	fileID := pranalysis.FileID(17, ".env.example", ".env.local")
	baseline, err := cryptokit.Encrypt(rek, []byte("baseline-non-secret-sentinel"), cryptokit.AAD{InstanceID: state.InstanceID, GitHubRepoID: 17, FilePath: ".env.local", KeyName: "DATABASE_URL", Scope: "baseline", Version: 1, KeyEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateBaselineSecret(ctx, "acme", "api", user.ID, device.ID, fileID, "DATABASE_URL", 0, SecretEnvelope(baseline)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.RepositorySnapshotForDevice(ctx, "acme", "api", user.ID, device.ID)
	if err != nil || len(snapshot.Secrets) != 1 || snapshot.Secrets[0].KeyName != "DATABASE_URL" || strings.Contains(string(snapshot.Secrets[0].Envelope.Ciphertext), "baseline-non-secret-sentinel") {
		t.Fatalf("baseline snapshot = %#v, %v", snapshot, err)
	}
	pull := githubapp.PullRequest{Number: 100, BaseSHA: "base", HeadSHA: "head", AuthorID: user.ID, State: "open", Repository: githubapp.Repository{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main"}}
	if _, err := store.SavePullRequestRequirements(ctx, pull, []pranalysis.Requirement{{FileID: fileID, KeyName: "STRIPE_SECRET_KEY", State: pranalysis.StateMissing}}); err != nil {
		t.Fatal(err)
	}
	requirements, err := store.PullRequirementsForDevice(ctx, "acme", "api", 100, user.ID, device.ID)
	if err != nil || len(requirements.Requirements) != 1 || requirements.Requirements[0].CurrentVersion != 0 {
		t.Fatalf("pull requirements = %#v, %v", requirements, err)
	}
	envelope, err := cryptokit.Encrypt(rek, []byte("non-secret-test-value"), cryptokit.AAD{InstanceID: state.InstanceID, GitHubRepoID: 17, FilePath: ".env.local", KeyName: "STRIPE_SECRET_KEY", Scope: "pull_request", ScopeID: "100", Version: 1, KeyEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := store.UpdatePullRequestSecret(ctx, "acme", "api", 100, user.ID, device.ID, fileID, "STRIPE_SECRET_KEY", 0, SecretEnvelope(envelope))
	if err != nil || len(readiness.Requirements) != 1 || readiness.Requirements[0].State != pranalysis.StateReady {
		t.Fatalf("UpdatePullRequestSecret() = %#v, %v", readiness, err)
	}
	if _, err := store.UpdatePullRequestSecret(ctx, "acme", "api", 100, user.ID, device.ID, fileID, "STRIPE_SECRET_KEY", 0, SecretEnvelope(envelope)); !errors.Is(err, ErrSecretVersionConflict) {
		t.Fatalf("stale update error = %v, want conflict", err)
	}
	pull.State = "merged"
	if err := store.ClosePullRequest(ctx, pull); err != nil {
		t.Fatal(err)
	}
	var promotedAt any
	var stored string
	if err := store.db.QueryRow(`SELECT promoted_at, CAST(ciphertext AS TEXT) FROM secret_versions WHERE repository_id = 'github:17' AND scope = 'pull_request' AND scope_id = '100'`).Scan(&promotedAt, &stored); err != nil || promotedAt == nil || strings.Contains(stored, "non-secret-test-value") {
		t.Fatalf("promoted ciphertext = %q, %v, %v", stored, promotedAt, err)
	}
	pull.Number, pull.State = 101, "open"
	if _, err := store.SavePullRequestRequirements(ctx, pull, []pranalysis.Requirement{{FileID: fileID, KeyName: "SECOND_KEY", State: pranalysis.StateMissing}}); err != nil {
		t.Fatal(err)
	}
	envelope, err = cryptokit.Encrypt(rek, []byte("another-non-secret-sentinel"), cryptokit.AAD{InstanceID: state.InstanceID, GitHubRepoID: 17, FilePath: ".env.local", KeyName: "SECOND_KEY", Scope: "pull_request", ScopeID: "101", Version: 1, KeyEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdatePullRequestSecret(ctx, "acme", "api", 101, user.ID, device.ID, fileID, "SECOND_KEY", 0, SecretEnvelope(envelope)); err != nil {
		t.Fatal(err)
	}
	pull.State = "closed"
	if err := store.ClosePullRequest(ctx, pull); err != nil {
		t.Fatal(err)
	}
	var archivedAt any
	if err := store.db.QueryRow(`SELECT archived_at FROM secret_versions WHERE repository_id = 'github:17' AND scope_id = '101'`).Scan(&archivedAt); err != nil || archivedAt == nil {
		t.Fatalf("discarded pending ciphertext archived_at = %v, %v", archivedAt, err)
	}
}
