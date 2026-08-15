// Package sqlite provides the v1 SQLite storage foundation.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/migrations"
	_ "modernc.org/sqlite"
)

const databaseFile = "localenv.db"

// Store owns a single SQLite connection. A single connection keeps connection
// pragmas (notably foreign_keys) consistently enabled for this small v1 server.
type Store struct {
	db *sql.DB
}

// Open creates the data directory and database with restrictive permissions,
// enables required pragmas, and applies all forward migrations before use.
func Open(ctx context.Context, dataDir string) (*Store, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("data directory must not be empty")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}

	path := filepath.Join(dataDir, databaseFile)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create database file: %w", err)
	}
	if closeErr := file.Close(); closeErr != nil {
		return nil, fmt.Errorf("close database file: %w", closeErr)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure database file: %w", err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.configure(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) configure(ctx context.Context) error {
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure sqlite (%s): %w", pragma, err)
		}
	}
	return nil
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	var highestApplied int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&highestApplied); err != nil {
		return fmt.Errorf("read current schema version: %w", err)
	}
	highestKnown, err := migrationVersion(migrations.Names[len(migrations.Names)-1])
	if err != nil {
		return err
	}
	if highestApplied > highestKnown {
		return fmt.Errorf("database schema version %d is newer than this server supports (%d)", highestApplied, highestKnown)
	}
	for _, name := range migrations.Names {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		var applied bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)`, version).Scan(&applied); err != nil {
			return fmt.Errorf("read migration %d: %w", version, err)
		}
		if applied {
			continue
		}
		sqlBytes, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		if _, err = tx.ExecContext(ctx, string(sqlBytes)); err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, version, time.Now().UTC())
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}

func migrationVersion(name string) (int, error) {
	prefix, _, found := strings.Cut(name, "_")
	if !found {
		return 0, fmt.Errorf("invalid migration filename %q", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("invalid migration filename %q", name)
	}
	return version, nil
}

// Ready proves that the database is readable and all compiled migrations are
// recorded. It does not expose database details in the HTTP response.
func (s *Store) Ready(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	for _, name := range migrations.Names {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		var applied bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)`, version).Scan(&applied); err != nil {
			return fmt.Errorf("read migration %d: %w", version, err)
		}
		if !applied {
			return fmt.Errorf("migration %d is not applied", version)
		}
	}
	return nil
}

// ConfigureGitHubInstance persists the public, non-secret instance identity.
// Private GitHub credentials are deliberately stored only in the encrypted file
// managed by githubapp.CredentialStore.
func (s *Store) ConfigureGitHubInstance(ctx context.Context, organizationID int64, organizationLogin string, appID int64, publicURL, displayName string) error {
	if organizationID <= 0 || strings.TrimSpace(organizationLogin) == "" || appID <= 0 {
		return errors.New("incomplete GitHub instance configuration")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO instance(id, github_org_id, github_org_login, github_app_id, public_url, display_name, created_at)
		VALUES ('singleton', ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			github_org_id = excluded.github_org_id,
			github_org_login = excluded.github_org_login,
			github_app_id = excluded.github_app_id,
			public_url = excluded.public_url,
			display_name = excluded.display_name`,
		organizationID, organizationLogin, appID, publicURL, displayName, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("store GitHub instance configuration: %w", err)
	}
	return nil
}

// GitHubSetupReady reports whether the non-secret part of setup was persisted.
func (s *Store) GitHubSetupReady(ctx context.Context) error {
	var appID int64
	if err := s.db.QueryRowContext(ctx, `SELECT github_app_id FROM instance WHERE id = 'singleton'`).Scan(&appID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("GitHub App setup has not completed")
		}
		return fmt.Errorf("read GitHub instance configuration: %w", err)
	}
	if appID <= 0 {
		return errors.New("GitHub App setup is incomplete")
	}
	return nil
}

// ProcessGitHubWebhook records a delivery and its installation/repository
// effect in one transaction. A duplicate delivery is never processed twice.
func (s *Store) ProcessGitHubWebhook(ctx context.Context, event githubapp.WebhookEvent) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin webhook transaction: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO webhook_deliveries(github_delivery_id, event_type, received_at, status) VALUES (?, ?, ?, 'received') ON CONFLICT(github_delivery_id) DO NOTHING`, event.DeliveryID, event.EventType, time.Now().UTC())
	if err != nil {
		return false, fmt.Errorf("record GitHub webhook delivery: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect GitHub webhook delivery: %w", err)
	}
	if inserted == 0 {
		return true, nil
	}
	if err := s.applyGitHubWebhook(ctx, tx, event); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE webhook_deliveries SET processed_at = ?, status = 'processed' WHERE github_delivery_id = ?`, time.Now().UTC(), event.DeliveryID); err != nil {
		return false, fmt.Errorf("complete GitHub webhook delivery: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit GitHub webhook delivery: %w", err)
	}
	return false, nil
}

func (s *Store) applyGitHubWebhook(ctx context.Context, tx *sql.Tx, event githubapp.WebhookEvent) error {
	switch event.EventType {
	case "installation", "installation_repositories":
		var deletedAt any
		if event.InstallationDeleted {
			deletedAt = time.Now().UTC()
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO github_installations(github_installation_id, github_org_id, github_org_login, deleted_at, created_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(github_installation_id) DO UPDATE SET
				github_org_id = excluded.github_org_id,
				github_org_login = excluded.github_org_login,
				deleted_at = excluded.deleted_at`,
			event.InstallationID, nullableID(event.InstallationOrgID), nullableText(event.InstallationOrgLogin), deletedAt, time.Now().UTC()); err != nil {
			return fmt.Errorf("store GitHub installation: %w", err)
		}
		if event.InstallationDeleted {
			if _, err := tx.ExecContext(ctx, `UPDATE github_installation_repositories SET active = 0, updated_at = ? WHERE github_installation_id = ?`, time.Now().UTC(), event.InstallationID); err != nil {
				return fmt.Errorf("deactivate removed GitHub installation repositories: %w", err)
			}
		}
		for _, repository := range event.RepositoriesAdded {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO github_installation_repositories(github_repo_id, github_installation_id, owner, name, default_branch, active, updated_at)
				VALUES (?, ?, ?, ?, ?, 1, ?)
				ON CONFLICT(github_repo_id) DO UPDATE SET
					github_installation_id = excluded.github_installation_id,
					owner = excluded.owner,
					name = excluded.name,
					default_branch = excluded.default_branch,
					active = 1,
					updated_at = excluded.updated_at`,
				repository.GitHubRepoID, event.InstallationID, repository.Owner, repository.Name, repository.DefaultBranch, time.Now().UTC()); err != nil {
				return fmt.Errorf("store discovered GitHub repository: %w", err)
			}
		}
		for _, repository := range event.RepositoriesRemoved {
			if _, err := tx.ExecContext(ctx, `UPDATE github_installation_repositories SET active = 0, updated_at = ? WHERE github_repo_id = ? AND github_installation_id = ?`, time.Now().UTC(), repository.GitHubRepoID, event.InstallationID); err != nil {
				return fmt.Errorf("remove discovered GitHub repository: %w", err)
			}
		}
	}
	return nil
}

func nullableID(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// DiscoveredRepositories lists safe setup metadata, not managed repository
// contracts. P2 will add localenv.yaml validation and activation.
func (s *Store) DiscoveredRepositories(ctx context.Context) ([]githubapp.Repository, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT owner, name FROM github_installation_repositories WHERE active = 1 ORDER BY owner, name`)
	if err != nil {
		return nil, fmt.Errorf("list discovered GitHub repositories: %w", err)
	}
	defer rows.Close()
	var repositories []githubapp.Repository
	for rows.Next() {
		var repository githubapp.Repository
		if err := rows.Scan(&repository.Owner, &repository.Name); err != nil {
			return nil, fmt.Errorf("scan discovered GitHub repository: %w", err)
		}
		repositories = append(repositories, repository)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate discovered GitHub repositories: %w", err)
	}
	return repositories, nil
}

// Close closes the database connection.
func (s *Store) Close() error { return s.db.Close() }
