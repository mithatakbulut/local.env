package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
)

// DashboardRepository is deliberately metadata-only. It has no ciphertext,
// wrapped key, secret value, or private device identity field.
type DashboardRepository struct {
	Owner              string
	Name               string
	DefaultBranch      string
	ActiveKeyEpoch     int64
	Revision           int64
	ManagedKeyCount    int
	OpenPullRequestCnt int
	Files              []RepositoryFile
	OpenPullRequests   []DashboardPullRequest
}

// DashboardPullRequest is the public readiness state shown by the web UI.
type DashboardPullRequest struct {
	Number       int
	State        string
	UpdatedAt    time.Time
	Requirements []pranalysis.Requirement
}

// AuditEvent contains allowlisted metadata about an action. Audit metadata is
// never a request body, secret envelope, session, or repository key.
type AuditEvent struct {
	EventType     string
	ActorUserID   string
	ActorDeviceID string
	RepositoryID  string
	Metadata      map[string]string
	CreatedAt     time.Time
}

// DashboardOrganization identifies the one organization configured for the
// instance, allowing the server to check an OAuth user's direct membership.
func (s *Store) DashboardOrganization(ctx context.Context) (githubapp.Organization, error) {
	var organization githubapp.Organization
	if err := s.db.QueryRowContext(ctx, `SELECT github_org_id, github_org_login FROM instance WHERE id = 'singleton'`).Scan(&organization.ID, &organization.Login); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return githubapp.Organization{}, errors.New("GitHub App setup has not completed")
		}
		return githubapp.Organization{}, fmt.Errorf("read dashboard organization: %w", err)
	}
	if organization.ID <= 0 || organization.Login == "" {
		return githubapp.Organization{}, errors.New("configured dashboard organization is incomplete")
	}
	return organization, nil
}

// DashboardRepositories returns only configured repository metadata.
func (s *Store) DashboardRepositories(ctx context.Context) ([]DashboardRepository, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.owner, r.name, r.default_branch, r.active_key_epoch,
		       COALESCE(rv.revision, 0),
		       (SELECT COUNT(DISTINCT sv.file_id || char(0) || sv.key_name)
		          FROM secret_versions sv WHERE sv.repository_id = r.id AND sv.archived_at IS NULL),
		       (SELECT COUNT(*) FROM pull_requests p WHERE p.repository_id = r.id AND p.state = 'open')
		FROM repositories r
		LEFT JOIN repo_revisions rv ON rv.repository_id = r.id
		ORDER BY r.owner, r.name`)
	if err != nil {
		return nil, fmt.Errorf("list dashboard repositories: %w", err)
	}
	defer rows.Close()
	var result []DashboardRepository
	for rows.Next() {
		var repository DashboardRepository
		if err := rows.Scan(&repository.Owner, &repository.Name, &repository.DefaultBranch, &repository.ActiveKeyEpoch, &repository.Revision, &repository.ManagedKeyCount, &repository.OpenPullRequestCnt); err != nil {
			return nil, fmt.Errorf("scan dashboard repository: %w", err)
		}
		result = append(result, repository)
	}
	return result, rows.Err()
}

// DashboardRepository returns safe details for exactly one configured repo.
func (s *Store) DashboardRepository(ctx context.Context, owner, name string) (DashboardRepository, error) {
	if !validRepositoryName(owner) || !validRepositoryName(name) {
		return DashboardRepository{}, ErrRepositoryNotManaged
	}
	var repository DashboardRepository
	var id string
	err := s.db.QueryRowContext(ctx, `
		SELECT r.id, r.owner, r.name, r.default_branch, r.active_key_epoch,
		       COALESCE(rv.revision, 0),
		       (SELECT COUNT(DISTINCT sv.file_id || char(0) || sv.key_name)
		          FROM secret_versions sv WHERE sv.repository_id = r.id AND sv.archived_at IS NULL),
		       (SELECT COUNT(*) FROM pull_requests p WHERE p.repository_id = r.id AND p.state = 'open')
		FROM repositories r LEFT JOIN repo_revisions rv ON rv.repository_id = r.id
		WHERE r.owner = ? AND r.name = ?`, owner, name).Scan(&id, &repository.Owner, &repository.Name, &repository.DefaultBranch, &repository.ActiveKeyEpoch, &repository.Revision, &repository.ManagedKeyCount, &repository.OpenPullRequestCnt)
	if errors.Is(err, sql.ErrNoRows) {
		return DashboardRepository{}, ErrRepositoryNotManaged
	}
	if err != nil {
		return DashboardRepository{}, fmt.Errorf("read dashboard repository: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT schema_path, target_path FROM repo_files WHERE repository_id = ? ORDER BY schema_path, target_path`, id)
	if err != nil {
		return DashboardRepository{}, fmt.Errorf("list dashboard repository files: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var file RepositoryFile
		if err := rows.Scan(&file.SchemaPath, &file.TargetPath); err != nil {
			return DashboardRepository{}, fmt.Errorf("scan dashboard repository file: %w", err)
		}
		repository.Files = append(repository.Files, file)
	}
	if err := rows.Err(); err != nil {
		return DashboardRepository{}, err
	}
	pulls, err := s.db.QueryContext(ctx, `SELECT pr_number, state, updated_at FROM pull_requests WHERE repository_id = ? AND state = 'open' ORDER BY pr_number DESC`, id)
	if err != nil {
		return DashboardRepository{}, fmt.Errorf("list dashboard pull requests: %w", err)
	}
	defer pulls.Close()
	for pulls.Next() {
		var pull DashboardPullRequest
		if err := pulls.Scan(&pull.Number, &pull.State, &pull.UpdatedAt); err != nil {
			return DashboardRepository{}, fmt.Errorf("scan dashboard pull request: %w", err)
		}
		repository.OpenPullRequests = append(repository.OpenPullRequests, pull)
	}
	return repository, pulls.Err()
}

// DashboardPullRequest returns key names and readiness states, never values.
func (s *Store) DashboardPullRequest(ctx context.Context, owner, name string, number int) (DashboardPullRequest, error) {
	if number <= 0 {
		return DashboardPullRequest{}, ErrRepositoryNotManaged
	}
	var result DashboardPullRequest
	var repositoryID string
	err := s.db.QueryRowContext(ctx, `SELECT r.id, p.pr_number, p.state, p.updated_at FROM repositories r JOIN pull_requests p ON p.repository_id = r.id WHERE r.owner = ? AND r.name = ? AND p.pr_number = ?`, owner, name, number).Scan(&repositoryID, &result.Number, &result.State, &result.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DashboardPullRequest{}, ErrRepositoryNotManaged
	}
	if err != nil {
		return DashboardPullRequest{}, fmt.Errorf("read dashboard pull request: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT file_id, key_name, requirement_state FROM pr_requirements WHERE repository_id = ? AND pr_number = ? ORDER BY key_name, file_id`, repositoryID, number)
	if err != nil {
		return DashboardPullRequest{}, fmt.Errorf("list dashboard pull requirements: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var requirement pranalysis.Requirement
		if err := rows.Scan(&requirement.FileID, &requirement.KeyName, &requirement.State); err != nil {
			return DashboardPullRequest{}, fmt.Errorf("scan dashboard pull requirement: %w", err)
		}
		result.Requirements = append(result.Requirements, requirement)
	}
	return result, rows.Err()
}

// DashboardDevices returns public, active device metadata only.
func (s *Store) DashboardDevices(ctx context.Context) ([]RepositoryDevice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, d.github_user_id, u.login, d.name, d.public_recipient, d.fingerprint, d.created_at, d.last_seen_at, EXISTS(SELECT 1 FROM wrapped_repo_keys wr WHERE wr.device_id = d.id) FROM devices d JOIN github_users u ON u.github_user_id = d.github_user_id WHERE d.revoked_at IS NULL ORDER BY d.created_at DESC, d.id`)
	if err != nil {
		return nil, fmt.Errorf("list dashboard devices: %w", err)
	}
	defer rows.Close()
	var result []RepositoryDevice
	for rows.Next() {
		var device RepositoryDevice
		if err := rows.Scan(&device.ID, &device.GitHubUserID, &device.GitHubLogin, &device.Name, &device.PublicRecipient, &device.Fingerprint, &device.CreatedAt, &device.LastSeenAt, &device.HasKey); err != nil {
			return nil, fmt.Errorf("scan dashboard device: %w", err)
		}
		result = append(result, device)
	}
	return result, rows.Err()
}

// DashboardAuditEvents returns a bounded, metadata-only audit trail.
func (s *Store) DashboardAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_type, COALESCE(actor_user_id, ''), COALESCE(actor_device_id, ''), COALESCE(repository_id, ''), metadata_json, created_at FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list dashboard audit events: %w", err)
	}
	defer rows.Close()
	var result []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var raw string
		if err := rows.Scan(&event.EventType, &event.ActorUserID, &event.ActorDeviceID, &event.RepositoryID, &raw, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan dashboard audit event: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &event.Metadata); err != nil {
			return nil, fmt.Errorf("decode dashboard audit metadata: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}
