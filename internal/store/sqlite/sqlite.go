// Package sqlite provides the v1 SQLite storage foundation.
package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/migrations"
	_ "modernc.org/sqlite"
)

const databaseFile = "localenv.db"

// ErrRepositoryNotManaged lets webhook handling safely ignore repositories
// where local.env has not yet persisted a validated contract.
var (
	ErrRepositoryNotManaged         = errors.New("repository is not managed")
	ErrRepositoryAlreadyInitialized = errors.New("repository encryption is already initialized")
	ErrSecretVersionConflict        = errors.New("secret version conflict")
	ErrPullRequestNotOpen           = errors.New("pull request is not open")
	ErrDeviceAccessNotFound         = errors.New("device access request not found")
	ErrKeyRotationConflict          = errors.New("repository key rotation conflict")
)

// Store owns a single SQLite connection. A single connection keeps connection
// pragmas (notably foreign_keys) consistently enabled for this small v1 server.
type Store struct {
	db *sql.DB
}

// AuthenticatedSession is the public identity derived from an active opaque
// session. It deliberately has no token or OAuth credential field.
type AuthenticatedSession struct {
	User   githubapp.User
	Device Device
}

// Device is public device metadata. Private age identities never enter this
// package or the server database.
type Device struct {
	ID              string    `json:"id"`
	GitHubUserID    int64     `json:"github_user_id"`
	Name            string    `json:"name"`
	PublicRecipient string    `json:"public_recipient"`
	Fingerprint     string    `json:"fingerprint"`
	CreatedAt       time.Time `json:"created_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

// RepositoryCryptoState is the non-secret bootstrap metadata a client needs
// to construct canonical AAD and initialize an uninitialized repository. It
// deliberately has no repository key or wrapped-key field.
type RepositoryCryptoState struct {
	InstanceID     string `json:"instance_id"`
	GitHubRepoID   int64  `json:"github_repo_id"`
	Owner          string `json:"owner"`
	Name           string `json:"name"`
	ActiveKeyEpoch int64  `json:"active_key_epoch"`
	InstallationID int64  `json:"-"`
	Initialized    bool   `json:"initialized"`
}

// SecretEnvelope is the opaque ciphertext record accepted by the server. It
// has deliberately no plaintext field; clients construct it after local AEAD
// encryption.
type SecretEnvelope struct {
	Algorithm  string `json:"algorithm"`
	KeyEpoch   int64  `json:"key_epoch"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Version    int64  `json:"version"`
}

// PullRequirement is the public metadata a CLI needs to encrypt a missing PR
// value with the next immutable version number.
type PullRequirement struct {
	FileID         string `json:"file_id"`
	FilePath       string `json:"file_path"`
	KeyName        string `json:"key_name"`
	State          string `json:"state"`
	CurrentVersion int64  `json:"current_version"`
}

// PullRequirementsResponse includes the requesting device's age-wrapped REK,
// never a plaintext REK or plaintext secret value.
type PullRequirementsResponse struct {
	Repository   RepositoryCryptoState `json:"repository"`
	PullRequest  githubapp.PullRequest `json:"pull_request"`
	WrappedREK   []byte                `json:"wrapped_rek"`
	Requirements []PullRequirement     `json:"requirements"`
}

// SecretSnapshot is an opaque, decryptable-only-on-device secret record.
// Scope fields are returned because they are authenticated AAD inputs.
type SecretSnapshot struct {
	FileID   string         `json:"file_id"`
	FilePath string         `json:"file_path"`
	KeyName  string         `json:"key_name"`
	Scope    string         `json:"scope"`
	ScopeID  string         `json:"scope_id"`
	Envelope SecretEnvelope `json:"envelope"`
}

type RepositorySnapshot struct {
	Repository RepositoryCryptoState `json:"repository"`
	WrappedREK []byte                `json:"wrapped_rek"`
	Secrets    []SecretSnapshot      `json:"secrets"`
}

// DeviceAccessRequest contains only public identity metadata. The approval
// code is intentionally never stored in this type or in SQLite as plaintext.
type DeviceAccessRequest struct {
	ID              string    `json:"id"`
	GitHubUserID    int64     `json:"github_user_id"`
	GitHubLogin     string    `json:"github_login"`
	DeviceID        string    `json:"device_id"`
	DeviceName      string    `json:"device_name"`
	PublicRecipient string    `json:"public_recipient"`
	Fingerprint     string    `json:"fingerprint"`
	CreatedAt       time.Time `json:"created_at"`
}

type RepositoryDevice struct {
	Device
	GitHubLogin string `json:"github_login"`
	HasKey      bool   `json:"has_key"`
}

// KeyRotation is the ciphertext-only, client-produced replacement snapshot
// for one repository key epoch. The server cannot construct it because it
// never has a plaintext REK or secret value.
type KeyRotation struct {
	ExpectedEpoch int64                `json:"expected_epoch"`
	WrappedKeys   []RotationWrappedKey `json:"wrapped_keys"`
	Secrets       []RotationSecret     `json:"secrets"`
}

type RotationWrappedKey struct {
	DeviceID   string `json:"device_id"`
	WrappedREK []byte `json:"wrapped_rek"`
}

type RotationSecret struct {
	FileID   string         `json:"file_id"`
	FilePath string         `json:"file_path"`
	KeyName  string         `json:"key_name"`
	Scope    string         `json:"scope"`
	ScopeID  string         `json:"scope_id"`
	Envelope SecretEnvelope `json:"envelope"`
}

// CreateAuthExchange records a one-time, short-lived CLI exchange code by
// hash only. code must be random and is never persisted or logged.
func (s *Store) CreateAuthExchange(ctx context.Context, user githubapp.User, code string, expiresAt time.Time) error {
	if user.ID <= 0 || strings.TrimSpace(user.Login) == "" || code == "" || expiresAt.Before(time.Now().UTC()) {
		return errors.New("invalid authentication exchange")
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO github_users(github_user_id, login, created_at, last_seen_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(github_user_id) DO UPDATE SET login = excluded.login, last_seen_at = excluded.last_seen_at`, user.ID, user.Login, now, now)
	if err != nil {
		return fmt.Errorf("store GitHub user: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_exchanges(code_hash, github_user_id, expires_at, consumed_at, created_at) VALUES (?, ?, ?, NULL, ?)`, tokenHash(code), user.ID, expiresAt.UTC(), now)
	if err != nil {
		return fmt.Errorf("store authentication exchange: %w", err)
	}
	return nil
}

// ConsumeAuthExchange atomically invalidates an exchange code and returns its
// GitHub user. The plaintext exchange code is compared only through its hash.
func (s *Store) ConsumeAuthExchange(ctx context.Context, code string) (githubapp.User, error) {
	if code == "" {
		return githubapp.User{}, errors.New("authentication exchange code is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return githubapp.User{}, fmt.Errorf("begin authentication exchange: %w", err)
	}
	defer tx.Rollback()
	var user githubapp.User
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT u.github_user_id, u.login, e.expires_at FROM auth_exchanges e JOIN github_users u ON u.github_user_id = e.github_user_id WHERE e.code_hash = ? AND e.consumed_at IS NULL`, tokenHash(code)).Scan(&user.ID, &user.Login, &expiresAt)
	if err != nil || !expiresAt.After(time.Now().UTC()) {
		return githubapp.User{}, errors.New("authentication exchange is invalid or expired")
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth_exchanges SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL`, time.Now().UTC(), tokenHash(code))
	if err != nil {
		return githubapp.User{}, fmt.Errorf("consume authentication exchange: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return githubapp.User{}, errors.New("authentication exchange is invalid or expired")
	}
	if err := tx.Commit(); err != nil {
		return githubapp.User{}, fmt.Errorf("commit authentication exchange: %w", err)
	}
	return user, nil
}

// CreateSession persists only the SHA-256 hash of an already random 256-bit
// opaque token. Sessions have no OAuth access-token field.
func (s *Store) CreateSession(ctx context.Context, user githubapp.User, token string, expiresAt time.Time) error {
	if user.ID <= 0 || strings.TrimSpace(user.Login) == "" || token == "" || !expiresAt.After(time.Now().UTC()) {
		return errors.New("invalid session")
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create session: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO github_users(github_user_id, login, created_at, last_seen_at) VALUES (?, ?, ?, ?) ON CONFLICT(github_user_id) DO UPDATE SET login = excluded.login, last_seen_at = excluded.last_seen_at`, user.ID, user.Login, now, now); err != nil {
		return fmt.Errorf("store session user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(token_hash, github_user_id, device_id, created_at, last_seen_at, expires_at, revoked_at) VALUES (?, ?, NULL, ?, ?, ?, NULL)`, tokenHash(token), user.ID, now, now, expiresAt.UTC()); err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session: %w", err)
	}
	return nil
}

// AuthenticateSession validates a bearer token without returning it.
func (s *Store) AuthenticateSession(ctx context.Context, token string) (AuthenticatedSession, error) {
	if token == "" {
		return AuthenticatedSession{}, errors.New("session token is required")
	}
	now := time.Now().UTC()
	var result AuthenticatedSession
	var deviceID, name, recipient, fingerprint sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT u.github_user_id, u.login, s.device_id, d.name, d.public_recipient, d.fingerprint
		FROM sessions s JOIN github_users u ON u.github_user_id = s.github_user_id
		LEFT JOIN devices d ON d.id = s.device_id AND d.revoked_at IS NULL
		WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?`, tokenHash(token), now).Scan(&result.User.ID, &result.User.Login, &deviceID, &name, &recipient, &fingerprint)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthenticatedSession{}, errors.New("session is invalid or expired")
		}
		return AuthenticatedSession{}, fmt.Errorf("authenticate session: %w", err)
	}
	if deviceID.Valid {
		result.Device = Device{ID: deviceID.String, GitHubUserID: result.User.ID, Name: name.String, PublicRecipient: recipient.String, Fingerprint: fingerprint.String}
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`, now, tokenHash(token))
	return result, nil
}

// RegisterDevice associates an active session with its locally generated age
// recipient. It receives only public identity metadata.
func (s *Store) RegisterDevice(ctx context.Context, token, id, name, recipient, fingerprint string) (Device, error) {
	if token == "" || id == "" || !validDeviceText(name, 128) || !validDeviceText(recipient, 256) || !validDeviceText(fingerprint, 128) {
		return Device{}, errors.New("invalid device registration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, fmt.Errorf("begin device registration: %w", err)
	}
	defer tx.Rollback()
	var userID int64
	err = tx.QueryRowContext(ctx, `SELECT github_user_id FROM sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?`, tokenHash(token), time.Now().UTC()).Scan(&userID)
	if err != nil {
		return Device{}, errors.New("session is invalid or expired")
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO devices(id, github_user_id, name, public_recipient, fingerprint, created_at, last_seen_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT(public_recipient) DO UPDATE SET name = excluded.name, last_seen_at = excluded.last_seen_at WHERE devices.github_user_id = excluded.github_user_id AND devices.revoked_at IS NULL`, id, userID, name, recipient, fingerprint, now, now); err != nil {
		return Device{}, fmt.Errorf("store device: %w", err)
	}
	var device Device
	err = tx.QueryRowContext(ctx, `SELECT id, github_user_id, name, public_recipient, fingerprint, created_at, last_seen_at FROM devices WHERE public_recipient = ? AND revoked_at IS NULL`, recipient).Scan(&device.ID, &device.GitHubUserID, &device.Name, &device.PublicRecipient, &device.Fingerprint, &device.CreatedAt, &device.LastSeenAt)
	if err != nil || device.GitHubUserID != userID {
		return Device{}, errors.New("device recipient belongs to another user or is revoked")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET device_id = ?, last_seen_at = ? WHERE token_hash = ?`, device.ID, now, tokenHash(token)); err != nil {
		return Device{}, fmt.Errorf("associate session device: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Device{}, fmt.Errorf("commit device registration: %w", err)
	}
	return device, nil
}

// RevokeSession invalidates exactly the presented opaque token.
func (s *Store) RevokeSession(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("session token is required")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`, time.Now().UTC(), tokenHash(token))
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// DevicesForUser returns only public, active device identity metadata.
func (s *Store) DevicesForUser(ctx context.Context, githubUserID int64) ([]Device, error) {
	if githubUserID <= 0 {
		return nil, errors.New("GitHub user ID must be positive")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, github_user_id, name, public_recipient, fingerprint, created_at, last_seen_at FROM devices WHERE github_user_id = ? AND revoked_at IS NULL ORDER BY created_at, id`, githubUserID)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var device Device
		if err := rows.Scan(&device.ID, &device.GitHubUserID, &device.Name, &device.PublicRecipient, &device.Fingerprint, &device.CreatedAt, &device.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate devices: %w", err)
	}
	return devices, nil
}

// CreateDeviceAccessRequest records a fresh, code-hash-only request when an
// authenticated device has GitHub access but no wrapped key for this repo.
func (s *Store) CreateDeviceAccessRequest(ctx context.Context, owner, name string, githubUserID int64, deviceID, code string) (DeviceAccessRequest, error) {
	if githubUserID <= 0 || deviceID == "" || len(code) < 16 || !validRepositoryName(owner) || !validRepositoryName(name) {
		return DeviceAccessRequest{}, errors.New("invalid device access request")
	}
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil || !state.Initialized {
		return DeviceAccessRequest{}, errors.New("repository encryption is not initialized")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return DeviceAccessRequest{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceAccessRequest{}, fmt.Errorf("begin device access request: %w", err)
	}
	defer tx.Rollback()
	var request DeviceAccessRequest
	err = tx.QueryRowContext(ctx, `SELECT d.id, d.github_user_id, u.login, d.name, d.public_recipient, d.fingerprint FROM devices d JOIN github_users u ON u.github_user_id = d.github_user_id WHERE d.id = ? AND d.github_user_id = ? AND d.revoked_at IS NULL`, deviceID, githubUserID).Scan(&request.DeviceID, &request.GitHubUserID, &request.GitHubLogin, &request.DeviceName, &request.PublicRecipient, &request.Fingerprint)
	if err != nil {
		return DeviceAccessRequest{}, errors.New("active device is required")
	}
	var hasKey bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM wrapped_repo_keys WHERE repository_id = ? AND epoch = ? AND device_id = ?)`, repositoryID, state.ActiveKeyEpoch, deviceID).Scan(&hasKey); err != nil {
		return DeviceAccessRequest{}, fmt.Errorf("check existing device access: %w", err)
	}
	if hasKey {
		return DeviceAccessRequest{}, errors.New("device already has repository access")
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE device_access_requests SET status = 'revoked', revoked_at = ? WHERE repository_id = ? AND device_id = ? AND status = 'pending'`, now, repositoryID, deviceID); err != nil {
		return DeviceAccessRequest{}, fmt.Errorf("replace pending device access request: %w", err)
	}
	request.ID, err = newUUID()
	if err != nil {
		return DeviceAccessRequest{}, err
	}
	request.CreatedAt = now
	if _, err := tx.ExecContext(ctx, `INSERT INTO device_access_requests(id, repository_id, device_id, code_hash, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)`, request.ID, repositoryID, deviceID, tokenHash(code), now); err != nil {
		return DeviceAccessRequest{}, fmt.Errorf("store device access request: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, githubUserID, deviceID, repositoryID, "device.access_requested", map[string]string{"target_device_id": deviceID}); err != nil {
		return DeviceAccessRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceAccessRequest{}, fmt.Errorf("commit device access request: %w", err)
	}
	return request, nil
}

// PendingDeviceAccessRequests lists approval candidates without exposing
// approval codes or any private key material.
func (s *Store) PendingDeviceAccessRequests(ctx context.Context, owner, name string) ([]DeviceAccessRequest, error) {
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil || !state.Initialized {
		return nil, errors.New("repository encryption is not initialized")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, d.github_user_id, u.login, d.id, d.name, d.public_recipient, d.fingerprint, r.created_at FROM device_access_requests r JOIN devices d ON d.id = r.device_id JOIN github_users u ON u.github_user_id = d.github_user_id WHERE r.repository_id = ? AND r.status = 'pending' AND d.revoked_at IS NULL ORDER BY r.created_at, r.id`, repositoryID)
	if err != nil {
		return nil, fmt.Errorf("list pending device access requests: %w", err)
	}
	defer rows.Close()
	var result []DeviceAccessRequest
	for rows.Next() {
		var request DeviceAccessRequest
		if err := rows.Scan(&request.ID, &request.GitHubUserID, &request.GitHubLogin, &request.DeviceID, &request.DeviceName, &request.PublicRecipient, &request.Fingerprint, &request.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan pending device access request: %w", err)
		}
		result = append(result, request)
	}
	return result, rows.Err()
}

// RepositoryDevices returns public active-device metadata and whether each
// device has a wrapped key for the active epoch.
func (s *Store) RepositoryDevices(ctx context.Context, owner, name string) ([]RepositoryDevice, error) {
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil || !state.Initialized {
		return nil, errors.New("repository encryption is not initialized")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, d.github_user_id, u.login, d.name, d.public_recipient, d.fingerprint, d.created_at, d.last_seen_at, EXISTS(SELECT 1 FROM wrapped_repo_keys wr WHERE wr.repository_id = ? AND wr.epoch = ? AND wr.device_id = d.id) FROM devices d JOIN github_users u ON u.github_user_id = d.github_user_id WHERE d.revoked_at IS NULL ORDER BY d.created_at, d.id`, repositoryID, state.ActiveKeyEpoch)
	if err != nil {
		return nil, fmt.Errorf("list repository devices: %w", err)
	}
	defer rows.Close()
	var result []RepositoryDevice
	for rows.Next() {
		var device RepositoryDevice
		if err := rows.Scan(&device.ID, &device.GitHubUserID, &device.GitHubLogin, &device.Name, &device.PublicRecipient, &device.Fingerprint, &device.CreatedAt, &device.LastSeenAt, &device.HasKey); err != nil {
			return nil, fmt.Errorf("scan repository device: %w", err)
		}
		result = append(result, device)
	}
	return result, rows.Err()
}

// DeviceAccessRequestForCode lets an approver inspect the exact public device
// fingerprint before a local REK is unwrapped and re-wrapped.
func (s *Store) DeviceAccessRequestForCode(ctx context.Context, owner, name, code string) (DeviceAccessRequest, error) {
	if len(code) < 16 {
		return DeviceAccessRequest{}, ErrDeviceAccessNotFound
	}
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil || !state.Initialized {
		return DeviceAccessRequest{}, ErrDeviceAccessNotFound
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return DeviceAccessRequest{}, err
	}
	var request DeviceAccessRequest
	err = s.db.QueryRowContext(ctx, `SELECT r.id, d.github_user_id, u.login, d.id, d.name, d.public_recipient, d.fingerprint, r.created_at FROM device_access_requests r JOIN devices d ON d.id = r.device_id JOIN github_users u ON u.github_user_id = d.github_user_id WHERE r.repository_id = ? AND r.code_hash = ? AND r.status = 'pending' AND d.revoked_at IS NULL`, repositoryID, tokenHash(code)).Scan(&request.ID, &request.GitHubUserID, &request.GitHubLogin, &request.DeviceID, &request.DeviceName, &request.PublicRecipient, &request.Fingerprint, &request.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceAccessRequest{}, ErrDeviceAccessNotFound
	}
	if err != nil {
		return DeviceAccessRequest{}, fmt.Errorf("read device access request: %w", err)
	}
	return request, nil
}

// ApproveDeviceAccess stores a new per-device wrapped REK. It verifies the
// approver already has the active wrapped REK; neither side sends plaintext.
func (s *Store) ApproveDeviceAccess(ctx context.Context, owner, name string, actorUserID int64, actorDeviceID, code string, wrappedREK []byte) error {
	if actorUserID <= 0 || actorDeviceID == "" || len(code) < 16 || len(wrappedREK) == 0 || len(wrappedREK) > 64<<10 {
		return errors.New("invalid device approval")
	}
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil || !state.Initialized {
		return errors.New("repository encryption is not initialized")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin device approval: %w", err)
	}
	defer tx.Rollback()
	var approved bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM wrapped_repo_keys wr JOIN devices d ON d.id = wr.device_id WHERE wr.repository_id = ? AND wr.epoch = ? AND d.id = ? AND d.github_user_id = ? AND d.revoked_at IS NULL)`, repositoryID, state.ActiveKeyEpoch, actorDeviceID, actorUserID).Scan(&approved); err != nil || !approved {
		return errors.New("approving device does not have the repository key")
	}
	var targetDeviceID string
	err = tx.QueryRowContext(ctx, `SELECT r.device_id FROM device_access_requests r JOIN devices d ON d.id = r.device_id WHERE r.repository_id = ? AND r.code_hash = ? AND r.status = 'pending' AND d.revoked_at IS NULL`, repositoryID, tokenHash(code)).Scan(&targetDeviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDeviceAccessNotFound
	}
	if err != nil {
		return fmt.Errorf("read pending device access request: %w", err)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO wrapped_repo_keys(repository_id, epoch, device_id, wrapped_key, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(repository_id, epoch, device_id) DO NOTHING`, repositoryID, state.ActiveKeyEpoch, targetDeviceID, wrappedREK, now); err != nil {
		return fmt.Errorf("store approved wrapped repository key: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE device_access_requests SET status = 'approved', approved_at = ?, approved_by_device_id = ? WHERE repository_id = ? AND code_hash = ? AND status = 'pending'`, now, actorDeviceID, repositoryID, tokenHash(code))
	if err != nil {
		return fmt.Errorf("approve device access request: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrDeviceAccessNotFound
	}
	if err := insertAuditEvent(ctx, tx, actorUserID, actorDeviceID, repositoryID, "device.access_approved", map[string]string{"target_device_id": targetDeviceID}); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeDevice removes every wrapped REK for a device and invalidates its
// sessions. Existing local plaintext cannot be remotely erased.
func (s *Store) RevokeDevice(ctx context.Context, actorUserID int64, actorDeviceID, targetDeviceID string) error {
	if actorUserID <= 0 || actorDeviceID == "" || targetDeviceID == "" {
		return errors.New("invalid device revocation")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin device revocation: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, targetDeviceID)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("device is not active")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL`, now, targetDeviceID); err != nil {
		return fmt.Errorf("revoke device sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM wrapped_repo_keys WHERE device_id = ?`, targetDeviceID); err != nil {
		return fmt.Errorf("delete device wrapped repository keys: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_access_requests SET status = 'revoked', revoked_at = ? WHERE device_id = ? AND status = 'pending'`, now, targetDeviceID); err != nil {
		return fmt.Errorf("revoke pending device access requests: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, actorUserID, actorDeviceID, "", "device.revoked", map[string]string{"target_device_id": targetDeviceID}); err != nil {
		return err
	}
	return tx.Commit()
}

func insertAuditEvent(ctx context.Context, tx *sql.Tx, actorUserID int64, actorDeviceID, repositoryID, eventType string, metadata map[string]string) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	var user any
	if actorUserID > 0 {
		user = strconv.FormatInt(actorUserID, 10)
	}
	var device, repository any
	if actorDeviceID != "" {
		device = actorDeviceID
	}
	if repositoryID != "" {
		repository = repositoryID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(id, actor_user_id, actor_device_id, repository_id, event_type, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, id, user, device, repository, eventType, string(encoded), time.Now().UTC()); err != nil {
		return fmt.Errorf("store audit event: %w", err)
	}
	return nil
}

func tokenHash(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }

func validDeviceText(value string, limit int) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= limit
}

// RepositoryConfigSnapshot is the ciphertext-free, validated repository
// contract that P2 persists. Schema values and secret values have no field in
// this type by design.
type RepositoryConfigSnapshot struct {
	GitHubRepoID  int64
	Owner         string
	Name          string
	DefaultBranch string
	Files         []RepositoryFile
}

// RepositoryFile is one schema-to-local-file mapping from localenv.yaml.
type RepositoryFile struct {
	SchemaPath string
	TargetPath string
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
	cryptoInstanceID, err := newUUID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO instance(id, github_org_id, github_org_login, github_app_id, public_url, display_name, crypto_instance_id, created_at)
		VALUES ('singleton', ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			github_org_id = excluded.github_org_id,
			github_org_login = excluded.github_org_login,
			github_app_id = excluded.github_app_id,
			public_url = excluded.public_url,
			display_name = excluded.display_name,
			crypto_instance_id = CASE WHEN instance.crypto_instance_id = '' THEN excluded.crypto_instance_id ELSE instance.crypto_instance_id END`,
		organizationID, organizationLogin, appID, publicURL, displayName, cryptoInstanceID, time.Now().UTC())
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
		var status string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM webhook_deliveries WHERE github_delivery_id = ?`, event.DeliveryID).Scan(&status); err != nil {
			return false, fmt.Errorf("read GitHub webhook delivery status: %w", err)
		}
		if status == "processed" {
			return true, nil
		}
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

// MarkGitHubWebhookFailed preserves a retryable delivery when downstream PR
// analysis or a GitHub Check/comment upsert fails after receipt.
func (s *Store) MarkGitHubWebhookFailed(ctx context.Context, deliveryID string) error {
	if strings.TrimSpace(deliveryID) == "" {
		return errors.New("GitHub delivery ID must not be empty")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE webhook_deliveries SET processed_at = NULL, status = 'failed' WHERE github_delivery_id = ?`, deliveryID)
	if err != nil {
		return fmt.Errorf("mark GitHub webhook delivery failed: %w", err)
	}
	return nil
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

// SaveRepositoryConfigSnapshot atomically replaces an activated repository's
// file contract. It stores paths only; dotenv contents are never accepted.
func (s *Store) SaveRepositoryConfigSnapshot(ctx context.Context, snapshot RepositoryConfigSnapshot) error {
	if err := validateRepositoryConfigSnapshot(snapshot); err != nil {
		return err
	}
	repositoryID := fmt.Sprintf("github:%d", snapshot.GitHubRepoID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin repository configuration snapshot: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO repositories(id, github_repo_id, owner, name, default_branch, active_key_epoch, created_at)
		VALUES (?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(github_repo_id) DO UPDATE SET
			owner = excluded.owner,
			name = excluded.name,
			default_branch = excluded.default_branch`,
		repositoryID, snapshot.GitHubRepoID, snapshot.Owner, snapshot.Name, snapshot.DefaultBranch, time.Now().UTC()); err != nil {
		return fmt.Errorf("store repository configuration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM repo_files WHERE repository_id = ?`, repositoryID); err != nil {
		return fmt.Errorf("clear repository file configuration: %w", err)
	}
	for _, file := range snapshot.Files {
		if _, err := tx.ExecContext(ctx, `INSERT INTO repo_files(id, repository_id, schema_path, target_path) VALUES (?, ?, ?, ?)`, pranalysis.FileID(snapshot.GitHubRepoID, file.SchemaPath, file.TargetPath), repositoryID, file.SchemaPath, file.TargetPath); err != nil {
			return fmt.Errorf("store repository file configuration: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit repository configuration snapshot: %w", err)
	}
	return nil
}

// PullRequestReadiness is the ciphertext-free PR state used to publish a
// readiness check. It intentionally contains key names only.
type PullRequestReadiness struct {
	PullRequest  githubapp.PullRequest
	Requirements []pranalysis.Requirement
	CheckRunID   int64
	CommentID    int64
}

// SavePullRequestRequirements atomically replaces a PR's requirements using a
// completed base/head analysis. Existing Check Run and comment identifiers are
// retained so GitHub artifacts are updated instead of duplicated.
func (s *Store) SavePullRequestRequirements(ctx context.Context, pull githubapp.PullRequest, requirements []pranalysis.Requirement) (PullRequestReadiness, error) {
	repositoryID, err := s.repositoryID(ctx, pull.Repository.GitHubRepoID)
	if err != nil {
		return PullRequestReadiness{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PullRequestReadiness{}, fmt.Errorf("begin PR requirements: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pull_requests(repository_id, pr_number, head_sha, base_sha, author_github_user_id, state, merged_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(repository_id, pr_number) DO UPDATE SET
			head_sha = excluded.head_sha,
			base_sha = excluded.base_sha,
			author_github_user_id = excluded.author_github_user_id,
			state = excluded.state,
			merged_at = excluded.merged_at,
			updated_at = excluded.updated_at`, repositoryID, pull.Number, pull.HeadSHA, pull.BaseSHA, pull.AuthorID, pull.State, pull.MergedAt, time.Now().UTC()); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("store pull request: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pr_requirements WHERE repository_id = ? AND pr_number = ?`, repositoryID, pull.Number); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("clear PR requirements: %w", err)
	}
	for index := range requirements {
		requirement := requirements[index]
		if !validRequirement(requirement) {
			return PullRequestReadiness{}, errors.New("invalid PR requirement")
		}
		if requirement.State == pranalysis.StateMissing {
			var exists bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM secret_versions WHERE repository_id = ? AND file_id = ? AND key_name = ? AND scope = 'pull_request' AND scope_id = ? AND archived_at IS NULL)`, repositoryID, requirement.FileID, requirement.KeyName, strconv.Itoa(pull.Number)).Scan(&exists); err != nil {
				return PullRequestReadiness{}, fmt.Errorf("check PR secret resolution: %w", err)
			}
			if exists {
				requirement.State = pranalysis.StateReady
				requirements[index] = requirement
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO pr_requirements(repository_id, pr_number, file_id, key_name, requirement_state) VALUES (?, ?, ?, ?, ?)`, repositoryID, pull.Number, requirement.FileID, requirement.KeyName, requirement.State); err != nil {
			return PullRequestReadiness{}, fmt.Errorf("store PR requirement: %w", err)
		}
	}
	var result PullRequestReadiness
	result.PullRequest = pull
	result.Requirements = append([]pranalysis.Requirement(nil), requirements...)
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(github_check_run_id, 0), COALESCE(github_comment_id, 0) FROM pull_requests WHERE repository_id = ? AND pr_number = ?`, repositoryID, pull.Number).Scan(&result.CheckRunID, &result.CommentID); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("read PR publication identifiers: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("commit PR requirements: %w", err)
	}
	return result, nil
}

// ClosePullRequest atomically promotes the current pending ciphertext for new
// baseline keys on merge, or archives pending ciphertext when a PR closes
// unmerged. Promotion preserves the original PR AAD identity: ciphertext is
// never moved to a different authenticated scope without client re-encryption.
func (s *Store) ClosePullRequest(ctx context.Context, pull githubapp.PullRequest) error {
	repositoryID, err := s.repositoryID(ctx, pull.Repository.GitHubRepoID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin close pull request: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pull_requests(repository_id, pr_number, head_sha, base_sha, author_github_user_id, state, merged_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(repository_id, pr_number) DO UPDATE SET
			head_sha = excluded.head_sha,
			base_sha = excluded.base_sha,
			author_github_user_id = excluded.author_github_user_id,
			state = excluded.state,
			merged_at = excluded.merged_at,
			updated_at = excluded.updated_at`, repositoryID, pull.Number, pull.HeadSHA, pull.BaseSHA, pull.AuthorID, pull.State, pull.MergedAt, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("close pull request: %w", err)
	}
	now := time.Now().UTC()
	if pull.State == "merged" {
		rows, err := tx.QueryContext(ctx, `SELECT file_id, key_name, MAX(version) FROM secret_versions WHERE repository_id = ? AND scope = 'pull_request' AND scope_id = ? AND archived_at IS NULL GROUP BY file_id, key_name`, repositoryID, strconv.Itoa(pull.Number))
		if err != nil {
			return fmt.Errorf("list pending secrets for promotion: %w", err)
		}
		var pending []struct {
			fileID, key string
			version     int64
		}
		for rows.Next() {
			var item struct {
				fileID, key string
				version     int64
			}
			if err := rows.Scan(&item.fileID, &item.key, &item.version); err != nil {
				rows.Close()
				return fmt.Errorf("scan pending secret: %w", err)
			}
			pending = append(pending, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate pending secrets: %w", err)
		}
		rows.Close()
		for _, item := range pending {
			var baselineExists bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM secret_versions WHERE repository_id = ? AND file_id = ? AND key_name = ? AND scope = 'baseline' AND archived_at IS NULL)`, repositoryID, item.fileID, item.key).Scan(&baselineExists); err != nil {
				return fmt.Errorf("check baseline secret: %w", err)
			}
			if baselineExists {
				if _, err := tx.ExecContext(ctx, `UPDATE secret_versions SET archived_at = ? WHERE repository_id = ? AND file_id = ? AND key_name = ? AND scope = 'pull_request' AND scope_id = ? AND archived_at IS NULL`, now, repositoryID, item.fileID, item.key, strconv.Itoa(pull.Number)); err != nil {
					return fmt.Errorf("archive conflicting pending secret: %w", err)
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE secret_versions SET promoted_at = ? WHERE repository_id = ? AND file_id = ? AND key_name = ? AND scope = 'pull_request' AND scope_id = ? AND version = ? AND archived_at IS NULL`, now, repositoryID, item.fileID, item.key, strconv.Itoa(pull.Number), item.version); err != nil {
				return fmt.Errorf("promote pending secret: %w", err)
			}
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE secret_versions SET archived_at = ? WHERE repository_id = ? AND scope = 'pull_request' AND scope_id = ? AND archived_at IS NULL`, now, repositoryID, strconv.Itoa(pull.Number)); err != nil {
			return fmt.Errorf("archive pending secrets: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO repo_revisions(repository_id, revision, updated_at) VALUES (?, 1, ?) ON CONFLICT(repository_id) DO UPDATE SET revision = repo_revisions.revision + 1, updated_at = excluded.updated_at`, repositoryID, now); err != nil {
		return fmt.Errorf("advance repository revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit close pull request: %w", err)
	}
	return nil
}

// SaveReadinessPublication records the remote Check Run/comment identities
// only after GitHub accepts the upsert response.
func (s *Store) SaveReadinessPublication(ctx context.Context, githubRepositoryID int64, number int, checkRunID, commentID int64) error {
	repositoryID, err := s.repositoryID(ctx, githubRepositoryID)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE pull_requests SET github_check_run_id = CASE WHEN ? > 0 THEN ? ELSE github_check_run_id END, github_comment_id = CASE WHEN ? > 0 THEN ? ELSE github_comment_id END, updated_at = ? WHERE repository_id = ? AND pr_number = ?`, checkRunID, checkRunID, commentID, commentID, time.Now().UTC(), repositoryID, number)
	if err != nil {
		return fmt.Errorf("save PR publication identifiers: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return errors.New("pull request not found while saving publication identifiers")
	}
	return nil
}

// PullRequestRequirements returns the last persisted public readiness states.
// It exists for future authenticated API/UI handlers and cannot expose values.
func (s *Store) PullRequestRequirements(ctx context.Context, githubRepositoryID int64, number int) ([]pranalysis.Requirement, error) {
	repositoryID, err := s.repositoryID(ctx, githubRepositoryID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT file_id, key_name, requirement_state FROM pr_requirements WHERE repository_id = ? AND pr_number = ? ORDER BY key_name, file_id`, repositoryID, number)
	if err != nil {
		return nil, fmt.Errorf("list PR requirements: %w", err)
	}
	defer rows.Close()
	var requirements []pranalysis.Requirement
	for rows.Next() {
		var requirement pranalysis.Requirement
		if err := rows.Scan(&requirement.FileID, &requirement.KeyName, &requirement.State); err != nil {
			return nil, fmt.Errorf("scan PR requirement: %w", err)
		}
		requirements = append(requirements, requirement)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate PR requirements: %w", err)
	}
	return requirements, nil
}

// PullRequirementsForDevice returns public PR requirements plus only the
// requesting active device's wrapped REK. It is the P6 read side needed for
// local encryption; it has no plaintext or unwrapped key material.
func (s *Store) PullRequirementsForDevice(ctx context.Context, owner, name string, number int, githubUserID int64, deviceID string) (PullRequirementsResponse, error) {
	if number <= 0 || githubUserID <= 0 || deviceID == "" {
		return PullRequirementsResponse{}, errors.New("invalid pull requirements request")
	}
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil {
		return PullRequirementsResponse{}, err
	}
	if !state.Initialized {
		return PullRequirementsResponse{}, errors.New("repository encryption is not initialized")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return PullRequirementsResponse{}, err
	}
	var wrapped []byte
	err = s.db.QueryRowContext(ctx, `SELECT wr.wrapped_key FROM wrapped_repo_keys wr JOIN devices d ON d.id = wr.device_id WHERE wr.repository_id = ? AND wr.epoch = ? AND wr.device_id = ? AND d.github_user_id = ? AND d.revoked_at IS NULL`, repositoryID, state.ActiveKeyEpoch, deviceID, githubUserID).Scan(&wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return PullRequirementsResponse{}, errors.New("active device does not have the repository key")
	}
	if err != nil {
		return PullRequirementsResponse{}, fmt.Errorf("read wrapped repository key: %w", err)
	}
	var pull PullRequirementsResponse
	pull.Repository = state
	pull.WrappedREK = append([]byte(nil), wrapped...)
	pull.PullRequest.Number = number
	pull.PullRequest.Repository = githubapp.Repository{GitHubRepoID: state.GitHubRepoID, Owner: state.Owner, Name: state.Name}
	err = s.db.QueryRowContext(ctx, `SELECT head_sha, base_sha, author_github_user_id, state, merged_at FROM pull_requests WHERE repository_id = ? AND pr_number = ?`, repositoryID, number).Scan(&pull.PullRequest.HeadSHA, &pull.PullRequest.BaseSHA, &pull.PullRequest.AuthorID, &pull.PullRequest.State, &pull.PullRequest.MergedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return PullRequirementsResponse{}, errors.New("pull request requirements not found")
	}
	if err != nil {
		return PullRequirementsResponse{}, fmt.Errorf("read pull request: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT q.file_id, rf.target_path, q.key_name, q.requirement_state, COALESCE((SELECT MAX(version) FROM secret_versions sv WHERE sv.repository_id = q.repository_id AND sv.file_id = q.file_id AND sv.key_name = q.key_name AND sv.scope = 'pull_request' AND sv.scope_id = ? AND sv.archived_at IS NULL), 0) FROM pr_requirements q JOIN repo_files rf ON rf.id = q.file_id AND rf.repository_id = q.repository_id WHERE q.repository_id = ? AND q.pr_number = ? AND q.requirement_state != 'removed' ORDER BY q.key_name, q.file_id`, strconv.Itoa(number), repositoryID, number)
	if err != nil {
		return PullRequirementsResponse{}, fmt.Errorf("list pull requirements: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var requirement PullRequirement
		if err := rows.Scan(&requirement.FileID, &requirement.FilePath, &requirement.KeyName, &requirement.State, &requirement.CurrentVersion); err != nil {
			return PullRequirementsResponse{}, fmt.Errorf("scan pull requirement: %w", err)
		}
		pull.Requirements = append(pull.Requirements, requirement)
	}
	if err := rows.Err(); err != nil {
		return PullRequirementsResponse{}, fmt.Errorf("iterate pull requirements: %w", err)
	}
	return pull, nil
}

// RepositorySnapshotForDevice returns ciphertext-only baseline state and the
// caller's wrapped REK. Promoted PR records retain their PR scope because that
// is the scope authenticated by their original AEAD envelope.
func (s *Store) RepositorySnapshotForDevice(ctx context.Context, owner, name string, githubUserID int64, deviceID string) (RepositorySnapshot, error) {
	if githubUserID <= 0 || deviceID == "" {
		return RepositorySnapshot{}, errors.New("invalid repository snapshot request")
	}
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	if !state.Initialized {
		return RepositorySnapshot{}, errors.New("repository encryption is not initialized")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	var wrapped []byte
	err = s.db.QueryRowContext(ctx, `SELECT wr.wrapped_key FROM wrapped_repo_keys wr JOIN devices d ON d.id = wr.device_id WHERE wr.repository_id = ? AND wr.epoch = ? AND wr.device_id = ? AND d.github_user_id = ? AND d.revoked_at IS NULL`, repositoryID, state.ActiveKeyEpoch, deviceID, githubUserID).Scan(&wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return RepositorySnapshot{}, errors.New("active device does not have the repository key")
	}
	if err != nil {
		return RepositorySnapshot{}, fmt.Errorf("read wrapped repository key: %w", err)
	}
	result := RepositorySnapshot{Repository: state, WrappedREK: append([]byte(nil), wrapped...)}
	rows, err := s.db.QueryContext(ctx, `SELECT sv.file_id, rf.target_path, sv.key_name, sv.scope, sv.scope_id, sv.algorithm, sv.key_epoch, sv.nonce, sv.ciphertext, sv.version FROM secret_versions sv JOIN repo_files rf ON rf.id = sv.file_id AND rf.repository_id = sv.repository_id WHERE sv.repository_id = ? AND sv.archived_at IS NULL AND (sv.scope = 'baseline' OR sv.promoted_at IS NOT NULL) AND sv.version = (SELECT MAX(current.version) FROM secret_versions current WHERE current.repository_id = sv.repository_id AND current.file_id = sv.file_id AND current.key_name = sv.key_name AND current.scope = sv.scope AND current.scope_id = sv.scope_id AND current.archived_at IS NULL) ORDER BY sv.file_id, sv.key_name, sv.scope, sv.scope_id`, repositoryID)
	if err != nil {
		return RepositorySnapshot{}, fmt.Errorf("list encrypted repository snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var secret SecretSnapshot
		if err := rows.Scan(&secret.FileID, &secret.FilePath, &secret.KeyName, &secret.Scope, &secret.ScopeID, &secret.Envelope.Algorithm, &secret.Envelope.KeyEpoch, &secret.Envelope.Nonce, &secret.Envelope.Ciphertext, &secret.Envelope.Version); err != nil {
			return RepositorySnapshot{}, fmt.Errorf("scan encrypted repository snapshot: %w", err)
		}
		result.Secrets = append(result.Secrets, secret)
	}
	if err := rows.Err(); err != nil {
		return RepositorySnapshot{}, fmt.Errorf("iterate encrypted repository snapshot: %w", err)
	}
	return result, nil
}

// PullRequestSnapshotForDevice returns the baseline snapshot plus the current
// pending values for one open pull request. The caller still receives only
// ciphertext and its own age-wrapped repository key.
func (s *Store) PullRequestSnapshotForDevice(ctx context.Context, owner, name string, number int, githubUserID int64, deviceID string) (RepositorySnapshot, error) {
	if number <= 0 {
		return RepositorySnapshot{}, errors.New("pull request number must be positive")
	}
	result, err := s.RepositorySnapshotForDevice(ctx, owner, name, githubUserID, deviceID)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	repositoryID, err := s.repositoryID(ctx, result.Repository.GitHubRepoID)
	if err != nil {
		return RepositorySnapshot{}, err
	}
	var state string
	if err := s.db.QueryRowContext(ctx, `SELECT state FROM pull_requests WHERE repository_id = ? AND pr_number = ?`, repositoryID, number).Scan(&state); err != nil || state != "open" {
		return RepositorySnapshot{}, errors.New("pull request is not open")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sv.file_id, rf.target_path, sv.key_name, sv.scope, sv.scope_id, sv.algorithm, sv.key_epoch, sv.nonce, sv.ciphertext, sv.version FROM secret_versions sv JOIN repo_files rf ON rf.id = sv.file_id AND rf.repository_id = sv.repository_id WHERE sv.repository_id = ? AND sv.scope = 'pull_request' AND sv.scope_id = ? AND sv.archived_at IS NULL AND sv.promoted_at IS NULL AND sv.version = (SELECT MAX(current.version) FROM secret_versions current WHERE current.repository_id = sv.repository_id AND current.file_id = sv.file_id AND current.key_name = sv.key_name AND current.scope = 'pull_request' AND current.scope_id = ? AND current.archived_at IS NULL) ORDER BY sv.file_id, sv.key_name`, repositoryID, strconv.Itoa(number), strconv.Itoa(number))
	if err != nil {
		return RepositorySnapshot{}, fmt.Errorf("list encrypted pull request snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var secret SecretSnapshot
		if err := rows.Scan(&secret.FileID, &secret.FilePath, &secret.KeyName, &secret.Scope, &secret.ScopeID, &secret.Envelope.Algorithm, &secret.Envelope.KeyEpoch, &secret.Envelope.Nonce, &secret.Envelope.Ciphertext, &secret.Envelope.Version); err != nil {
			return RepositorySnapshot{}, fmt.Errorf("scan encrypted pull request snapshot: %w", err)
		}
		result.Secrets = append(result.Secrets, secret)
	}
	if err := rows.Err(); err != nil {
		return RepositorySnapshot{}, fmt.Errorf("iterate encrypted pull request snapshot: %w", err)
	}
	return result, nil
}

// UpdateBaselineSecret appends a locally encrypted baseline value. It is used
// by `localenv import`; the caller must already own a wrapped active REK.
func (s *Store) UpdateBaselineSecret(ctx context.Context, owner, name string, githubUserID int64, deviceID, fileID, keyName string, expectedVersion int64, envelope SecretEnvelope) error {
	if expectedVersion < 0 || !validSecretIdentity(fileID, keyName) || !validSecretEnvelope(envelope) {
		return errors.New("invalid encrypted secret update")
	}
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil {
		return err
	}
	if !state.Initialized || envelope.KeyEpoch != state.ActiveKeyEpoch {
		return errors.New("encrypted secret uses an inactive repository key epoch")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin baseline secret update: %w", err)
	}
	defer tx.Rollback()
	var allowed bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM repo_files rf JOIN devices d JOIN wrapped_repo_keys wr ON wr.device_id = d.id WHERE rf.repository_id = ? AND rf.id = ? AND d.id = ? AND d.github_user_id = ? AND d.revoked_at IS NULL AND wr.repository_id = ? AND wr.epoch = ?)`, repositoryID, fileID, deviceID, githubUserID, repositoryID, state.ActiveKeyEpoch).Scan(&allowed)
	if err != nil || !allowed {
		return errors.New("active device does not have repository access")
	}
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE repository_id = ? AND file_id = ? AND key_name = ? AND scope = 'baseline' AND scope_id = '' AND archived_at IS NULL`, repositoryID, fileID, keyName).Scan(&current); err != nil {
		return fmt.Errorf("read current baseline version: %w", err)
	}
	if current != expectedVersion || envelope.Version != current+1 {
		return ErrSecretVersionConflict
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO secret_versions(id, repository_id, file_id, key_name, scope, scope_id, version, key_epoch, algorithm, nonce, ciphertext, created_by_user_id, created_at, archived_at, promoted_at) VALUES (?, ?, ?, ?, 'baseline', '', ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`, id, repositoryID, fileID, keyName, envelope.Version, envelope.KeyEpoch, envelope.Algorithm, envelope.Nonce, envelope.Ciphertext, strconv.FormatInt(githubUserID, 10), now); err != nil {
		return fmt.Errorf("store encrypted baseline secret: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO repo_revisions(repository_id, revision, updated_at) VALUES (?, 1, ?) ON CONFLICT(repository_id) DO UPDATE SET revision = repo_revisions.revision + 1, updated_at = excluded.updated_at`, repositoryID, now); err != nil {
		return fmt.Errorf("advance repository revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit encrypted baseline secret: %w", err)
	}
	return nil
}

// UpdatePullRequestSecret appends an immutable ciphertext version and marks
// its public readiness requirement ready. Optimistic version checking prevents
// one concurrent editor from silently replacing another's value.
func (s *Store) UpdatePullRequestSecret(ctx context.Context, owner, name string, number int, githubUserID int64, deviceID, fileID, keyName string, expectedVersion int64, envelope SecretEnvelope) (PullRequestReadiness, error) {
	if number <= 0 || expectedVersion < 0 || !validSecretIdentity(fileID, keyName) || !validSecretEnvelope(envelope) {
		return PullRequestReadiness{}, errors.New("invalid encrypted secret update")
	}
	state, err := s.RepositoryCryptoState(ctx, owner, name)
	if err != nil {
		return PullRequestReadiness{}, err
	}
	if !state.Initialized || envelope.KeyEpoch != state.ActiveKeyEpoch {
		return PullRequestReadiness{}, errors.New("encrypted secret uses an inactive repository key epoch")
	}
	repositoryID, err := s.repositoryID(ctx, state.GitHubRepoID)
	if err != nil {
		return PullRequestReadiness{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PullRequestReadiness{}, fmt.Errorf("begin encrypted secret update: %w", err)
	}
	defer tx.Rollback()
	var activeDevice string
	err = tx.QueryRowContext(ctx, `SELECT d.id FROM devices d JOIN wrapped_repo_keys wr ON wr.device_id = d.id WHERE d.id = ? AND d.github_user_id = ? AND d.revoked_at IS NULL AND wr.repository_id = ? AND wr.epoch = ?`, deviceID, githubUserID, repositoryID, state.ActiveKeyEpoch).Scan(&activeDevice)
	if err != nil || activeDevice != deviceID {
		return PullRequestReadiness{}, errors.New("active device does not have the repository key")
	}
	var pull githubapp.PullRequest
	pull.Number = number
	pull.Repository = githubapp.Repository{GitHubRepoID: state.GitHubRepoID, Owner: state.Owner, Name: state.Name}
	err = tx.QueryRowContext(ctx, `SELECT head_sha, base_sha, author_github_user_id, state, merged_at, COALESCE(github_check_run_id, 0), COALESCE(github_comment_id, 0) FROM pull_requests WHERE repository_id = ? AND pr_number = ?`, repositoryID, number).Scan(&pull.HeadSHA, &pull.BaseSHA, &pull.AuthorID, &pull.State, &pull.MergedAt, new(int64), new(int64))
	if errors.Is(err, sql.ErrNoRows) {
		return PullRequestReadiness{}, errors.New("pull request requirements not found")
	}
	if err != nil {
		return PullRequestReadiness{}, fmt.Errorf("read pull request for update: %w", err)
	}
	if pull.State != "open" {
		return PullRequestReadiness{}, ErrPullRequestNotOpen
	}
	var requirementState string
	err = tx.QueryRowContext(ctx, `SELECT requirement_state FROM pr_requirements WHERE repository_id = ? AND pr_number = ? AND file_id = ? AND key_name = ?`, repositoryID, number, fileID, keyName).Scan(&requirementState)
	if err != nil || requirementState == pranalysis.StateRemoved {
		return PullRequestReadiness{}, errors.New("secret is not required by this pull request")
	}
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE repository_id = ? AND file_id = ? AND key_name = ? AND scope = 'pull_request' AND scope_id = ? AND archived_at IS NULL`, repositoryID, fileID, keyName, strconv.Itoa(number)).Scan(&current); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("read current encrypted secret version: %w", err)
	}
	if current != expectedVersion || envelope.Version != current+1 {
		return PullRequestReadiness{}, ErrSecretVersionConflict
	}
	id, err := newUUID()
	if err != nil {
		return PullRequestReadiness{}, err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO secret_versions(id, repository_id, file_id, key_name, scope, scope_id, version, key_epoch, algorithm, nonce, ciphertext, created_by_user_id, created_at, archived_at, promoted_at) VALUES (?, ?, ?, ?, 'pull_request', ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`, id, repositoryID, fileID, keyName, strconv.Itoa(number), envelope.Version, envelope.KeyEpoch, envelope.Algorithm, envelope.Nonce, envelope.Ciphertext, strconv.FormatInt(githubUserID, 10), now); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("store encrypted secret: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pr_requirements SET requirement_state = 'ready' WHERE repository_id = ? AND pr_number = ? AND file_id = ? AND key_name = ?`, repositoryID, number, fileID, keyName); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("mark pull requirement ready: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO repo_revisions(repository_id, revision, updated_at) VALUES (?, 1, ?) ON CONFLICT(repository_id) DO UPDATE SET revision = repo_revisions.revision + 1, updated_at = excluded.updated_at`, repositoryID, now); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("advance repository revision: %w", err)
	}
	result := PullRequestReadiness{PullRequest: pull}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(github_check_run_id, 0), COALESCE(github_comment_id, 0) FROM pull_requests WHERE repository_id = ? AND pr_number = ?`, repositoryID, number).Scan(&result.CheckRunID, &result.CommentID); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("read readiness publication: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT file_id, key_name, requirement_state FROM pr_requirements WHERE repository_id = ? AND pr_number = ? ORDER BY key_name, file_id`, repositoryID, number)
	if err != nil {
		return PullRequestReadiness{}, fmt.Errorf("list updated requirements: %w", err)
	}
	for rows.Next() {
		var item pranalysis.Requirement
		if err := rows.Scan(&item.FileID, &item.KeyName, &item.State); err != nil {
			rows.Close()
			return PullRequestReadiness{}, fmt.Errorf("scan updated requirement: %w", err)
		}
		result.Requirements = append(result.Requirements, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return PullRequestReadiness{}, fmt.Errorf("iterate updated requirements: %w", err)
	}
	rows.Close()
	if err := tx.Commit(); err != nil {
		return PullRequestReadiness{}, fmt.Errorf("commit encrypted secret update: %w", err)
	}
	return result, nil
}

func validSecretIdentity(fileID, keyName string) bool {
	if fileID == "" || len(fileID) > 128 || keyName == "" || len(keyName) > 256 {
		return false
	}
	for index, runeValue := range keyName {
		if !(runeValue == '_' || runeValue >= 'A' && runeValue <= 'Z' || index > 0 && runeValue >= '0' && runeValue <= '9') {
			return false
		}
	}
	return true
}

func validSecretEnvelope(envelope SecretEnvelope) bool {
	return envelope.Algorithm == "XCHACHA20-POLY1305" && envelope.KeyEpoch > 0 && envelope.Version > 0 && len(envelope.Nonce) == 24 && len(envelope.Ciphertext) >= 16 && len(envelope.Ciphertext) <= 1<<20
}

func (s *Store) repositoryID(ctx context.Context, githubRepositoryID int64) (string, error) {
	if githubRepositoryID <= 0 {
		return "", ErrRepositoryNotManaged
	}
	var repositoryID string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM repositories WHERE github_repo_id = ?`, githubRepositoryID).Scan(&repositoryID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrRepositoryNotManaged
	}
	if err != nil {
		return "", fmt.Errorf("find managed repository: %w", err)
	}
	return repositoryID, nil
}

// RepositoryCryptoState returns only bootstrap metadata for a repository
// covered by the current GitHub App installation. Callers must still perform
// a current GitHub permission check before returning it to a user.
func (s *Store) RepositoryCryptoState(ctx context.Context, owner, name string) (RepositoryCryptoState, error) {
	if !validRepositoryName(owner) || !validRepositoryName(name) {
		return RepositoryCryptoState{}, ErrRepositoryNotManaged
	}
	var state RepositoryCryptoState
	err := s.db.QueryRowContext(ctx, `
		SELECT i.crypto_instance_id, r.github_repo_id, r.owner, r.name,
		       r.active_key_epoch, gir.github_installation_id
		FROM repositories r
		JOIN instance i ON i.id = 'singleton'
		JOIN github_installation_repositories gir
		  ON gir.github_repo_id = r.github_repo_id AND gir.active = 1
		WHERE r.owner = ? AND r.name = ?`, owner, name).Scan(
		&state.InstanceID, &state.GitHubRepoID, &state.Owner, &state.Name,
		&state.ActiveKeyEpoch, &state.InstallationID)
	if errors.Is(err, sql.ErrNoRows) {
		return RepositoryCryptoState{}, ErrRepositoryNotManaged
	}
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("read repository crypto state: %w", err)
	}
	if state.InstanceID == "" {
		instanceID, err := s.ensureCryptoInstanceID(ctx)
		if err != nil {
			return RepositoryCryptoState{}, err
		}
		state.InstanceID = instanceID
	}
	state.Initialized = state.ActiveKeyEpoch > 0
	return state, nil
}

// InitializeRepositoryCrypto atomically creates epoch 1 and persists one
// device-wrapped REK. The server receives only the opaque age ciphertext.
func (s *Store) InitializeRepositoryCrypto(ctx context.Context, owner, name string, githubUserID int64, deviceID string, wrappedREK []byte) (RepositoryCryptoState, error) {
	if !validRepositoryName(owner) || !validRepositoryName(name) || githubUserID <= 0 || deviceID == "" || len(wrappedREK) == 0 || len(wrappedREK) > 64<<10 {
		return RepositoryCryptoState{}, errors.New("invalid repository encryption bootstrap")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("begin repository encryption bootstrap: %w", err)
	}
	defer tx.Rollback()
	var repositoryID string
	var state RepositoryCryptoState
	err = tx.QueryRowContext(ctx, `
		SELECT r.id, i.crypto_instance_id, r.github_repo_id, r.owner, r.name,
		       r.active_key_epoch, gir.github_installation_id
		FROM repositories r
		JOIN instance i ON i.id = 'singleton'
		JOIN github_installation_repositories gir
		  ON gir.github_repo_id = r.github_repo_id AND gir.active = 1
		WHERE r.owner = ? AND r.name = ?`, owner, name).Scan(
		&repositoryID, &state.InstanceID, &state.GitHubRepoID, &state.Owner,
		&state.Name, &state.ActiveKeyEpoch, &state.InstallationID)
	if errors.Is(err, sql.ErrNoRows) {
		return RepositoryCryptoState{}, ErrRepositoryNotManaged
	}
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("read repository encryption bootstrap: %w", err)
	}
	if state.ActiveKeyEpoch != 0 {
		return RepositoryCryptoState{}, ErrRepositoryAlreadyInitialized
	}
	var activeDevice string
	err = tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE id = ? AND github_user_id = ? AND revoked_at IS NULL`, deviceID, githubUserID).Scan(&activeDevice)
	if err != nil || activeDevice != deviceID {
		return RepositoryCryptoState{}, errors.New("active device is required for repository encryption bootstrap")
	}
	if state.InstanceID == "" {
		state.InstanceID, err = newUUID()
		if err != nil {
			return RepositoryCryptoState{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE instance SET crypto_instance_id = ? WHERE id = 'singleton' AND crypto_instance_id = ''`, state.InstanceID); err != nil {
			return RepositoryCryptoState{}, fmt.Errorf("set instance cryptographic identity: %w", err)
		}
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO repo_key_epochs(repository_id, epoch, status, created_at, retired_at) VALUES (?, 1, 'active', ?, NULL)`, repositoryID, now); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("store repository key epoch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO wrapped_repo_keys(repository_id, epoch, device_id, wrapped_key, created_at) VALUES (?, 1, ?, ?, ?)`, repositoryID, deviceID, wrappedREK, now); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("store wrapped repository key: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE repositories SET active_key_epoch = 1 WHERE id = ? AND active_key_epoch = 0`, repositoryID)
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("activate repository key epoch: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return RepositoryCryptoState{}, ErrRepositoryAlreadyInitialized
	}
	if err := tx.Commit(); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("commit repository encryption bootstrap: %w", err)
	}
	state.ActiveKeyEpoch = 1
	state.Initialized = true
	return state, nil
}

// RotateRepositoryKey atomically activates a client-created epoch and its
// complete re-encrypted current snapshot. It verifies every active key holder
// receives exactly one new wrapped REK before retiring the old epoch.
func (s *Store) RotateRepositoryKey(ctx context.Context, owner, name string, githubUserID int64, deviceID string, rotation KeyRotation) (RepositoryCryptoState, error) {
	if githubUserID <= 0 || deviceID == "" || rotation.ExpectedEpoch <= 0 || len(rotation.WrappedKeys) == 0 {
		return RepositoryCryptoState{}, errors.New("invalid repository key rotation")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("begin repository key rotation: %w", err)
	}
	defer tx.Rollback()

	var repositoryID string
	var state RepositoryCryptoState
	err = tx.QueryRowContext(ctx, `
		SELECT r.id, i.crypto_instance_id, r.github_repo_id, r.owner, r.name,
		       r.active_key_epoch, gir.github_installation_id
		FROM repositories r
		JOIN instance i ON i.id = 'singleton'
		JOIN github_installation_repositories gir
		  ON gir.github_repo_id = r.github_repo_id AND gir.active = 1
		WHERE r.owner = ? AND r.name = ?`, owner, name).Scan(
		&repositoryID, &state.InstanceID, &state.GitHubRepoID, &state.Owner,
		&state.Name, &state.ActiveKeyEpoch, &state.InstallationID)
	if errors.Is(err, sql.ErrNoRows) {
		return RepositoryCryptoState{}, ErrRepositoryNotManaged
	}
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("read repository key rotation state: %w", err)
	}
	if state.ActiveKeyEpoch != rotation.ExpectedEpoch {
		return RepositoryCryptoState{}, ErrKeyRotationConflict
	}
	var authorized bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM wrapped_repo_keys wr JOIN devices d ON d.id = wr.device_id WHERE wr.repository_id = ? AND wr.epoch = ? AND d.id = ? AND d.github_user_id = ? AND d.revoked_at IS NULL)`, repositoryID, state.ActiveKeyEpoch, deviceID, githubUserID).Scan(&authorized)
	if err != nil || !authorized {
		return RepositoryCryptoState{}, errors.New("active device does not have the repository key")
	}

	activeDevices := make(map[string]struct{})
	rows, err := tx.QueryContext(ctx, `SELECT d.id FROM wrapped_repo_keys wr JOIN devices d ON d.id = wr.device_id WHERE wr.repository_id = ? AND wr.epoch = ? AND d.revoked_at IS NULL ORDER BY d.id`, repositoryID, state.ActiveKeyEpoch)
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("list active repository devices: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return RepositoryCryptoState{}, fmt.Errorf("scan active repository device: %w", err)
		}
		activeDevices[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RepositoryCryptoState{}, fmt.Errorf("iterate active repository devices: %w", err)
	}
	rows.Close()
	providedDevices := make(map[string]struct{}, len(rotation.WrappedKeys))
	for _, key := range rotation.WrappedKeys {
		if key.DeviceID == "" || len(key.WrappedREK) == 0 || len(key.WrappedREK) > 64<<10 {
			return RepositoryCryptoState{}, errors.New("invalid rotated wrapped repository key")
		}
		if _, duplicate := providedDevices[key.DeviceID]; duplicate {
			return RepositoryCryptoState{}, errors.New("duplicate rotated wrapped repository key")
		}
		providedDevices[key.DeviceID] = struct{}{}
	}
	if len(providedDevices) != len(activeDevices) {
		return RepositoryCryptoState{}, ErrKeyRotationConflict
	}
	for id := range activeDevices {
		if _, found := providedDevices[id]; !found {
			return RepositoryCryptoState{}, ErrKeyRotationConflict
		}
	}

	type currentSecret struct {
		fileID, filePath, keyName, scope, scopeID string
		version                                   int64
	}
	current := make(map[string]currentSecret)
	rows, err = tx.QueryContext(ctx, `SELECT sv.file_id, rf.target_path, sv.key_name, sv.scope, sv.scope_id, sv.version FROM secret_versions sv JOIN repo_files rf ON rf.id = sv.file_id AND rf.repository_id = sv.repository_id WHERE sv.repository_id = ? AND sv.archived_at IS NULL AND (sv.scope = 'baseline' OR sv.promoted_at IS NOT NULL) AND sv.version = (SELECT MAX(existing.version) FROM secret_versions existing WHERE existing.repository_id = sv.repository_id AND existing.file_id = sv.file_id AND existing.key_name = sv.key_name AND existing.scope = sv.scope AND existing.scope_id = sv.scope_id AND existing.archived_at IS NULL)`, repositoryID)
	if err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("list repository rotation snapshot: %w", err)
	}
	for rows.Next() {
		var secret currentSecret
		if err := rows.Scan(&secret.fileID, &secret.filePath, &secret.keyName, &secret.scope, &secret.scopeID, &secret.version); err != nil {
			rows.Close()
			return RepositoryCryptoState{}, fmt.Errorf("scan repository rotation snapshot: %w", err)
		}
		current[rotationSecretID(secret.fileID, secret.keyName, secret.scope, secret.scopeID)] = secret
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RepositoryCryptoState{}, fmt.Errorf("iterate repository rotation snapshot: %w", err)
	}
	rows.Close()
	if len(rotation.Secrets) != len(current) {
		return RepositoryCryptoState{}, ErrKeyRotationConflict
	}
	rotated := make(map[string]RotationSecret, len(rotation.Secrets))
	for _, secret := range rotation.Secrets {
		id := rotationSecretID(secret.FileID, secret.KeyName, secret.Scope, secret.ScopeID)
		expected, found := current[id]
		if !found || secret.FilePath != expected.filePath || !validSecretIdentity(secret.FileID, secret.KeyName) || !validSecretEnvelope(secret.Envelope) || secret.Envelope.KeyEpoch != state.ActiveKeyEpoch+1 || secret.Envelope.Version != expected.version+1 {
			return RepositoryCryptoState{}, ErrKeyRotationConflict
		}
		if _, duplicate := rotated[id]; duplicate {
			return RepositoryCryptoState{}, ErrKeyRotationConflict
		}
		rotated[id] = secret
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO repo_key_epochs(repository_id, epoch, status, created_at, retired_at) VALUES (?, ?, 'active', ?, NULL)`, repositoryID, state.ActiveKeyEpoch+1, now); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("create repository key epoch: %w", err)
	}
	for _, key := range rotation.WrappedKeys {
		if _, err := tx.ExecContext(ctx, `INSERT INTO wrapped_repo_keys(repository_id, epoch, device_id, wrapped_key, created_at) VALUES (?, ?, ?, ?, ?)`, repositoryID, state.ActiveKeyEpoch+1, key.DeviceID, key.WrappedREK, now); err != nil {
			return RepositoryCryptoState{}, fmt.Errorf("store rotated wrapped repository key: %w", err)
		}
	}
	for _, secret := range rotation.Secrets {
		id, err := newUUID()
		if err != nil {
			return RepositoryCryptoState{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO secret_versions(id, repository_id, file_id, key_name, scope, scope_id, version, key_epoch, algorithm, nonce, ciphertext, created_by_user_id, created_at, archived_at, promoted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`, id, repositoryID, secret.FileID, secret.KeyName, secret.Scope, secret.ScopeID, secret.Envelope.Version, secret.Envelope.KeyEpoch, secret.Envelope.Algorithm, secret.Envelope.Nonce, secret.Envelope.Ciphertext, strconv.FormatInt(githubUserID, 10), now); err != nil {
			return RepositoryCryptoState{}, fmt.Errorf("store rotated encrypted secret: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repo_key_epochs SET status = 'retired', retired_at = ? WHERE repository_id = ? AND epoch = ? AND status = 'active'`, now, repositoryID, state.ActiveKeyEpoch); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("retire repository key epoch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repositories SET active_key_epoch = ? WHERE id = ? AND active_key_epoch = ?`, state.ActiveKeyEpoch+1, repositoryID, state.ActiveKeyEpoch); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("activate repository key epoch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM wrapped_repo_keys WHERE repository_id = ? AND epoch = ?`, repositoryID, state.ActiveKeyEpoch); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("delete retired wrapped repository keys: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO repo_revisions(repository_id, revision, updated_at) VALUES (?, 1, ?) ON CONFLICT(repository_id) DO UPDATE SET revision = repo_revisions.revision + 1, updated_at = excluded.updated_at`, repositoryID, now); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("advance repository revision: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, githubUserID, deviceID, repositoryID, "repository.key_rotated", map[string]string{"from_epoch": strconv.FormatInt(state.ActiveKeyEpoch, 10), "to_epoch": strconv.FormatInt(state.ActiveKeyEpoch+1, 10)}); err != nil {
		return RepositoryCryptoState{}, err
	}
	if err := tx.Commit(); err != nil {
		return RepositoryCryptoState{}, fmt.Errorf("commit repository key rotation: %w", err)
	}
	state.ActiveKeyEpoch++
	state.Initialized = true
	return state, nil
}

func rotationSecretID(fileID, keyName, scope, scopeID string) string {
	return fileID + "\x00" + keyName + "\x00" + scope + "\x00" + scopeID
}

func validRepositoryName(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= 255 && !strings.ContainsAny(value, "/\\\x00")
}

func newUUID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("generate instance cryptographic identity: %w", err)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

func (s *Store) ensureCryptoInstanceID(ctx context.Context) (string, error) {
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT crypto_instance_id FROM instance WHERE id = 'singleton'`).Scan(&existing)
	if err != nil {
		return "", errors.New("instance cryptographic identity is not initialized")
	}
	if existing != "" {
		return existing, nil
	}
	generated, err := newUUID()
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE instance SET crypto_instance_id = ? WHERE id = 'singleton' AND crypto_instance_id = ''`, generated); err != nil {
		return "", fmt.Errorf("set instance cryptographic identity: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT crypto_instance_id FROM instance WHERE id = 'singleton'`).Scan(&existing); err != nil || existing == "" {
		return "", errors.New("instance cryptographic identity is not initialized")
	}
	return existing, nil
}

func validRequirement(requirement pranalysis.Requirement) bool {
	if requirement.FileID == "" || requirement.KeyName == "" {
		return false
	}
	return requirement.State == pranalysis.StateMissing || requirement.State == pranalysis.StateReady || requirement.State == pranalysis.StateRemoved
}

// RepositoryConfigSnapshot returns the last validated contract for a managed
// repository. It cannot return dotenv values because none are stored.
func (s *Store) RepositoryConfigSnapshot(ctx context.Context, githubRepoID int64) (RepositoryConfigSnapshot, error) {
	if githubRepoID <= 0 {
		return RepositoryConfigSnapshot{}, errors.New("GitHub repository ID must be positive")
	}
	var snapshot RepositoryConfigSnapshot
	var repositoryID string
	err := s.db.QueryRowContext(ctx, `SELECT id, github_repo_id, owner, name, default_branch FROM repositories WHERE github_repo_id = ?`, githubRepoID).Scan(&repositoryID, &snapshot.GitHubRepoID, &snapshot.Owner, &snapshot.Name, &snapshot.DefaultBranch)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RepositoryConfigSnapshot{}, errors.New("repository configuration snapshot not found")
		}
		return RepositoryConfigSnapshot{}, fmt.Errorf("read repository configuration: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT schema_path, target_path FROM repo_files WHERE repository_id = ? ORDER BY schema_path, target_path`, repositoryID)
	if err != nil {
		return RepositoryConfigSnapshot{}, fmt.Errorf("list repository file configuration: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var file RepositoryFile
		if err := rows.Scan(&file.SchemaPath, &file.TargetPath); err != nil {
			return RepositoryConfigSnapshot{}, fmt.Errorf("scan repository file configuration: %w", err)
		}
		snapshot.Files = append(snapshot.Files, file)
	}
	if err := rows.Err(); err != nil {
		return RepositoryConfigSnapshot{}, fmt.Errorf("iterate repository file configuration: %w", err)
	}
	return snapshot, nil
}

func validateRepositoryConfigSnapshot(snapshot RepositoryConfigSnapshot) error {
	if snapshot.GitHubRepoID <= 0 || strings.TrimSpace(snapshot.Owner) == "" || strings.TrimSpace(snapshot.Name) == "" || strings.TrimSpace(snapshot.DefaultBranch) == "" {
		return errors.New("repository configuration snapshot is incomplete")
	}
	if len(snapshot.Files) == 0 {
		return errors.New("repository configuration snapshot has no files")
	}
	seen := make(map[string]struct{}, len(snapshot.Files))
	for _, file := range snapshot.Files {
		if !validRepositoryRelativePath(file.SchemaPath) || !validRepositoryRelativePath(file.TargetPath) {
			return errors.New("repository configuration snapshot has an incomplete file mapping")
		}
		key := file.SchemaPath + "\x00" + file.TargetPath
		if _, duplicate := seen[key]; duplicate {
			return errors.New("repository configuration snapshot has duplicate file mappings")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validRepositoryRelativePath(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
}

// Close closes the database connection.
func (s *Store) Close() error { return s.db.Close() }

// BackupTo creates a transactionally consistent SQLite database copy without
// relying on copying a live WAL database. destination must not already exist.
func (s *Store) BackupTo(ctx context.Context, destination string) error {
	if strings.TrimSpace(destination) == "" || !filepath.IsAbs(destination) {
		return errors.New("backup destination must be an absolute path")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect backup destination: %w", err)
	}
	// VACUUM INTO is SQLite's safe online-copy mechanism. Quote the filename as
	// a SQL literal after rejecting no path content; values never enter this SQL.
	escaped := strings.ReplaceAll(destination, "'", "''")
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO '"+escaped+"'"); err != nil {
		return fmt.Errorf("create online SQLite backup: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return fmt.Errorf("secure SQLite backup: %w", err)
	}
	return nil
}
