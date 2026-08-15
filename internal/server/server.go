// Package server exposes the local.env HTTP surface.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/localenv/localenv/internal/config"
	"github.com/localenv/localenv/internal/dotenv"
	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/internal/repository"
	"github.com/localenv/localenv/internal/store/sqlite"
)

const (
	oauthStateCookie    = "localenv_oauth_state"
	cliOAuthStateCookie = "localenv_cli_oauth_state"
	setupCookie         = "localenv_setup"
	maxWebhookBytes     = 2 << 20
)

type readinessStore interface{ Ready(context.Context) error }

type githubSetupStore interface {
	ConfigureGitHubInstance(context.Context, int64, string, int64, string, string) error
	GitHubSetupReady(context.Context) error
}

type webhookStore interface {
	ProcessGitHubWebhook(context.Context, githubapp.WebhookEvent) (bool, error)
}

type webhookFailureStore interface {
	MarkGitHubWebhookFailed(context.Context, string) error
}

type discoveryStore interface {
	DiscoveredRepositories(context.Context) ([]githubapp.Repository, error)
}

type readinessPRStore interface {
	SavePullRequestRequirements(context.Context, githubapp.PullRequest, []pranalysis.Requirement) (sqlite.PullRequestReadiness, error)
	ClosePullRequest(context.Context, githubapp.PullRequest) error
	SaveReadinessPublication(context.Context, int64, int, int64, int64) error
}

type cliAuthStore interface {
	CreateAuthExchange(context.Context, githubapp.User, string, time.Time) error
	ConsumeAuthExchange(context.Context, string) (githubapp.User, error)
	CreateSession(context.Context, githubapp.User, string, time.Time) error
	AuthenticateSession(context.Context, string) (sqlite.AuthenticatedSession, error)
	RegisterDevice(context.Context, string, string, string, string, string) (sqlite.Device, error)
	DevicesForUser(context.Context, int64) ([]sqlite.Device, error)
	RevokeSession(context.Context, string) error
}

type repositoryCryptoStore interface {
	RepositoryCryptoState(context.Context, string, string) (sqlite.RepositoryCryptoState, error)
	InitializeRepositoryCrypto(context.Context, string, string, int64, string, []byte) (sqlite.RepositoryCryptoState, error)
	RotateRepositoryKey(context.Context, string, string, int64, string, sqlite.KeyRotation) (sqlite.RepositoryCryptoState, error)
}

type repositoryActivationStore interface {
	DiscoveredRepository(context.Context, string, string) (githubapp.Repository, int64, error)
	SaveRepositoryConfigSnapshot(context.Context, sqlite.RepositoryConfigSnapshot) error
}

type encryptedSecretStore interface {
	PullRequirementsForDevice(context.Context, string, string, int, int64, string) (sqlite.PullRequirementsResponse, error)
	UpdatePullRequestSecret(context.Context, string, string, int, int64, string, string, string, int64, sqlite.SecretEnvelope) (sqlite.PullRequestReadiness, error)
	RepositorySnapshotForDevice(context.Context, string, string, int64, string) (sqlite.RepositorySnapshot, error)
	PullRequestSnapshotForDevice(context.Context, string, string, int, int64, string) (sqlite.RepositorySnapshot, error)
	UpdateBaselineSecret(context.Context, string, string, int64, string, string, string, int64, sqlite.SecretEnvelope) error
}

type deviceSharingStore interface {
	CreateDeviceAccessRequest(context.Context, string, string, int64, string, string) (sqlite.DeviceAccessRequest, error)
	PendingDeviceAccessRequests(context.Context, string, string) ([]sqlite.DeviceAccessRequest, error)
	DeviceAccessRequestForCode(context.Context, string, string, string) (sqlite.DeviceAccessRequest, error)
	ApproveDeviceAccess(context.Context, string, string, int64, string, string, []byte) error
	RepositoryDevices(context.Context, string, string) ([]sqlite.RepositoryDevice, error)
	RevokeDevice(context.Context, int64, string, string) error
}

// Server holds dependencies for HTTP handlers.
type Server struct {
	config      config.Config
	store       readinessStore
	credentials *githubapp.CredentialStore
	github      githubapp.Client
	logger      *slog.Logger
	limiter     *requestLimiter
}

// New constructs a server using GitHub's public endpoints.
func New(config config.Config, store readinessStore) *Server {
	return NewWithGitHubClient(config, store, githubapp.DefaultClient())
}

// NewWithLogger constructs the production server with one shared structured
// logger for lifecycle and request events.
func NewWithLogger(config config.Config, store readinessStore, logger *slog.Logger) *Server {
	return NewWithGitHubClientAndLogger(config, store, githubapp.DefaultClient(), logger)
}

// NewWithGitHubClient exists to keep external GitHub exchanges testable.
func NewWithGitHubClient(config config.Config, store readinessStore, client githubapp.Client) *Server {
	return NewWithGitHubClientAndLogger(config, store, client, defaultLogger())
}

// NewWithGitHubClientAndLogger permits production to supply its structured
// logger and tests to capture only safe request metadata.
func NewWithGitHubClientAndLogger(config config.Config, store readinessStore, client githubapp.Client, logger *slog.Logger) *Server {
	if logger == nil {
		logger = defaultLogger()
	}
	return &Server{config: config, store: store, credentials: githubapp.NewCredentialStore(config.DataDir, config.GitHubAppCredentialsEncryptionKey), github: client, logger: logger, limiter: newRequestLimiter()}
}

// Handler returns the public HTTP routes available through P1.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /setup", s.setup)
	mux.HandleFunc("GET /login", s.dashboardLogin)
	mux.HandleFunc("GET /repos", s.dashboardRepositories)
	mux.HandleFunc("GET /repos/{owner}/{repo}", s.dashboardRepository)
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{number}", s.dashboardPullRequest)
	mux.HandleFunc("GET /devices", s.dashboardDevices)
	mux.HandleFunc("GET /audit", s.dashboardAudit)
	mux.HandleFunc("GET /settings", s.dashboardSettings)
	mux.HandleFunc("POST /setup/github-app", s.createGitHubApp)
	mux.HandleFunc("GET /setup/github-app/callback", s.githubAppCallback)
	mux.HandleFunc("GET /auth/github/start", s.githubAuthStart)
	mux.HandleFunc("GET /auth/github/callback", s.githubAuthCallback)
	mux.HandleFunc("GET /auth/cli/start", s.cliAuthStart)
	mux.HandleFunc("GET /auth/cli/callback", s.cliAuthCallback)
	mux.HandleFunc("POST /api/v1/auth/exchange", s.cliExchange)
	mux.HandleFunc("POST /api/v1/auth/logout", s.cliLogout)
	mux.HandleFunc("GET /api/v1/me", s.me)
	mux.HandleFunc("POST /api/v1/devices", s.registerDevice)
	mux.HandleFunc("GET /api/v1/devices", s.devices)
	mux.HandleFunc("POST /api/v1/repos/{owner}/{repo}/device-access-requests", s.createDeviceAccessRequest)
	mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}/device-access-requests", s.pendingDeviceAccessRequests)
	mux.HandleFunc("POST /api/v1/repos/{owner}/{repo}/device-access-requests/inspect", s.inspectDeviceAccessRequest)
	mux.HandleFunc("POST /api/v1/repos/{owner}/{repo}/device-access-requests/approve", s.approveDeviceAccess)
	mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}/devices", s.repositoryDevices)
	mux.HandleFunc("DELETE /api/v1/repos/{owner}/{repo}/devices/{id}", s.revokeDevice)
	mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}", s.repositoryCryptoState)
	mux.HandleFunc("POST /api/v1/repos/{owner}/{repo}/init", s.initializeRepositoryCrypto)
	mux.HandleFunc("POST /api/v1/repos/{owner}/{repo}/key-epochs", s.rotateRepositoryKey)
	mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}/snapshot", s.repositorySnapshot)
	mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}/pulls/current", s.currentPullRequest)
	mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}/pulls/{number}/snapshot", s.pullRequestSnapshot)
	mux.HandleFunc("PUT /api/v1/repos/{owner}/{repo}/secrets/{fileID}/{keyName}", s.updateBaselineSecret)
	mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}/pulls/{number}/requirements", s.pullRequirements)
	mux.HandleFunc("PUT /api/v1/repos/{owner}/{repo}/pulls/{number}/secrets/{fileID}/{keyName}", s.updatePullRequestSecret)
	mux.HandleFunc("POST /api/v1/github/webhook", s.githubWebhook)
	return s.withSecurity(mux)
}

// rotateRepositoryKey accepts only a complete client-side re-encryption of
// the current snapshot. No secret value or plaintext REK crosses this API.
func (s *Server) rotateRepositoryKey(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if authenticated.Device.ID == "" {
		http.Error(w, "active device is required", http.StatusBadRequest)
		return
	}
	store, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository key persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := store.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil || !state.Initialized {
		http.Error(w, "repository encryption is unavailable", http.StatusBadRequest)
		return
	}
	if !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	var rotation sqlite.KeyRotation
	if !decodeRequestJSON(w, r, &rotation) {
		return
	}
	state, err = store.RotateRepositoryKey(r.Context(), state.Owner, state.Name, authenticated.User.ID, authenticated.Device.ID, rotation)
	if errors.Is(err, sqlite.ErrKeyRotationConflict) {
		http.Error(w, "repository key rotation conflicted; download a fresh snapshot and retry", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "repository key rotation was rejected", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, state)
}

func (s *Server) currentPullRequest(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	branch := r.URL.Query().Get("branch")
	if strings.TrimSpace(branch) == "" || len(branch) > 255 {
		http.Error(w, "branch is required", http.StatusBadRequest)
		return
	}
	stateStore, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := stateStore.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil || !s.authorizeRepository(w, r, state, authenticated.User) {
		if err != nil {
			http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	credentials, found, err := s.credentials.Load()
	if err != nil || !found {
		http.Error(w, "GitHub App credentials are unavailable", http.StatusServiceUnavailable)
		return
	}
	number, err := s.github.OpenPullRequestNumber(r.Context(), credentials, state.InstallationID, state.Owner, state.Name, branch)
	if err != nil {
		http.Error(w, "pull request lookup is unavailable", http.StatusBadGateway)
		return
	}
	if number == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Number int `json:"number"`
	}{Number: number})
}

func (s *Server) pullRequestSnapshot(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	store, ok := s.store.(encryptedSecretStore)
	if !ok {
		http.Error(w, "encrypted secret persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	number, err := parsePositivePathInt(r.PathValue("number"))
	if err != nil || authenticated.Device.ID == "" {
		http.Error(w, "active device and pull request number are required", http.StatusBadRequest)
		return
	}
	stateStore, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := stateStore.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	snapshot, err := store.PullRequestSnapshotForDevice(r.Context(), state.Owner, state.Name, number, authenticated.User.ID, authenticated.Device.ID)
	if err != nil {
		http.Error(w, "encrypted pull request snapshot is unavailable", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) repositorySnapshot(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	store, ok := s.store.(encryptedSecretStore)
	if !ok {
		http.Error(w, "encrypted secret persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	stateStore, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := stateStore.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	if authenticated.Device.ID == "" || !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	snapshot, err := store.RepositorySnapshotForDevice(r.Context(), state.Owner, state.Name, authenticated.User.ID, authenticated.Device.ID)
	if err != nil {
		http.Error(w, "encrypted repository snapshot is unavailable", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) updateBaselineSecret(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	store, ok := s.store.(encryptedSecretStore)
	if !ok {
		http.Error(w, "encrypted secret persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	stateStore, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := stateStore.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	if authenticated.Device.ID == "" || !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	var request struct {
		ExpectedCurrentVersion int64                 `json:"expected_current_version"`
		Envelope               sqlite.SecretEnvelope `json:"envelope"`
	}
	if !decodeRequestJSON(w, r, &request) {
		return
	}
	err = store.UpdateBaselineSecret(r.Context(), state.Owner, state.Name, authenticated.User.ID, authenticated.Device.ID, r.PathValue("fileID"), r.PathValue("keyName"), request.ExpectedCurrentVersion, request.Envelope)
	if errors.Is(err, sqlite.ErrSecretVersionConflict) {
		http.Error(w, "secret changed remotely; refresh and retry", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "encrypted secret update was rejected", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		State string `json:"state"`
	}{State: "stored"})
}

func (s *Server) pullRequirements(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	store, ok := s.store.(encryptedSecretStore)
	if !ok {
		http.Error(w, "encrypted secret persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	number, err := parsePositivePathInt(r.PathValue("number"))
	if err != nil || authenticated.Device.ID == "" {
		http.Error(w, "active device and pull request number are required", http.StatusBadRequest)
		return
	}
	stateStore, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := stateStore.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	response, err := store.PullRequirementsForDevice(r.Context(), state.Owner, state.Name, number, authenticated.User.ID, authenticated.Device.ID)
	if err != nil {
		http.Error(w, "pull request requirements are unavailable", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) updatePullRequestSecret(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	store, ok := s.store.(encryptedSecretStore)
	if !ok {
		http.Error(w, "encrypted secret persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	number, err := parsePositivePathInt(r.PathValue("number"))
	if err != nil || authenticated.Device.ID == "" {
		http.Error(w, "active device and pull request number are required", http.StatusBadRequest)
		return
	}
	stateStore, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := stateStore.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	var request struct {
		ExpectedCurrentVersion int64                 `json:"expected_current_version"`
		Envelope               sqlite.SecretEnvelope `json:"envelope"`
	}
	if !decodeRequestJSON(w, r, &request) {
		return
	}
	readiness, err := store.UpdatePullRequestSecret(r.Context(), state.Owner, state.Name, number, authenticated.User.ID, authenticated.Device.ID, r.PathValue("fileID"), r.PathValue("keyName"), request.ExpectedCurrentVersion, request.Envelope)
	if errors.Is(err, sqlite.ErrSecretVersionConflict) {
		http.Error(w, "secret changed remotely; refresh and retry", http.StatusConflict)
		return
	}
	if errors.Is(err, sqlite.ErrPullRequestNotOpen) {
		http.Error(w, "pull request is not open", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "encrypted secret update was rejected", http.StatusBadRequest)
		return
	}
	credentials, configured, credentialErr := s.credentials.Load()
	if credentialErr != nil || !configured {
		writeJSON(w, http.StatusAccepted, struct {
			State     string `json:"state"`
			Readiness string `json:"readiness"`
		}{State: "stored", Readiness: "pending"})
		return
	}
	summary, comment, success := readinessText(readiness.Requirements, s.publicURL(fmt.Sprintf("/repos/%s/%s/pulls/%d", url.PathEscape(state.Owner), url.PathEscape(state.Name), number)))
	publication, err := s.github.PublishReadiness(r.Context(), credentials, state.InstallationID, readiness.PullRequest, githubapp.ReadinessPublication{CheckRunID: readiness.CheckRunID, CommentID: readiness.CommentID, Success: success, Summary: summary, Comment: comment})
	if err != nil {
		s.logGitHubPublicationFailure(err)
		if publications, ok := s.store.(readinessPRStore); ok && (publication.CheckRunID > 0 || publication.CommentID > 0) {
			_ = publications.SaveReadinessPublication(r.Context(), state.GitHubRepoID, number, publication.CheckRunID, publication.CommentID)
		}
		writeJSON(w, http.StatusAccepted, struct {
			State     string `json:"state"`
			Readiness string `json:"readiness"`
		}{State: "stored", Readiness: "pending"})
		return
	}
	if publications, ok := s.store.(readinessPRStore); ok {
		if err := publications.SaveReadinessPublication(r.Context(), state.GitHubRepoID, number, publication.CheckRunID, publication.CommentID); err != nil {
			writeJSON(w, http.StatusAccepted, struct {
				State     string `json:"state"`
				Readiness string `json:"readiness"`
			}{State: "stored", Readiness: "pending"})
			return
		}
	}
	writeJSON(w, http.StatusOK, struct {
		State     string `json:"state"`
		Readiness string `json:"readiness"`
	}{State: "ready", Readiness: "published"})
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if s.store.Ready(ctx) != nil || s.githubReady(ctx) != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) githubReady(ctx context.Context) error {
	store, ok := s.store.(githubSetupStore)
	if !ok {
		return nil // Retains the P0 fake-store operational test contract.
	}
	if !s.credentials.Configured() {
		return errors.New("GitHub credential encryption is not configured")
	}
	if err := store.GitHubSetupReady(ctx); err != nil {
		return err
	}
	_, found, err := s.credentials.Load()
	if err != nil || !found {
		return errors.New("GitHub App credentials are not available")
	}
	return nil
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	page := setupPage{DisplayName: s.config.DisplayName}
	if !s.config.GitHubSetupConfigured() {
		page.ConfigurationRequired = true
		s.renderSetup(w, http.StatusServiceUnavailable, page)
		return
	}
	credentials, configured, err := s.credentials.Load()
	if err != nil {
		http.Error(w, "setup configuration is unavailable", http.StatusServiceUnavailable)
		return
	}
	if configured {
		page.Complete = true
		page.AppURL = installationURL(credentials.AppHTMLURL)
		if store, ok := s.store.(discoveryStore); ok {
			page.Repositories, _ = store.DiscoveredRepositories(r.Context())
		}
		s.renderSetup(w, http.StatusOK, page)
		return
	}
	session, found := s.readSetupSession(r)
	if !found || session.Expired() {
		page.SignInURL = "/auth/github/start"
		s.renderSetup(w, http.StatusOK, page)
		return
	}
	page.CSRFToken = session.CSRFToken
	page.Organizations = session.Organizations
	s.renderSetup(w, http.StatusOK, page)
}

func (s *Server) githubAuthStart(w http.ResponseWriter, r *http.Request) {
	if !s.config.GitHubSetupConfigured() {
		http.Error(w, "GitHub setup is not configured", http.StatusServiceUnavailable)
		return
	}
	clientID, _, ok := s.oauthCredentials()
	if !ok {
		http.Error(w, "GitHub OAuth is not configured", http.StatusServiceUnavailable)
		return
	}
	state, err := randomToken()
	if err != nil {
		http.Error(w, "could not start GitHub sign-in", http.StatusInternalServerError)
		return
	}
	if !s.writeCookie(w, oauthStateCookie, oauthState{State: state, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, 10*time.Minute) {
		http.Error(w, "could not start GitHub sign-in", http.StatusInternalServerError)
		return
	}
	authorizeURL, err := s.github.AuthorizationURL(clientID, s.publicURL("/auth/github/callback"), state)
	if err != nil {
		http.Error(w, "could not start GitHub sign-in", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

func (s *Server) githubAuthCallback(w http.ResponseWriter, r *http.Request) {
	state, found := s.readOAuthState(r)
	if !found || state.Expired() || r.URL.Query().Get("state") == "" || r.URL.Query().Get("state") != state.State || r.URL.Query().Get("code") == "" {
		http.Error(w, "GitHub sign-in could not be verified", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := s.oauthCredentials()
	if !ok {
		http.Error(w, "GitHub OAuth is not configured", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := s.github.ExchangeOAuthCode(ctx, clientID, clientSecret, r.URL.Query().Get("code"), s.publicURL("/auth/github/callback"))
	if err != nil {
		http.Error(w, "GitHub sign-in failed", http.StatusBadGateway)
		return
	}
	user, organizations, err := s.github.UserAndOrganizations(ctx, token)
	if err != nil {
		http.Error(w, "GitHub organization discovery failed", http.StatusBadGateway)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "could not complete GitHub sign-in", http.StatusInternalServerError)
		return
	}
	if state.Audience == "dashboard" {
		store, available := s.store.(dashboardStore)
		if !available {
			http.Error(w, "dashboard is unavailable", http.StatusServiceUnavailable)
			return
		}
		organization, orgErr := store.DashboardOrganization(ctx)
		if orgErr != nil {
			http.Error(w, "GitHub organization membership is required for dashboard access", http.StatusForbidden)
			return
		}
		membership, membershipErr := s.github.ActiveOrganizationMembership(ctx, token, organization.Login)
		if membershipErr != nil || membership.ID != organization.ID {
			http.Error(w, "GitHub organization membership is required for dashboard access", http.StatusForbidden)
			return
		}
		session := dashboardSession{User: user, OrganizationID: organization.ID, ExpiresAt: time.Now().UTC().Add(8 * time.Hour)}
		if !s.writeCookie(w, dashboardCookie, session, 8*time.Hour) {
			http.Error(w, "could not complete dashboard sign-in", http.StatusInternalServerError)
			return
		}
		s.clearCookie(w, oauthStateCookie)
		http.Redirect(w, r, "/repos", http.StatusFound)
		return
	}
	session := setupSession{User: user, Organizations: organizations, CSRFToken: csrf, ExpiresAt: time.Now().UTC().Add(15 * time.Minute)}
	if !s.writeCookie(w, setupCookie, session, 15*time.Minute) {
		http.Error(w, "could not complete GitHub sign-in", http.StatusInternalServerError)
		return
	}
	s.clearCookie(w, oauthStateCookie)
	http.Redirect(w, r, "/setup", http.StatusFound)
}

// cliAuthStart creates browser state bound to a local loopback callback. The
// callback is intentionally constrained to 127.0.0.1/::1 so a login code can
// never be redirected to an arbitrary remote host.
func (s *Server) cliAuthStart(w http.ResponseWriter, r *http.Request) {
	callback, ok := loopbackCallback(r.URL.Query().Get("redirect_uri"))
	if !ok || s.config.PublicURL == nil {
		http.Error(w, "CLI login is unavailable", http.StatusBadRequest)
		return
	}
	clientID, _, ok := s.oauthCredentials()
	if !ok {
		http.Error(w, "GitHub OAuth is not configured", http.StatusServiceUnavailable)
		return
	}
	state, err := randomToken()
	if err != nil || !s.writeCookie(w, cliOAuthStateCookie, cliOAuthState{State: state, CallbackURL: callback.String(), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, 10*time.Minute) {
		http.Error(w, "could not start CLI sign-in", http.StatusInternalServerError)
		return
	}
	authorizeURL, err := s.github.AuthorizationURL(clientID, s.publicURL("/auth/cli/callback"), state)
	if err != nil {
		http.Error(w, "could not start CLI sign-in", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

func (s *Server) cliAuthCallback(w http.ResponseWriter, r *http.Request) {
	state, found := s.readCLIOAuthState(r)
	if !found || state.Expired() || r.URL.Query().Get("code") == "" || r.URL.Query().Get("state") != state.State {
		http.Error(w, "CLI sign-in could not be verified", http.StatusBadRequest)
		return
	}
	callback, ok := loopbackCallback(state.CallbackURL)
	if !ok {
		http.Error(w, "CLI sign-in callback is invalid", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := s.oauthCredentials()
	if !ok {
		http.Error(w, "GitHub OAuth is not configured", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	githubToken, err := s.github.ExchangeOAuthCode(ctx, clientID, clientSecret, r.URL.Query().Get("code"), s.publicURL("/auth/cli/callback"))
	if err != nil {
		http.Error(w, "GitHub sign-in failed", http.StatusBadGateway)
		return
	}
	user, _, err := s.github.UserAndOrganizations(ctx, githubToken)
	if err != nil {
		http.Error(w, "GitHub identity lookup failed", http.StatusBadGateway)
		return
	}
	store, ok := s.store.(cliAuthStore)
	if !ok {
		http.Error(w, "CLI authentication persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	exchange, err := randomToken()
	if err != nil || store.CreateAuthExchange(ctx, user, exchange, time.Now().UTC().Add(5*time.Minute)) != nil {
		http.Error(w, "could not complete CLI sign-in", http.StatusInternalServerError)
		return
	}
	query := callback.Query()
	query.Set("code", exchange)
	callback.RawQuery = query.Encode()
	s.clearCookie(w, cliOAuthStateCookie)
	http.Redirect(w, r, callback.String(), http.StatusFound)
}

func (s *Server) cliExchange(w http.ResponseWriter, r *http.Request) {
	store, ok := s.store.(cliAuthStore)
	if !ok {
		http.Error(w, "CLI authentication persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if !decodeRequestJSON(w, r, &request) || request.Code == "" {
		http.Error(w, "invalid authentication exchange", http.StatusBadRequest)
		return
	}
	user, err := store.ConsumeAuthExchange(r.Context(), request.Code)
	if err != nil {
		http.Error(w, "invalid authentication exchange", http.StatusUnauthorized)
		return
	}
	token, err := randomToken()
	if err != nil || store.CreateSession(r.Context(), user, token, time.Now().UTC().Add(30*24*time.Hour)) != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Token     string         `json:"token"`
		ExpiresAt time.Time      `json:"expires_at"`
		User      githubapp.User `json:"user"`
	}{Token: token, ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour), User: user})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	authenticated, token, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	_ = token
	writeJSON(w, http.StatusOK, struct {
		User   githubapp.User `json:"user"`
		Device sqlite.Device  `json:"device"`
	}{User: authenticated.User, Device: authenticated.Device})
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	_, token, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var request struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		PublicRecipient string `json:"public_recipient"`
		Fingerprint     string `json:"fingerprint"`
	}
	if !decodeRequestJSON(w, r, &request) || request.ID == "" || request.Name == "" || request.Fingerprint == "" {
		http.Error(w, "invalid device registration", http.StatusBadRequest)
		return
	}
	if _, err := age.ParseX25519Recipient(request.PublicRecipient); err != nil {
		http.Error(w, "invalid device registration", http.StatusBadRequest)
		return
	}
	store := s.store.(cliAuthStore)
	device, err := store.RegisterDevice(r.Context(), token, request.ID, request.Name, request.PublicRecipient, request.Fingerprint)
	if err != nil {
		http.Error(w, "device registration failed", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	devices, err := s.store.(cliAuthStore).DevicesForUser(r.Context(), authenticated.User.ID)
	if err != nil {
		http.Error(w, "could not list devices", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) deviceAccessState(w http.ResponseWriter, r *http.Request) (sqlite.AuthenticatedSession, sqlite.RepositoryCryptoState, deviceSharingStore, bool) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return sqlite.AuthenticatedSession{}, sqlite.RepositoryCryptoState{}, nil, false
	}
	store, ok := s.store.(deviceSharingStore)
	if !ok {
		http.Error(w, "device sharing persistence is unavailable", http.StatusServiceUnavailable)
		return sqlite.AuthenticatedSession{}, sqlite.RepositoryCryptoState{}, nil, false
	}
	stateStore, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return sqlite.AuthenticatedSession{}, sqlite.RepositoryCryptoState{}, nil, false
	}
	state, err := stateStore.RepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return sqlite.AuthenticatedSession{}, sqlite.RepositoryCryptoState{}, nil, false
	}
	if err != nil || !state.Initialized {
		http.Error(w, "repository encryption is unavailable", http.StatusBadRequest)
		return sqlite.AuthenticatedSession{}, sqlite.RepositoryCryptoState{}, nil, false
	}
	if authenticated.Device.ID == "" || !s.authorizeRepository(w, r, state, authenticated.User) {
		return sqlite.AuthenticatedSession{}, sqlite.RepositoryCryptoState{}, nil, false
	}
	return authenticated, state, store, true
}

func (s *Server) createDeviceAccessRequest(w http.ResponseWriter, r *http.Request) {
	authenticated, state, store, ok := s.deviceAccessState(w, r)
	if !ok {
		return
	}
	code, err := randomToken()
	if err != nil {
		http.Error(w, "could not create device access request", http.StatusInternalServerError)
		return
	}
	request, err := store.CreateDeviceAccessRequest(r.Context(), state.Owner, state.Name, authenticated.User.ID, authenticated.Device.ID, code)
	if err != nil {
		http.Error(w, "device access request was rejected", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		sqlite.DeviceAccessRequest
		Code string `json:"code"`
	}{DeviceAccessRequest: request, Code: code})
}

func (s *Server) pendingDeviceAccessRequests(w http.ResponseWriter, r *http.Request) {
	_, state, store, ok := s.deviceAccessState(w, r)
	if !ok {
		return
	}
	requests, err := store.PendingDeviceAccessRequests(r.Context(), state.Owner, state.Name)
	if err != nil {
		http.Error(w, "pending device access requests are unavailable", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, requests)
}

func (s *Server) inspectDeviceAccessRequest(w http.ResponseWriter, r *http.Request) {
	_, state, store, ok := s.deviceAccessState(w, r)
	if !ok {
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if !decodeRequestJSON(w, r, &request) {
		return
	}
	access, err := store.DeviceAccessRequestForCode(r.Context(), state.Owner, state.Name, request.Code)
	if errors.Is(err, sqlite.ErrDeviceAccessNotFound) {
		http.Error(w, "device access request was not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "device access request is unavailable", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, access)
}

func (s *Server) approveDeviceAccess(w http.ResponseWriter, r *http.Request) {
	authenticated, state, store, ok := s.deviceAccessState(w, r)
	if !ok {
		return
	}
	var request struct {
		Code       string `json:"code"`
		WrappedREK []byte `json:"wrapped_rek"`
	}
	if !decodeRequestJSON(w, r, &request) {
		return
	}
	err := store.ApproveDeviceAccess(r.Context(), state.Owner, state.Name, authenticated.User.ID, authenticated.Device.ID, request.Code, request.WrappedREK)
	if errors.Is(err, sqlite.ErrDeviceAccessNotFound) {
		http.Error(w, "device access request was not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "device access approval was rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) repositoryDevices(w http.ResponseWriter, r *http.Request) {
	_, state, store, ok := s.deviceAccessState(w, r)
	if !ok {
		return
	}
	devices, err := store.RepositoryDevices(r.Context(), state.Owner, state.Name)
	if err != nil {
		http.Error(w, "repository devices are unavailable", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	authenticated, _, store, ok := s.deviceAccessState(w, r)
	if !ok {
		return
	}
	if err := store.RevokeDevice(r.Context(), authenticated.User.ID, authenticated.Device.ID, r.PathValue("id")); err != nil {
		http.Error(w, "device revocation was rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) cliLogout(w http.ResponseWriter, r *http.Request) {
	_, token, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if err := s.store.(cliAuthStore).RevokeSession(r.Context(), token); err != nil {
		http.Error(w, "could not revoke session", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// repositoryCryptoState returns only public repository/crypto metadata after
// the caller's current GitHub write access has been checked. Wrapped keys are
// intentionally introduced only by the later snapshot flow.
func (s *Server) repositoryCryptoState(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	store, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository bootstrap persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := s.ensureRepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"), store)
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "repository bootstrap is unavailable", http.StatusServiceUnavailable)
		return
	}
	if authenticated.Device.ID == "" || !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	writeJSON(w, http.StatusOK, state)
}

// initializeRepositoryCrypto accepts an age-wrapped 32-byte REK generated on
// the client. It neither accepts nor constructs a plaintext repository key.
func (s *Server) initializeRepositoryCrypto(w http.ResponseWriter, r *http.Request) {
	authenticated, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	store, ok := s.store.(repositoryCryptoStore)
	if !ok {
		http.Error(w, "repository bootstrap persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := s.ensureRepositoryCryptoState(r.Context(), r.PathValue("owner"), r.PathValue("repo"), store)
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "repository bootstrap is unavailable", http.StatusServiceUnavailable)
		return
	}
	if authenticated.Device.ID == "" || !s.authorizeRepository(w, r, state, authenticated.User) {
		return
	}
	var request struct {
		WrappedREK []byte `json:"wrapped_rek"`
	}
	if !decodeRequestJSON(w, r, &request) {
		return
	}
	initialized, err := store.InitializeRepositoryCrypto(r.Context(), state.Owner, state.Name, authenticated.User.ID, authenticated.Device.ID, request.WrappedREK)
	if errors.Is(err, sqlite.ErrRepositoryAlreadyInitialized) {
		http.Error(w, "repository encryption is already initialized", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "repository encryption bootstrap failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, initialized)
}

// ensureRepositoryCryptoState activates an installed repository from its
// committed default-branch contract exactly when the first CLI bootstrap
// needs it. Only public paths and schema key syntax are persisted.
func (s *Server) ensureRepositoryCryptoState(ctx context.Context, owner, name string, stateStore repositoryCryptoStore) (sqlite.RepositoryCryptoState, error) {
	state, err := stateStore.RepositoryCryptoState(ctx, owner, name)
	if !errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		return state, err
	}
	activationStore, ok := s.store.(repositoryActivationStore)
	if !ok {
		return sqlite.RepositoryCryptoState{}, err
	}
	discovered, installationID, err := activationStore.DiscoveredRepository(ctx, owner, name)
	if err != nil {
		return sqlite.RepositoryCryptoState{}, err
	}
	credentials, configured, err := s.credentials.Load()
	if err != nil || !configured {
		return sqlite.RepositoryCryptoState{}, errors.New("GitHub App credentials are unavailable")
	}
	contractSource, err := s.github.ReadFile(ctx, credentials, installationID, discovered.Owner, discovered.Name, "localenv.yaml", discovered.DefaultBranch)
	if err != nil {
		return sqlite.RepositoryCryptoState{}, fmt.Errorf("read repository contract: %w", err)
	}
	contract, err := repository.ParseConfig(contractSource)
	if err != nil {
		return sqlite.RepositoryCryptoState{}, fmt.Errorf("parse repository contract: %w", err)
	}
	files := make([]sqlite.RepositoryFile, 0, len(contract.Files))
	for _, file := range contract.Files {
		schema, err := s.github.ReadFile(ctx, credentials, installationID, discovered.Owner, discovered.Name, file.Schema, discovered.DefaultBranch)
		if err != nil {
			return sqlite.RepositoryCryptoState{}, fmt.Errorf("read repository schema: %w", err)
		}
		if _, err := dotenv.ParseSchema(schema); err != nil {
			return sqlite.RepositoryCryptoState{}, fmt.Errorf("parse repository schema: %w", err)
		}
		files = append(files, sqlite.RepositoryFile{SchemaPath: file.Schema, TargetPath: file.Target})
	}
	if err := activationStore.SaveRepositoryConfigSnapshot(ctx, sqlite.RepositoryConfigSnapshot{GitHubRepoID: discovered.GitHubRepoID, Owner: discovered.Owner, Name: discovered.Name, DefaultBranch: discovered.DefaultBranch, Files: files}); err != nil {
		return sqlite.RepositoryCryptoState{}, fmt.Errorf("activate repository contract: %w", err)
	}
	return stateStore.RepositoryCryptoState(ctx, discovered.Owner, discovered.Name)
}

func (s *Server) authorizeRepository(w http.ResponseWriter, r *http.Request, state sqlite.RepositoryCryptoState, user githubapp.User) bool {
	credentials, configured, err := s.credentials.Load()
	if err != nil || !configured {
		http.Error(w, "repository authorization is unavailable", http.StatusServiceUnavailable)
		return false
	}
	allowed, err := s.github.HasRepositoryWriteAccess(r.Context(), credentials, state.InstallationID, state.Owner, state.Name, user.Login)
	if err != nil {
		http.Error(w, "repository authorization is unavailable", http.StatusBadGateway)
		return false
	}
	if !allowed {
		http.Error(w, "repository access is required", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (sqlite.AuthenticatedSession, string, bool) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return sqlite.AuthenticatedSession{}, "", false
	}
	store, ok := s.store.(cliAuthStore)
	if !ok {
		http.Error(w, "CLI authentication persistence is unavailable", http.StatusServiceUnavailable)
		return sqlite.AuthenticatedSession{}, "", false
	}
	result, err := store.AuthenticateSession(r.Context(), token)
	if err != nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return sqlite.AuthenticatedSession{}, "", false
	}
	return result, token, true
}

func (s *Server) createGitHubApp(w http.ResponseWriter, r *http.Request) {
	if !s.config.GitHubSetupConfigured() || s.rejectCrossOrigin(r) {
		http.Error(w, "GitHub setup is unavailable", http.StatusForbidden)
		return
	}
	if _, complete, _ := s.credentials.Load(); complete {
		http.Error(w, "GitHub App is already configured", http.StatusConflict)
		return
	}
	session, found := s.readSetupSession(r)
	if !found || session.Expired() || r.FormValue("csrf_token") == "" || r.FormValue("csrf_token") != session.CSRFToken {
		http.Error(w, "setup session could not be verified", http.StatusForbidden)
		return
	}
	organization, found := session.organization(r.FormValue("organization_id"))
	if !found {
		http.Error(w, "selected GitHub organization is unavailable", http.StatusBadRequest)
		return
	}
	state, err := randomToken()
	if err != nil {
		http.Error(w, "could not create GitHub App setup", http.StatusInternalServerError)
		return
	}
	session.ManifestState = state
	session.SelectedOrganization = organization
	if !s.writeCookie(w, setupCookie, session, time.Until(session.ExpiresAt)) {
		http.Error(w, "could not create GitHub App setup", http.StatusInternalServerError)
		return
	}
	manifest, err := githubapp.Manifest(organization.Login+"-localenv", s.config.PublicURL.String())
	if err != nil {
		http.Error(w, "could not create GitHub App manifest", http.StatusInternalServerError)
		return
	}
	action := "https://github.com/organizations/" + url.PathEscape(organization.Login) + "/settings/apps/new?state=" + url.QueryEscape(state)
	s.renderManifestPost(w, action, string(manifest))
}

func (s *Server) githubAppCallback(w http.ResponseWriter, r *http.Request) {
	session, found := s.readSetupSession(r)
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	if !found || session.Expired() || code == "" || state == "" || state != session.ManifestState || session.SelectedOrganization.ID <= 0 {
		http.Error(w, "GitHub App setup could not be verified", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	conversion, err := s.github.ConvertManifest(ctx, code)
	if err != nil {
		http.Error(w, "GitHub App setup failed", http.StatusBadGateway)
		return
	}
	credentials := githubapp.Credentials{AppID: conversion.ID, ClientID: conversion.ClientID, ClientSecret: conversion.ClientSecret, PrivateKeyPEM: conversion.PEM, WebhookSecret: conversion.WebhookSecret, AppHTMLURL: conversion.HTMLURL}
	if existing, configured, err := s.credentials.Load(); err != nil {
		http.Error(w, "GitHub App setup storage is unavailable", http.StatusServiceUnavailable)
		return
	} else if configured && existing.AppID != credentials.AppID {
		http.Error(w, "GitHub App is already configured", http.StatusConflict)
		return
	}
	if err := s.credentials.Save(credentials); err != nil {
		http.Error(w, "GitHub App setup storage failed", http.StatusInternalServerError)
		return
	}
	store, ok := s.store.(githubSetupStore)
	if !ok {
		http.Error(w, "GitHub setup persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := store.ConfigureGitHubInstance(ctx, session.SelectedOrganization.ID, session.SelectedOrganization.Login, credentials.AppID, s.config.PublicURL.String(), s.config.DisplayName); err != nil {
		http.Error(w, "GitHub App setup persistence failed", http.StatusInternalServerError)
		return
	}
	s.clearCookie(w, setupCookie)
	http.Redirect(w, r, "/setup", http.StatusFound)
}

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	credentials, configured, err := s.credentials.Load()
	if err != nil || !configured {
		http.Error(w, "GitHub webhook is not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBytes))
	if err != nil {
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}
	if !githubapp.VerifyWebhookSignature(credentials.WebhookSecret, r.Header.Get("X-Hub-Signature-256"), body) {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	event, err := githubapp.ParseWebhook(r.Header.Get("X-GitHub-Event"), r.Header.Get("X-GitHub-Delivery"), body)
	if err != nil {
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}
	store, ok := s.store.(webhookStore)
	if !ok {
		http.Error(w, "webhook persistence is unavailable", http.StatusServiceUnavailable)
		return
	}
	duplicate, err := store.ProcessGitHubWebhook(r.Context(), event)
	if err != nil {
		http.Error(w, "webhook processing failed", http.StatusInternalServerError)
		return
	}
	if duplicate {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"duplicate"}\n`))
		return
	}
	if event.PullRequest != nil {
		if err := s.processPullRequest(r.Context(), credentials, event); err != nil {
			if failures, ok := s.store.(webhookFailureStore); ok {
				_ = failures.MarkGitHubWebhookFailed(r.Context(), event.DeliveryID)
			}
			http.Error(w, "pull request readiness processing failed", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}\n`))
}

func (s *Server) processPullRequest(ctx context.Context, credentials githubapp.Credentials, event githubapp.WebhookEvent) error {
	store, ok := s.store.(readinessPRStore)
	if !ok || event.PullRequest == nil {
		return nil
	}
	pull := *event.PullRequest
	if pull.State == "closed" || pull.State == "merged" {
		err := store.ClosePullRequest(ctx, pull)
		if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
			return nil
		}
		return err
	}
	result, err := pranalysis.Analyze(ctx, s.github, credentials, event.InstallationID, pull)
	if err != nil {
		return err
	}
	readiness, err := store.SavePullRequestRequirements(ctx, pull, result.Requirements)
	if errors.Is(err, sqlite.ErrRepositoryNotManaged) {
		return nil
	}
	if err != nil {
		return err
	}
	summary, comment, success := readinessText(result.Requirements, s.publicURL(fmt.Sprintf("/repos/%s/%s/pulls/%d", url.PathEscape(pull.Repository.Owner), url.PathEscape(pull.Repository.Name), pull.Number)))
	publication, err := s.github.PublishReadiness(ctx, credentials, event.InstallationID, pull, githubapp.ReadinessPublication{CheckRunID: readiness.CheckRunID, CommentID: readiness.CommentID, Success: success, Summary: summary, Comment: comment})
	if err != nil {
		s.logGitHubPublicationFailure(err)
		if publication.CheckRunID > 0 || publication.CommentID > 0 {
			_ = store.SaveReadinessPublication(ctx, pull.Repository.GitHubRepoID, pull.Number, publication.CheckRunID, publication.CommentID)
		}
		return err
	}
	return store.SaveReadinessPublication(ctx, pull.Repository.GitHubRepoID, pull.Number, publication.CheckRunID, publication.CommentID)
}

func (s *Server) logGitHubPublicationFailure(err error) {
	var githubError *githubapp.HTTPError
	if errors.As(err, &githubError) {
		attributes := []any{"github_operation", githubError.Operation, "github_status", githubError.StatusCode, "github_status_class", githubError.StatusClass()}
		if githubError.PermissionRequirement != "" {
			attributes = append(attributes, "github_permission_requirement", githubError.PermissionRequirement)
		}
		if githubError.GrantedPermissions != "" {
			attributes = append(attributes, "github_granted_permissions", githubError.GrantedPermissions)
		}
		s.logger.Warn("GitHub readiness publication failed", attributes...)
		return
	}
	s.logger.Warn("GitHub readiness publication failed", "github_status_class", "transport_or_response")
}

func readinessText(requirements []pranalysis.Requirement, detailsURL string) (summary, comment string, success bool) {
	missing := make([]string, 0)
	for _, requirement := range requirements {
		if requirement.State == pranalysis.StateMissing {
			missing = append(missing, requirement.KeyName)
		}
	}
	if len(missing) == 0 {
		return "All newly required local environment variables are configured.", "local.env readiness is passing.\n\nAll newly required local environment variables are configured.\n\nDocumentation:\n" + detailsURL, true
	}
	lines := make([]string, 0, len(missing))
	for _, key := range missing {
		lines = append(lines, "- "+key)
	}
	summary = fmt.Sprintf("Environment readiness failed.\n\n%d local environment variable", len(missing))
	if len(missing) != 1 {
		summary += "s are"
	} else {
		summary += " is"
	}
	summary += " missing:\n\n" + strings.Join(lines, "\n") + "\n\nRun:\n\n  localenv resolve\n\nor:\n\n  localenv set " + missing[0]
	comment = "local.env detected a new local environment dependency.\n\n"
	for _, key := range missing {
		comment += key + "    ❌ missing\n"
	}
	comment += "\nPR author: run\n\n    localenv resolve\n\nDocumentation:\n" + detailsURL
	return summary, comment, false
}

func (s *Server) oauthCredentials() (string, string, bool) {
	if credentials, configured, err := s.credentials.Load(); err == nil && configured {
		return credentials.ClientID, credentials.ClientSecret, true
	}
	if s.config.GitHubOAuthClientID != "" && s.config.GitHubOAuthClientSecret != "" {
		return s.config.GitHubOAuthClientID, s.config.GitHubOAuthClientSecret, true
	}
	return "", "", false
}

func (s *Server) publicURL(path string) string {
	copy := *s.config.PublicURL
	copy.Path = strings.TrimRight(copy.Path, "/") + path
	copy.RawQuery, copy.Fragment = "", ""
	return copy.String()
}

func (s *Server) writeCookie(w http.ResponseWriter, name string, value any, lifetime time.Duration) bool {
	encoded, err := json.Marshal(value)
	if err != nil {
		return false
	}
	sealed, err := s.credentials.SealCookie(encoded, name)
	if err != nil {
		return false
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/", Expires: time.Now().UTC().Add(lifetime), HttpOnly: true, Secure: s.config.PublicURL.Scheme == "https", SameSite: http.SameSiteLaxMode})
	return true
}

func (s *Server) readOAuthState(r *http.Request) (oauthState, bool) {
	var v oauthState
	return v, s.readCookie(r, oauthStateCookie, &v) && !v.ExpiresAt.IsZero()
}
func (s *Server) readCLIOAuthState(r *http.Request) (cliOAuthState, bool) {
	var v cliOAuthState
	return v, s.readCookie(r, cliOAuthStateCookie, &v) && !v.ExpiresAt.IsZero()
}
func (s *Server) readSetupSession(r *http.Request) (setupSession, bool) {
	var v setupSession
	return v, s.readCookie(r, setupCookie, &v) && !v.ExpiresAt.IsZero()
}

func (s *Server) readCookie(r *http.Request, name string, target any) bool {
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return false
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return false
	}
	plaintext, err := s.credentials.OpenCookie(ciphertext, name)
	if err != nil {
		return false
	}
	return json.Unmarshal(plaintext, target) == nil
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.config.PublicURL.Scheme == "https", SameSite: http.SameSiteLaxMode})
}

func (s *Server) rejectCrossOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return true
	}
	return parsed.Scheme != s.config.PublicURL.Scheme || parsed.Host != s.config.PublicURL.Host
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

type oauthState struct {
	State     string    `json:"state"`
	Audience  string    `json:"audience,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s oauthState) Expired() bool { return time.Now().UTC().After(s.ExpiresAt) }

type cliOAuthState struct {
	State       string    `json:"state"`
	CallbackURL string    `json:"callback_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s cliOAuthState) Expired() bool { return time.Now().UTC().After(s.ExpiresAt) }

func loopbackCallback(raw string) (*url.URL, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, false
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "127.0.0.1" && host != "::1" && host != "localhost" || parsed.Port() == "" {
		return nil, false
	}
	return parsed, true
}

func decodeRequestJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Body == nil {
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}

func parsePositivePathInt(raw string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, errors.New("invalid positive integer")
	}
	return value, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type setupSession struct {
	User                 githubapp.User           `json:"user"`
	Organizations        []githubapp.Organization `json:"organizations"`
	CSRFToken            string                   `json:"csrf_token"`
	ManifestState        string                   `json:"manifest_state,omitempty"`
	SelectedOrganization githubapp.Organization   `json:"selected_organization,omitempty"`
	ExpiresAt            time.Time                `json:"expires_at"`
}

func (s setupSession) Expired() bool { return time.Now().UTC().After(s.ExpiresAt) }
func (s setupSession) organization(rawID string) (githubapp.Organization, bool) {
	for _, organization := range s.Organizations {
		if fmt.Sprint(organization.ID) == rawID {
			return organization, true
		}
	}
	return githubapp.Organization{}, false
}

type setupPage struct {
	DisplayName           string
	ConfigurationRequired bool
	Complete              bool
	SignInURL             string
	CSRFToken             string
	Organizations         []githubapp.Organization
	AppURL                string
	Repositories          []githubapp.Repository
}

var setupTemplate = template.Must(template.New("setup").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{.DisplayName}} setup</title></head><body><main><h1>{{.DisplayName}} setup</h1>{{if .ConfigurationRequired}}<p>GitHub setup requires the bootstrap OAuth client and credential-encryption key configured by the instance administrator.</p>{{else if .Complete}}<p>GitHub App setup is complete. Install the App into the repositories you want local.env to discover.</p>{{if .AppURL}}<p><a href="{{.AppURL}}">Install GitHub App</a></p>{{end}}{{if .Repositories}}<h2>Discovered repositories</h2><ul>{{range .Repositories}}<li>{{.Owner}}/{{.Name}}</li>{{end}}</ul>{{end}}{{else if .SignInURL}}<p><a href="{{.SignInURL}}">Sign in with GitHub to select an organization</a></p>{{else}}<p>Select the organization that will own this GitHub App.</p><form method="post" action="/setup/github-app"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>Organization <select name="organization_id" required>{{range .Organizations}}<option value="{{.ID}}">{{.Login}}</option>{{end}}</select></label><button type="submit">Create GitHub App</button></form>{{end}}</main></body></html>`))
var manifestPostTemplate = template.Must(template.New("manifest").Parse(`<!doctype html><html lang="en"><body><main><p>Continue to GitHub to create your App.</p><form method="post" action="{{.Action}}"><input type="hidden" name="manifest" value="{{.Manifest}}"><button type="submit">Continue to GitHub</button></form></main></body></html>`))

func (s *Server) renderSetup(w http.ResponseWriter, status int, page setupPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = setupTemplate.Execute(w, page)
}
func (s *Server) renderManifestPost(w http.ResponseWriter, action, manifest string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = manifestPostTemplate.Execute(w, struct{ Action, Manifest string }{action, manifest})
}
func installationURL(htmlURL string) string {
	if htmlURL == "" {
		return ""
	}
	return strings.TrimRight(htmlURL, "/") + "/installations/new"
}
