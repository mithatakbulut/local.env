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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/localenv/localenv/internal/config"
	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/internal/store/sqlite"
)

const (
	oauthStateCookie = "localenv_oauth_state"
	setupCookie      = "localenv_setup"
	maxWebhookBytes  = 2 << 20
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

// Server holds dependencies for HTTP handlers.
type Server struct {
	config      config.Config
	store       readinessStore
	credentials *githubapp.CredentialStore
	github      githubapp.Client
}

// New constructs a server using GitHub's public endpoints.
func New(config config.Config, store readinessStore) *Server {
	return NewWithGitHubClient(config, store, githubapp.DefaultClient())
}

// NewWithGitHubClient exists to keep external GitHub exchanges testable.
func NewWithGitHubClient(config config.Config, store readinessStore, client githubapp.Client) *Server {
	return &Server{config: config, store: store, credentials: githubapp.NewCredentialStore(config.DataDir, config.GitHubAppCredentialsEncryptionKey), github: client}
}

// Handler returns the public HTTP routes available through P1.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /setup", s.setup)
	mux.HandleFunc("POST /setup/github-app", s.createGitHubApp)
	mux.HandleFunc("GET /setup/github-app/callback", s.githubAppCallback)
	mux.HandleFunc("GET /auth/github/start", s.githubAuthStart)
	mux.HandleFunc("GET /auth/github/callback", s.githubAuthCallback)
	mux.HandleFunc("POST /api/v1/github/webhook", s.githubWebhook)
	return mux
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
	session := setupSession{User: user, Organizations: organizations, CSRFToken: csrf, ExpiresAt: time.Now().UTC().Add(15 * time.Minute)}
	if !s.writeCookie(w, setupCookie, session, 15*time.Minute) {
		http.Error(w, "could not complete GitHub sign-in", http.StatusInternalServerError)
		return
	}
	s.clearCookie(w, oauthStateCookie)
	http.Redirect(w, r, "/setup", http.StatusFound)
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
		if publication.CheckRunID > 0 || publication.CommentID > 0 {
			_ = store.SaveReadinessPublication(ctx, pull.Repository.GitHubRepoID, pull.Number, publication.CheckRunID, publication.CommentID)
		}
		return err
	}
	return store.SaveReadinessPublication(ctx, pull.Repository.GitHubRepoID, pull.Number, publication.CheckRunID, publication.CommentID)
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
	ExpiresAt time.Time `json:"expires_at"`
}

func (s oauthState) Expired() bool { return time.Now().UTC().After(s.ExpiresAt) }

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
var manifestPostTemplate = template.Must(template.New("manifest").Parse(`<!doctype html><html lang="en"><body><form id="github-app-manifest" method="post" action="{{.Action}}"><input type="hidden" name="manifest" value="{{.Manifest}}"></form><p>Redirecting to GitHub to create your App…</p><script>document.getElementById('github-app-manifest').submit()</script></body></html>`))

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
