package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/store/sqlite"
)

const dashboardCookie = "localenv_dashboard"

const dashboardAuditPageSize = 20

type dashboardStore interface {
	DashboardOrganization(context.Context) (githubapp.Organization, error)
	DashboardRepositories(context.Context) ([]sqlite.DashboardRepository, error)
	DashboardRepository(context.Context, string, string) (sqlite.DashboardRepository, error)
	DashboardPullRequest(context.Context, string, string, int) (sqlite.DashboardPullRequest, error)
	DashboardDevices(context.Context) ([]sqlite.DashboardDevice, error)
	DashboardAuditEvents(context.Context, *sqlite.AuditCursor, int) (sqlite.AuditEventPage, error)
}

type dashboardSession struct {
	User           githubapp.User `json:"user"`
	OrganizationID int64          `json:"organization_id"`
	CSRFToken      string         `json:"csrf_token"`
	ExpiresAt      time.Time      `json:"expires_at"`
}

func (s dashboardSession) Expired() bool { return time.Now().UTC().After(s.ExpiresAt) }

func (s *Server) dashboardLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("logged_out") == "1" {
		s.renderDashboard(w, r, dashboardPage{Title: "Signed out", SignedOut: true})
		return
	}
	if _, ok := s.store.(dashboardStore); !ok || !s.config.GitHubSetupConfigured() {
		http.Error(w, "dashboard sign-in is unavailable", http.StatusServiceUnavailable)
		return
	}
	clientID, _, ok := s.oauthCredentials()
	if !ok {
		http.Error(w, "GitHub sign-in is unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := randomToken()
	if err != nil || !s.writeCookie(w, oauthStateCookie, oauthState{State: state, Audience: "dashboard", ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, 10*time.Minute) {
		http.Error(w, "could not start dashboard sign-in", http.StatusInternalServerError)
		return
	}
	authorizeURL, err := s.github.AuthorizationURL(clientID, s.publicURL("/auth/github/callback"), state)
	if err != nil {
		http.Error(w, "could not start dashboard sign-in", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// dashboardLogout removes only the local.env dashboard session. GitHub OAuth
// access tokens are used only during the callback and are never persisted, so
// there is no remote credential to revoke here.
func (s *Server) dashboardLogout(w http.ResponseWriter, r *http.Request) {
	_, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	if session.CSRFToken == "" || r.FormValue("csrf_token") == "" || r.FormValue("csrf_token") != session.CSRFToken {
		http.Error(w, "dashboard sign-out could not be verified", http.StatusForbidden)
		return
	}
	s.clearCookie(w, dashboardCookie)
	s.clearCookie(w, oauthStateCookie)
	http.Redirect(w, r, "/login?logged_out=1", http.StatusSeeOther)
}

func (s *Server) requireDashboard(w http.ResponseWriter, r *http.Request) (dashboardStore, dashboardSession, bool) {
	store, ok := s.store.(dashboardStore)
	if !ok {
		http.Error(w, "dashboard is unavailable", http.StatusServiceUnavailable)
		return nil, dashboardSession{}, false
	}
	var session dashboardSession
	if !s.readCookie(r, dashboardCookie, &session) || session.Expired() || session.User.ID <= 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return nil, dashboardSession{}, false
	}
	organization, err := store.DashboardOrganization(r.Context())
	if err != nil || organization.ID != session.OrganizationID {
		s.clearCookie(w, dashboardCookie)
		http.Error(w, "dashboard session is no longer valid", http.StatusForbidden)
		return nil, dashboardSession{}, false
	}
	return store, session, true
}

func (s *Server) dashboardRepositories(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	repositories, err := store.DashboardRepositories(r.Context())
	if err != nil {
		http.Error(w, "dashboard data is unavailable", http.StatusServiceUnavailable)
		return
	}
	s.renderDashboard(w, r, dashboardPage{Title: "Repositories", User: session.User.Login, CSRFToken: session.CSRFToken, RepositoryList: true, Repositories: repositories})
}

func (s *Server) dashboardRepository(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	repository, err := store.DashboardRepository(r.Context(), r.PathValue("owner"), r.PathValue("repo"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.renderDashboard(w, r, dashboardPage{Title: repository.Owner + "/" + repository.Name, User: session.User.Login, CSRFToken: session.CSRFToken, Repository: &repository})
}

func (s *Server) dashboardPullRequest(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	number, err := parsePositivePathInt(r.PathValue("number"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	pull, err := store.DashboardPullRequest(r.Context(), r.PathValue("owner"), r.PathValue("repo"), number)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.renderDashboard(w, r, dashboardPage{Title: fmt.Sprintf("PR #%d", pull.Number), User: session.User.Login, CSRFToken: session.CSRFToken, PullRequest: &pull, Owner: r.PathValue("owner"), Repo: r.PathValue("repo")})
}

func (s *Server) dashboardDevices(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	devices, err := store.DashboardDevices(r.Context())
	if err != nil {
		http.Error(w, "dashboard data is unavailable", http.StatusServiceUnavailable)
		return
	}
	s.renderDashboard(w, r, dashboardPage{Title: "Devices", User: session.User.Login, CSRFToken: session.CSRFToken, DeviceList: true, Devices: devices})
}

func (s *Server) dashboardAudit(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	page, err := store.DashboardAuditEvents(r.Context(), nil, dashboardAuditPageSize)
	if err != nil {
		http.Error(w, "dashboard data is unavailable", http.StatusServiceUnavailable)
		return
	}
	s.renderDashboard(w, r, dashboardPage{Title: "Audit", User: session.User.Login, CSRFToken: session.CSRFToken, AuditList: true, AuditEvents: dashboardAuditEventsFor(page.Events), AuditNextCursor: encodeDashboardAuditCursor(page.NextCursor)})
}

// dashboardAuditPage returns the next cursor-paginated, metadata-only page
// for the infinite-scroll audit view. It uses the same dashboard session and
// organization validation as the HTML route.
func (s *Server) dashboardAuditPage(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	cursor, err := decodeDashboardAuditCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		http.Error(w, "invalid audit cursor", http.StatusBadRequest)
		return
	}
	page, err := store.DashboardAuditEvents(r.Context(), cursor, dashboardAuditPageSize)
	if err != nil {
		http.Error(w, "dashboard data is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, dashboardAuditPageView{Events: dashboardAuditEventViewsFor(page.Events), NextCursor: encodeDashboardAuditCursor(page.NextCursor)})
}

func dashboardAuditEventsFor(events []sqlite.AuditEvent) []dashboardAuditEvent {
	view := make([]dashboardAuditEvent, 0, len(events))
	for _, event := range events {
		metadata := make([]dashboardMetadata, 0, len(event.Metadata))
		for key, value := range event.Metadata {
			metadata = append(metadata, dashboardMetadata{Key: key, Value: value})
		}
		sort.Slice(metadata, func(i, j int) bool { return metadata[i].Key < metadata[j].Key })
		view = append(view, dashboardAuditEvent{AuditEvent: event, Metadata: metadata})
	}
	return view
}

func dashboardAuditEventViewsFor(events []sqlite.AuditEvent) []dashboardAuditEventView {
	internal := dashboardAuditEventsFor(events)
	view := make([]dashboardAuditEventView, 0, len(internal))
	for _, event := range internal {
		view = append(view, dashboardAuditEventViewFor(event))
	}
	return view
}

func encodeDashboardAuditCursor(cursor *sqlite.AuditCursor) string {
	if cursor == nil || cursor.CreatedAt.IsZero() || cursor.ID == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(cursor.CreatedAt.UTC().Format(time.RFC3339Nano) + "\n" + cursor.ID))
}

func decodeDashboardAuditCursor(encoded string) (*sqlite.AuditCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(raw), "\n")
	if len(parts) != 2 || len(parts[1]) == 0 || len(parts[1]) > 128 {
		return nil, fmt.Errorf("malformed audit cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return nil, err
	}
	return &sqlite.AuditCursor{CreatedAt: createdAt, ID: parts[1]}, nil
}

func (s *Server) dashboardSettings(w http.ResponseWriter, r *http.Request) {
	_, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	s.renderDashboard(w, r, dashboardPage{Title: "Settings", User: session.User.Login, CSRFToken: session.CSRFToken, PublicURL: s.config.PublicURL.String(), DisplayName: s.config.DisplayName})
}

type dashboardMetadata struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type dashboardAuditEvent struct {
	sqlite.AuditEvent
	Metadata []dashboardMetadata
}
type dashboardPage struct {
	Title           string
	User            string
	CSRFToken       string
	RepositoryList  bool
	Repositories    []sqlite.DashboardRepository
	Repository      *sqlite.DashboardRepository
	PullRequest     *sqlite.DashboardPullRequest
	DeviceList      bool
	Devices         []sqlite.DashboardDevice
	AuditList       bool
	AuditEvents     []dashboardAuditEvent
	AuditNextCursor string
	Owner           string
	Repo            string
	PublicURL       string
	DisplayName     string
	SignedOut       bool
	FaviconURL      string
	Bootstrap       string
	Stylesheet      string
	Script          string
	ReactView       bool
}

type dashboardBootstrap struct {
	DisplayName string        `json:"display_name"`
	LogoURL     string        `json:"logo_url,omitempty"`
	Path        string        `json:"path"`
	Title       string        `json:"title"`
	User        string        `json:"user"`
	CSRFToken   string        `json:"csrf_token,omitempty"`
	View        dashboardView `json:"view"`
}

// dashboardView is a deliberately narrow browser contract. It contains only
// public repository metadata and readiness state; secret records, ciphertext,
// wrapped keys, sessions, and plaintext are intentionally not representable.
type dashboardView struct {
	Kind            string                    `json:"kind"`
	Repositories    []dashboardRepositoryView `json:"repositories"`
	Repository      *dashboardRepositoryView  `json:"repository,omitempty"`
	PullRequest     *dashboardPullRequestView `json:"pull_request,omitempty"`
	Devices         []dashboardDeviceView     `json:"devices"`
	AuditEvents     []dashboardAuditEventView `json:"audit_events"`
	AuditNextCursor string                    `json:"audit_next_cursor,omitempty"`
	Settings        *dashboardSettingsView    `json:"settings,omitempty"`
	Setup           *dashboardSetupView       `json:"setup,omitempty"`
	Owner           string                    `json:"owner,omitempty"`
	Repo            string                    `json:"repo,omitempty"`
	SignedOut       bool                      `json:"signed_out,omitempty"`
}

type dashboardRepositoryView struct {
	Owner                   string                     `json:"owner"`
	Name                    string                     `json:"name"`
	DefaultBranch           string                     `json:"default_branch"`
	ActiveKeyEpoch          int64                      `json:"active_key_epoch"`
	Revision                int64                      `json:"revision"`
	ManagedKeyCount         int                        `json:"managed_key_count"`
	OpenPullRequestCount    int                        `json:"open_pull_request_count"`
	MissingRequirementCount int                        `json:"missing_requirement_count"`
	Files                   []dashboardFileView        `json:"files"`
	OpenPullRequests        []dashboardPullRequestView `json:"open_pull_requests"`
}

type dashboardFileView struct {
	SchemaPath string `json:"schema_path"`
	TargetPath string `json:"target_path"`
}

type dashboardPullRequestView struct {
	Number                  int                        `json:"number"`
	State                   string                     `json:"state"`
	MissingRequirementCount int                        `json:"missing_requirement_count"`
	Requirements            []dashboardRequirementView `json:"requirements"`
}

type dashboardRequirementView struct {
	KeyName string `json:"key_name"`
	State   string `json:"state"`
}

type dashboardDeviceView struct {
	ID          string `json:"id"`
	GitHubLogin string `json:"github_login"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
	LastSeenAt  string `json:"last_seen_at"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	HasKey      bool   `json:"has_key"`
}

type dashboardAuditEventView struct {
	EventType     string              `json:"event_type"`
	ActorDeviceID string              `json:"actor_device_id"`
	Metadata      []dashboardMetadata `json:"metadata"`
	CreatedAt     string              `json:"created_at"`
}

type dashboardAuditPageView struct {
	Events     []dashboardAuditEventView `json:"events"`
	NextCursor string                    `json:"next_cursor,omitempty"`
}

type dashboardSettingsView struct {
	PublicURL string `json:"public_url"`
}

// dashboardSetupView carries only the existing setup page's display values
// and normal-form inputs. Its CSRF token is already rendered in the HTML form
// contract and remains verified against the signed setup cookie by Go.
type dashboardSetupView struct {
	State          string                        `json:"state"`
	SignInURL      string                        `json:"sign_in_url,omitempty"`
	CSRFToken      string                        `json:"csrf_token,omitempty"`
	Organizations  []dashboardOrganizationView   `json:"organizations"`
	AppURL         string                        `json:"app_url,omitempty"`
	Repositories   []dashboardDiscoveredRepoView `json:"repositories"`
	ManifestAction string                        `json:"manifest_action,omitempty"`
	Manifest       string                        `json:"manifest,omitempty"`
}

type dashboardOrganizationView struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type dashboardDiscoveredRepoView struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} · {{.DisplayName}}</title>
  {{if .FaviconURL}}<link rel="icon" href="{{.FaviconURL}}">{{end}}
  <link rel="stylesheet" href="/assets/{{.Stylesheet}}">
</head>
<body>
  <div id="dashboard-shell" data-dashboard="{{.Bootstrap}}"></div>
  <main id="dashboard-content" tabindex="-1"><div id="dashboard-page"></div></main>
  <script type="module" src="/assets/{{.Script}}"></script>
</body>
</html>`))

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, page dashboardPage) {
	assets, err := dashboardShellAssets()
	if err != nil {
		http.Error(w, "dashboard assets are unavailable", http.StatusServiceUnavailable)
		return
	}
	page.DisplayName = dashboardDisplayName(s.config.DisplayName)
	logoURL := brandingURLString(s.config.LogoURL)
	view := dashboardViewForPage(page)
	bootstrap, err := json.Marshal(dashboardBootstrap{DisplayName: page.DisplayName, LogoURL: logoURL, Path: r.URL.Path, Title: page.Title, User: page.User, CSRFToken: page.CSRFToken, View: view})
	if err != nil {
		http.Error(w, "dashboard metadata is unavailable", http.StatusInternalServerError)
		return
	}
	page.Bootstrap = string(bootstrap)
	page.ReactView = true
	page.FaviconURL = brandingURLString(s.config.FaviconURL)
	page.Stylesheet = assets.Stylesheet
	page.Script = assets.Script
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if page.CSRFToken != "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	_ = dashboardTemplate.Execute(w, page)
}

func dashboardViewForPage(page dashboardPage) dashboardView {
	switch {
	case page.SignedOut:
		return dashboardView{Kind: "signed_out", SignedOut: true}
	case page.RepositoryList:
		view := dashboardView{Kind: "repositories", Repositories: make([]dashboardRepositoryView, 0, len(page.Repositories))}
		for _, repository := range page.Repositories {
			view.Repositories = append(view.Repositories, dashboardRepositoryViewFor(repository))
		}
		return view
	case page.Repository != nil:
		return dashboardView{Kind: "repository", Repository: dashboardRepositoryViewPtr(*page.Repository)}
	case page.PullRequest != nil:
		return dashboardView{Kind: "pull_request", PullRequest: dashboardPullRequestViewPtr(*page.PullRequest), Owner: page.Owner, Repo: page.Repo}
	case page.DeviceList:
		view := dashboardView{Kind: "devices", Devices: make([]dashboardDeviceView, 0, len(page.Devices))}
		for _, device := range page.Devices {
			view.Devices = append(view.Devices, dashboardDeviceViewFor(device))
		}
		return view
	case page.AuditList:
		view := dashboardView{Kind: "audit", AuditEvents: make([]dashboardAuditEventView, 0, len(page.AuditEvents)), AuditNextCursor: page.AuditNextCursor}
		for _, event := range page.AuditEvents {
			view.AuditEvents = append(view.AuditEvents, dashboardAuditEventViewFor(event))
		}
		return view
	case page.PublicURL != "":
		return dashboardView{Kind: "settings", Settings: &dashboardSettingsView{PublicURL: page.PublicURL}}
	default:
		return dashboardView{Kind: "legacy"}
	}
}

func dashboardRepositoryViewPtr(repository sqlite.DashboardRepository) *dashboardRepositoryView {
	view := dashboardRepositoryViewFor(repository)
	return &view
}

func dashboardRepositoryViewFor(repository sqlite.DashboardRepository) dashboardRepositoryView {
	view := dashboardRepositoryView{
		Owner: repository.Owner, Name: repository.Name, DefaultBranch: repository.DefaultBranch,
		ActiveKeyEpoch: repository.ActiveKeyEpoch, Revision: repository.Revision,
		ManagedKeyCount: repository.ManagedKeyCount, OpenPullRequestCount: repository.OpenPullRequestCnt,
		MissingRequirementCount: repository.MissingRequirementCnt,
		Files:                   make([]dashboardFileView, 0, len(repository.Files)),
		OpenPullRequests:        make([]dashboardPullRequestView, 0, len(repository.OpenPullRequests)),
	}
	for _, file := range repository.Files {
		view.Files = append(view.Files, dashboardFileView{SchemaPath: file.SchemaPath, TargetPath: file.TargetPath})
	}
	for _, pull := range repository.OpenPullRequests {
		view.OpenPullRequests = append(view.OpenPullRequests, dashboardPullRequestViewFor(pull))
	}
	return view
}

func dashboardPullRequestViewPtr(pull sqlite.DashboardPullRequest) *dashboardPullRequestView {
	view := dashboardPullRequestViewFor(pull)
	return &view
}

func dashboardPullRequestViewFor(pull sqlite.DashboardPullRequest) dashboardPullRequestView {
	view := dashboardPullRequestView{Number: pull.Number, State: pull.State, MissingRequirementCount: pull.MissingRequirementCnt, Requirements: make([]dashboardRequirementView, 0, len(pull.Requirements))}
	for _, requirement := range pull.Requirements {
		view.Requirements = append(view.Requirements, dashboardRequirementView{KeyName: requirement.KeyName, State: requirement.State})
	}
	return view
}

func dashboardDeviceViewFor(device sqlite.DashboardDevice) dashboardDeviceView {
	view := dashboardDeviceView{ID: device.ID, GitHubLogin: device.GitHubLogin, Name: device.Name, Fingerprint: device.Fingerprint, CreatedAt: dashboardTime(device.CreatedAt), LastSeenAt: dashboardTime(device.LastSeenAt), HasKey: device.HasKey}
	if device.RevokedAt != nil {
		view.RevokedAt = dashboardTime(*device.RevokedAt)
	}
	return view
}

func dashboardAuditEventViewFor(event dashboardAuditEvent) dashboardAuditEventView {
	return dashboardAuditEventView{EventType: event.EventType, ActorDeviceID: event.ActorDeviceID, Metadata: event.Metadata, CreatedAt: dashboardTime(event.CreatedAt)}
}

func dashboardTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func dashboardViewForSetup(page setupPage) dashboardView {
	view := dashboardSetupView{Organizations: make([]dashboardOrganizationView, 0, len(page.Organizations)), Repositories: make([]dashboardDiscoveredRepoView, 0, len(page.Repositories))}
	switch {
	case page.ConfigurationRequired:
		view.State = "configuration_required"
	case page.ManifestAction != "":
		view.State, view.ManifestAction, view.Manifest = "manifest_post", page.ManifestAction, page.Manifest
	case page.Complete:
		view.State, view.AppURL = "complete", page.AppURL
	case page.SignInURL != "":
		view.State, view.SignInURL = "sign_in", page.SignInURL
	default:
		view.State, view.CSRFToken = "organization_selection", page.CSRFToken
	}
	for _, organization := range page.Organizations {
		view.Organizations = append(view.Organizations, dashboardOrganizationView{ID: organization.ID, Login: organization.Login})
	}
	for _, repository := range page.Repositories {
		view.Repositories = append(view.Repositories, dashboardDiscoveredRepoView{Owner: repository.Owner, Name: repository.Name})
	}
	return dashboardView{Kind: "setup", Setup: &view}
}

func dashboardDisplayName(value string) string {
	if strings.TrimSpace(value) == "" {
		return "local.env"
	}
	return value
}
