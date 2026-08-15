package server

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/store/sqlite"
)

const dashboardCookie = "localenv_dashboard"

type dashboardStore interface {
	DashboardOrganization(context.Context) (githubapp.Organization, error)
	DashboardRepositories(context.Context) ([]sqlite.DashboardRepository, error)
	DashboardRepository(context.Context, string, string) (sqlite.DashboardRepository, error)
	DashboardPullRequest(context.Context, string, string, int) (sqlite.DashboardPullRequest, error)
	DashboardDevices(context.Context) ([]sqlite.RepositoryDevice, error)
	DashboardAuditEvents(context.Context, int) ([]sqlite.AuditEvent, error)
}

type dashboardSession struct {
	User           githubapp.User `json:"user"`
	OrganizationID int64          `json:"organization_id"`
	ExpiresAt      time.Time      `json:"expires_at"`
}

func (s dashboardSession) Expired() bool { return time.Now().UTC().After(s.ExpiresAt) }

func (s *Server) dashboardLogin(w http.ResponseWriter, r *http.Request) {
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
	s.renderDashboard(w, dashboardPage{Title: "Repositories", User: session.User.Login, Repositories: repositories})
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
	s.renderDashboard(w, dashboardPage{Title: repository.Owner + "/" + repository.Name, User: session.User.Login, Repository: &repository})
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
	s.renderDashboard(w, dashboardPage{Title: fmt.Sprintf("PR #%d", pull.Number), User: session.User.Login, PullRequest: &pull, Owner: r.PathValue("owner"), Repo: r.PathValue("repo")})
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
	s.renderDashboard(w, dashboardPage{Title: "Devices", User: session.User.Login, Devices: devices})
}

func (s *Server) dashboardAudit(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	events, err := store.DashboardAuditEvents(r.Context(), 100)
	if err != nil {
		http.Error(w, "dashboard data is unavailable", http.StatusServiceUnavailable)
		return
	}
	view := make([]dashboardAuditEvent, 0, len(events))
	for _, event := range events {
		metadata := make([]dashboardMetadata, 0, len(event.Metadata))
		for key, value := range event.Metadata {
			metadata = append(metadata, dashboardMetadata{Key: key, Value: value})
		}
		sort.Slice(metadata, func(i, j int) bool { return metadata[i].Key < metadata[j].Key })
		view = append(view, dashboardAuditEvent{AuditEvent: event, Metadata: metadata})
	}
	s.renderDashboard(w, dashboardPage{Title: "Audit", User: session.User.Login, AuditEvents: view})
}

func (s *Server) dashboardSettings(w http.ResponseWriter, r *http.Request) {
	_, session, ok := s.requireDashboard(w, r)
	if !ok {
		return
	}
	s.renderDashboard(w, dashboardPage{Title: "Settings", User: session.User.Login, PublicURL: s.config.PublicURL.String(), DisplayName: s.config.DisplayName})
}

type dashboardMetadata struct{ Key, Value string }
type dashboardAuditEvent struct {
	sqlite.AuditEvent
	Metadata []dashboardMetadata
}
type dashboardPage struct {
	Title        string
	User         string
	Repositories []sqlite.DashboardRepository
	Repository   *sqlite.DashboardRepository
	PullRequest  *sqlite.DashboardPullRequest
	Devices      []sqlite.RepositoryDevice
	AuditEvents  []dashboardAuditEvent
	Owner        string
	Repo         string
	PublicURL    string
	DisplayName  string
}

var dashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{"formatTime": func(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	return value.UTC().Format(time.RFC3339)
}, "number": strconv.Itoa}).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{.Title}} · local.env</title></head><body><header><a href="/repos">local.env</a> · {{.User}} <nav><a href="/repos">Repositories</a> <a href="/devices">Devices</a> <a href="/audit">Audit</a> <a href="/settings">Settings</a></nav></header><main><h1>{{.Title}}</h1>{{if .Repositories}}<ul>{{range .Repositories}}<li><a href="/repos/{{.Owner}}/{{.Name}}">{{.Owner}}/{{.Name}}</a> — revision {{.Revision}}, {{.ManagedKeyCount}} encrypted managed keys, {{.OpenPullRequestCnt}} open PRs</li>{{end}}</ul>{{else if .Repository}}<p>Repository: {{.Repository.Owner}}/{{.Repository.Name}}</p><p>Current baseline revision: {{.Repository.Revision}} · Active key epoch: {{.Repository.ActiveKeyEpoch}} · Managed keys: {{.Repository.ManagedKeyCount}}</p><h2>Files</h2><ul>{{range .Repository.Files}}<li>Schema: {{.SchemaPath}} → Target: {{.TargetPath}}</li>{{end}}</ul><h2>Open PRs with env changes</h2><ul>{{range .Repository.OpenPullRequests}}<li><a href="/repos/{{$.Repository.Owner}}/{{$.Repository.Name}}/pulls/{{.Number}}">PR #{{.Number}}</a> ({{.State}})</li>{{else}}<li>None</li>{{end}}</ul><p>Secret plaintext is never shown in this dashboard.</p>{{else if .PullRequest}}<p><a href="/repos/{{.Owner}}/{{.Repo}}">{{.Owner}}/{{.Repo}}</a></p><p>PR #{{.PullRequest.Number}} — {{.PullRequest.State}}</p><table><thead><tr><th>Key</th><th>State</th></tr></thead><tbody>{{range .PullRequest.Requirements}}<tr><td>{{.KeyName}}</td><td>{{.State}}</td></tr>{{else}}<tr><td colspan="2">No environment requirements.</td></tr>{{end}}</tbody></table><p>Resolve missing keys using <code>localenv resolve</code>. This UI never accepts secret values.</p>{{else if .Devices}}<table><thead><tr><th>User</th><th>Device</th><th>Fingerprint</th><th>Active repo key</th></tr></thead><tbody>{{range .Devices}}<tr><td>{{.GitHubLogin}}</td><td>{{.Name}}</td><td>{{.Fingerprint}}</td><td>{{.HasKey}}</td></tr>{{end}}</tbody></table>{{else if .AuditEvents}}<table><thead><tr><th>Time</th><th>Event</th><th>Actor device</th><th>Metadata</th></tr></thead><tbody>{{range .AuditEvents}}<tr><td>{{formatTime .CreatedAt}}</td><td>{{.EventType}}</td><td>{{.ActorDeviceID}}</td><td>{{range .Metadata}}{{.Key}}={{.Value}} {{end}}</td></tr>{{end}}</tbody></table>{{else if .PublicURL}}<p>Instance: {{.DisplayName}}</p><p>Public URL: {{.PublicURL}}</p><p>Telemetry: disabled; this self-hosted build has no phone-home behavior.</p><p>Secrets are managed only by the CLI; dashboard configuration contains no secret editor.</p>{{else}}<p>No managed repositories have been discovered yet.</p>{{end}}</main></body></html>`))

func (s *Server) renderDashboard(w http.ResponseWriter, page dashboardPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = dashboardTemplate.Execute(w, page)
}
