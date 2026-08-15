package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/localenv/localenv/internal/config"
	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/internal/store/sqlite"
)

func TestSecurityMiddlewareSetsHeadersRedactsRequestDataAndLimitsAuthentication(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var logs bytes.Buffer
	app := NewWithGitHubClientAndLogger(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test")}, store, githubapp.DefaultClient(), slog.New(slog.NewTextHandler(&logs, nil)))
	sentinel := "P11-LOG-SECRET-SENTINEL"
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/exchange", strings.NewReader(`{"code":"`+sentinel+`"}`))
	request.Header.Set("Authorization", "Bearer "+sentinel)
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Strict-Transport-Security") == "" || response.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("security headers missing: %#v", response.Header())
	}
	if output := logs.String(); strings.Contains(output, sentinel) || strings.Contains(output, "body") || !strings.Contains(output, "request_id=") {
		t.Fatalf("request logs exposed unsafe data: %q", output)
	}
	for index := 0; index < 21; index++ {
		response = httptest.NewRecorder()
		app.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/exchange", strings.NewReader(`{}`)))
	}
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("authentication rate limit = %d, headers=%#v", response.Code, response.Header())
	}
}

func TestGitHubPublicationFailureLogsOnlySafeStatusMetadata(t *testing.T) {
	var logs bytes.Buffer
	app := NewWithGitHubClientAndLogger(config.Config{}, testStore{}, githubapp.DefaultClient(), slog.New(slog.NewTextHandler(&logs, nil)))
	app.logGitHubPublicationFailure(&githubapp.HTTPError{Operation: "issue_comment", StatusCode: http.StatusForbidden, PermissionRequirement: "issues_write", GrantedPermissions: "issues_write"})
	if output := logs.String(); !strings.Contains(output, "github_operation=issue_comment") || !strings.Contains(output, "github_status=403") || !strings.Contains(output, "github_status_class=forbidden") || !strings.Contains(output, "github_permission_requirement=issues_write") || !strings.Contains(output, "github_granted_permissions=issues_write") || strings.Contains(output, "error=") {
		t.Fatalf("GitHub failure log = %q", output)
	}
}

func TestDashboardPagesRequireSignedOrganizationSessionAndExposeOnlyMetadata(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.ConfigureGitHubInstance(ctx, 7, "acme", 9, "https://env.example.test", "Acme Local Env"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRepositoryConfigSnapshot(ctx, sqlite.RepositoryConfigSnapshot{GitHubRepoID: 42, Owner: "acme", Name: "api", DefaultBranch: "main", Files: []sqlite.RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}}); err != nil {
		t.Fatal(err)
	}
	pull := githubapp.PullRequest{Number: 12, Repository: githubapp.Repository{GitHubRepoID: 42, Owner: "acme", Name: "api"}, State: "open", HeadSHA: "head", BaseSHA: "base", AuthorID: 11}
	if _, err := store.SavePullRequestRequirements(ctx, pull, []pranalysis.Requirement{{FileID: pranalysis.FileID(42, ".env.example", ".env.local"), KeyName: "P11_DASHBOARD_KEY", State: pranalysis.StateMissing}}); err != nil {
		t.Fatal(err)
	}
	app := New(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), DisplayName: "Acme Local Env", GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store)
	unauthenticated := httptest.NewRecorder()
	app.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/repos", nil))
	if unauthenticated.Code != http.StatusFound || unauthenticated.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated dashboard = %d %q", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}
	cookieResponse := httptest.NewRecorder()
	if !app.writeCookie(cookieResponse, dashboardCookie, dashboardSession{User: githubapp.User{ID: 11, Login: "admin"}, OrganizationID: 7, ExpiresAt: time.Now().UTC().Add(time.Hour)}, time.Hour) {
		t.Fatal("write dashboard cookie")
	}
	cookie := cookieNamed(t, cookieResponse.Result().Cookies(), dashboardCookie)
	pageRequest := httptest.NewRequest(http.MethodGet, "/repos/acme/api/pulls/12", nil)
	pageRequest.AddCookie(cookie)
	page := httptest.NewRecorder()
	app.Handler().ServeHTTP(page, pageRequest)
	body, err := io.ReadAll(page.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if page.Code != http.StatusOK || !strings.Contains(string(body), "P11_DASHBOARD_KEY") || strings.Contains(string(body), "ciphertext") {
		t.Fatalf("dashboard PR page = %d %q", page.Code, body)
	}
	wrongOrigin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/exchange", strings.NewReader(`{}`))
	wrongOrigin.Header.Set("Origin", "https://other.example.test")
	blocked := httptest.NewRecorder()
	app.Handler().ServeHTTP(blocked, wrongOrigin)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("cross-origin mutation = %d", blocked.Code)
	}
}

func TestDashboardLoginRejectsUsersOutsideConfiguredOrganization(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.ConfigureGitHubInstance(context.Background(), 7, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_, _ = w.Write([]byte(`{"access_token":"oauth-token"}`))
		case "/user":
			_, _ = w.Write([]byte(`{"id":11,"login":"outsider"}`))
		case "/orgs/acme/members/outsider":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)
	app := NewWithGitHubClient(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), GitHubOAuthClientID: "client", GitHubOAuthClientSecret: "non-secret-test", GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.Client{HTTPClient: github.Client(), APIBaseURL: github.URL, OAuthURL: github.URL + "/login/oauth"})
	start := httptest.NewRecorder()
	app.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/login", nil))
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callback.AddCookie(cookieNamed(t, start.Result().Cookies(), oauthStateCookie))
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, callback)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "outsider") || strings.Contains(response.Body.String(), "oauth-token") {
		t.Fatalf("non-member dashboard callback = %d %q", response.Code, response.Body.String())
	}
}

func TestDashboardLoginUsesActiveOrganizationMembership(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.ConfigureGitHubInstance(context.Background(), 7, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_, _ = w.Write([]byte(`{"access_token":"oauth-token"}`))
		case "/user":
			_, _ = w.Write([]byte(`{"id":11,"login":"member"}`))
		case "/orgs/acme/members/member":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)
	app := NewWithGitHubClient(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), GitHubOAuthClientID: "client", GitHubOAuthClientSecret: "non-secret-test", GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.Client{HTTPClient: github.Client(), APIBaseURL: github.URL, OAuthURL: github.URL + "/login/oauth"})
	start := httptest.NewRecorder()
	app.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/login", nil))
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callback.AddCookie(cookieNamed(t, start.Result().Cookies(), oauthStateCookie))
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, callback)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/repos" {
		t.Fatalf("dashboard callback = %d %q, want redirect to /repos", response.Code, response.Header().Get("Location"))
	}
	if cookieNamed(t, response.Result().Cookies(), dashboardCookie) == nil {
		t.Fatal("dashboard callback did not create a dashboard session")
	}
}

func TestDashboardLoginLogsSafeOrganizationMembershipRedirect(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.ConfigureGitHubInstance(context.Background(), 7, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	const oauthToken = "oauth-token-must-not-be-logged"
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_, _ = w.Write([]byte(`{"access_token":"` + oauthToken + `"}`))
		case "/user":
			_, _ = w.Write([]byte(`{"id":11,"login":"member"}`))
		case "/orgs/acme/members/member":
			w.Header().Set("Location", "https://github.com/orgs/acme")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)
	var logs bytes.Buffer
	app := NewWithGitHubClientAndLogger(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), GitHubOAuthClientID: "client", GitHubOAuthClientSecret: "non-secret-test", GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.Client{HTTPClient: github.Client(), APIBaseURL: github.URL, OAuthURL: github.URL + "/login/oauth"}, slog.New(slog.NewTextHandler(&logs, nil)))
	start := httptest.NewRecorder()
	app.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/login", nil))
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callback.AddCookie(cookieNamed(t, start.Result().Cookies(), oauthStateCookie))
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, callback)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), oauthToken) {
		t.Fatalf("dashboard callback = %d %q", response.Code, response.Body.String())
	}
	output := logs.String()
	if !strings.Contains(output, "github_operation=organization_membership") || !strings.Contains(output, "github_status=302") || !strings.Contains(output, "github_status_class=requester_not_organization_member") || strings.Contains(output, oauthToken) || strings.Contains(output, "https://github.com/orgs/acme") {
		t.Fatalf("membership diagnostic log = %q", output)
	}
}
