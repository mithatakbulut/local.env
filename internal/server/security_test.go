package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"html"
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

func TestBrandingCSPAllowsOnlyConfiguredHTTPSImageOrigins(t *testing.T) {
	app := New(config.Config{
		PublicURL:  mustURL(t, "https://env.example.test"),
		LogoURL:    mustURL(t, "https://brand.example.test/logo.svg"),
		FaviconURL: mustURL(t, "https://brand.example.test/favicon.ico"),
	}, testStore{})
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	policy := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self'") || !strings.Contains(policy, "style-src 'self'") || !strings.Contains(policy, "font-src 'self'") || !strings.Contains(policy, "img-src 'self' https://brand.example.test") || strings.Contains(policy, "https://unapproved.example.test") {
		t.Fatalf("branding CSP = %q", policy)
	}
}

func TestDashboardShellRendersOnlyApprovedBrandingMetadata(t *testing.T) {
	app := New(config.Config{
		PublicURL:   mustURL(t, "https://env.example.test"),
		DisplayName: "Acme Local Env",
		LogoURL:     mustURL(t, "https://brand.example.test/logo.svg"),
		FaviconURL:  mustURL(t, "https://brand.example.test/favicon.ico"),
	}, testStore{})
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/setup", nil))
	body := html.UnescapeString(response.Body.String())
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(body, `id="dashboard-shell"`) || !strings.Contains(body, `Acme Local Env`) || !strings.Contains(body, `https://brand.example.test/logo.svg`) || !strings.Contains(body, `https://brand.example.test/favicon.ico`) || !strings.Contains(body, `/assets/index-`) {
		t.Fatalf("setup shell = %d %q", response.Code, body)
	}
	if strings.Contains(body, "<script>") || strings.Contains(body, "style=") || strings.Contains(body, "http://") {
		t.Fatalf("setup shell contained unsafe executable or branding markup: %q", body)
	}
}

func TestDashboardShellWithoutBrandingUsesOnlySelfHostedAssets(t *testing.T) {
	app := New(config.Config{PublicURL: mustURL(t, "https://env.example.test")}, testStore{})
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/setup", nil))
	body := html.UnescapeString(response.Body.String())
	policy := response.Header().Get("Content-Security-Policy")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(body, `"display_name":"local.env"`) || strings.Contains(body, `"logo_url":"https://`) || strings.Contains(body, `rel="icon"`) || !strings.Contains(body, `/assets/index-`) {
		t.Fatalf("unbranded setup shell = %d %q", response.Code, body)
	}
	if strings.Contains(policy, "img-src 'self' https://") || !strings.Contains(policy, "img-src 'self'") || !strings.Contains(policy, "script-src 'self'") || !strings.Contains(policy, "style-src 'self'") || !strings.Contains(policy, "font-src 'self'") {
		t.Fatalf("unbranded dashboard CSP = %q", policy)
	}
}

func TestBrandingURLStringRejectsUnsafeDirectConfig(t *testing.T) {
	unsafe := mustURL(t, "http://brand.example.test/logo.svg")
	if got := brandingURLString(unsafe); got != "" {
		t.Fatalf("unsafe branding URL = %q", got)
	}
}

func TestDashboardAssetsAreEmbeddedHashedAndImmutable(t *testing.T) {
	assets, err := dashboardAssetNames()
	if err != nil || len(assets) == 0 {
		t.Fatalf("embedded dashboard assets = %#v, %v", assets, err)
	}
	app := New(config.Config{PublicURL: mustURL(t, "https://env.example.test")}, testStore{})
	asset := httptest.NewRecorder()
	app.Handler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/assets/"+assets[0], nil))
	if asset.Code != http.StatusOK || asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || asset.Header().Get("Content-Type") == "" || asset.Body.Len() == 0 {
		t.Fatalf("asset response = %d, headers=%#v, bytes=%d", asset.Code, asset.Header(), asset.Body.Len())
	}
	for _, requestPath := range []string{"/assets/", "/assets/not-hashed.js", "/assets/../dashboard.go"} {
		blocked := httptest.NewRecorder()
		app.Handler().ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if blocked.Code != http.StatusNotFound {
			t.Fatalf("unsafe asset %q = %d, want 404", requestPath, blocked.Code)
		}
	}
}

func TestUnsafeAssetRequestPath(t *testing.T) {
	for _, requestPath := range []string{"/assets/../dashboard.go", "/assets/./index.js", "/assets/nested/../../dashboard.go"} {
		if !unsafeAssetRequestPath(requestPath) {
			t.Fatalf("unsafe asset path %q was accepted", requestPath)
		}
	}
	for _, requestPath := range []string{"/repos/acme/api", "/assets/index-CScqf1x0.js", "/assets/"} {
		if unsafeAssetRequestPath(requestPath) {
			t.Fatalf("safe path %q was rejected", requestPath)
		}
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
	repository, err := store.DashboardRepository(ctx, "acme", "api")
	if err != nil || repository.OpenPullRequestCnt != 1 || repository.MissingRequirementCnt != 1 || len(repository.OpenPullRequests) != 1 || repository.OpenPullRequests[0].MissingRequirementCnt != 1 {
		t.Fatalf("dashboard readiness summary = %#v, %v", repository, err)
	}
	const browserSentinel = "D5-NON-SECRET-BROWSER-SENTINEL"
	var logs bytes.Buffer
	app := NewWithGitHubClientAndLogger(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), DisplayName: "Acme Local Env", GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.DefaultClient(), slog.New(slog.NewTextHandler(&logs, nil)))
	for _, requestPath := range []string{"/repos", "/repos/acme/api", "/repos/acme/api/pulls/12", "/devices", "/audit", "/api/v1/dashboard/audit", "/settings"} {
		unauthenticated := httptest.NewRecorder()
		app.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if unauthenticated.Code != http.StatusFound || unauthenticated.Header().Get("Location") != "/login" {
			t.Fatalf("unauthenticated dashboard %q = %d %q", requestPath, unauthenticated.Code, unauthenticated.Header().Get("Location"))
		}
	}
	cookieResponse := httptest.NewRecorder()
	if !app.writeCookie(cookieResponse, dashboardCookie, dashboardSession{User: githubapp.User{ID: 11, Login: "admin"}, OrganizationID: 7, CSRFToken: "non-secret-dashboard-csrf", ExpiresAt: time.Now().UTC().Add(time.Hour)}, time.Hour) {
		t.Fatal("write dashboard cookie")
	}
	cookie := cookieNamed(t, cookieResponse.Result().Cookies(), dashboardCookie)
	for _, pageCase := range []struct {
		path string
		kind string
	}{
		{path: "/repos", kind: `"kind":"repositories"`},
		{path: "/repos/acme/api", kind: `"kind":"repository"`},
		{path: "/repos/acme/api/pulls/12", kind: `"kind":"pull_request"`},
		{path: "/devices", kind: `"kind":"devices"`},
		{path: "/audit", kind: `"kind":"audit"`},
		{path: "/settings", kind: `"kind":"settings"`},
	} {
		pageRequest := httptest.NewRequest(http.MethodGet, pageCase.path, nil)
		pageRequest.AddCookie(cookie)
		page := httptest.NewRecorder()
		app.Handler().ServeHTTP(page, pageRequest)
		body, err := io.ReadAll(page.Result().Body)
		if err != nil {
			t.Fatal(err)
		}
		pageBody := html.UnescapeString(string(body))
		if page.Code != http.StatusOK || page.Header().Get("Cache-Control") != "no-store" || !strings.Contains(pageBody, pageCase.kind) || !strings.Contains(pageBody, `"csrf_token":"non-secret-dashboard-csrf"`) || strings.Contains(pageBody, browserSentinel) || strings.Contains(pageBody, "ciphertext") || strings.Contains(pageBody, "wrapped_rek") || strings.Contains(pageBody, "secret_value") {
			t.Fatalf("dashboard page %q = %d %q", pageCase.path, page.Code, body)
		}
	}
	auditRequest := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/audit", nil)
	auditRequest.AddCookie(cookie)
	auditResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(auditResponse, auditRequest)
	if auditResponse.Code != http.StatusOK || !strings.Contains(auditResponse.Body.String(), `"events"`) || strings.Contains(auditResponse.Body.String(), browserSentinel) || strings.Contains(auditResponse.Body.String(), "ciphertext") || auditResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("dashboard audit page = %d %q", auditResponse.Code, auditResponse.Body.String())
	}

	// The sentinel stands in for sensitive browser input. It is intentionally
	// non-secret and must never be reflected by API responses or request logs.
	if err := store.CreateSession(ctx, githubapp.User{ID: 11, Login: "admin"}, browserSentinel, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, requestPath := range []string{"/api/v1/me", "/api/v1/devices"} {
		request := httptest.NewRequest(http.MethodGet, requestPath, nil)
		request.Header.Set("Authorization", "Bearer "+browserSentinel)
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), browserSentinel) {
			t.Fatalf("dashboard API %q = %d %q", requestPath, response.Code, response.Body.String())
		}
	}
	if strings.Contains(logs.String(), browserSentinel) {
		t.Fatalf("dashboard request logs reflected browser sentinel: %q", logs.String())
	}
	wrongOrigin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/exchange", strings.NewReader(`{}`))
	wrongOrigin.Header.Set("Origin", "https://other.example.test")
	blocked := httptest.NewRecorder()
	app.Handler().ServeHTTP(blocked, wrongOrigin)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("cross-origin mutation = %d", blocked.Code)
	}
}

func TestDashboardLogoutClearsTheLocalSessionAndRequiresCSRF(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.ConfigureGitHubInstance(context.Background(), 7, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	app := New(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store)
	cookieResponse := httptest.NewRecorder()
	if !app.writeCookie(cookieResponse, dashboardCookie, dashboardSession{User: githubapp.User{ID: 11, Login: "member"}, OrganizationID: 7, CSRFToken: "non-secret-dashboard-csrf", ExpiresAt: time.Now().UTC().Add(time.Hour)}, time.Hour) {
		t.Fatal("write dashboard cookie")
	}
	cookie := cookieNamed(t, cookieResponse.Result().Cookies(), dashboardCookie)

	missingCSRF := httptest.NewRequest(http.MethodPost, "/logout", nil)
	missingCSRF.AddCookie(cookie)
	missingCSRFResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(missingCSRFResponse, missingCSRF)
	if missingCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF = %d, want 403", missingCSRFResponse.Code)
	}

	wrongOrigin := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token=non-secret-dashboard-csrf"))
	wrongOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongOrigin.Header.Set("Origin", "https://other.example.test")
	wrongOrigin.AddCookie(cookie)
	wrongOriginResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(wrongOriginResponse, wrongOrigin)
	if wrongOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin logout = %d, want 403", wrongOriginResponse.Code)
	}

	logout := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token=non-secret-dashboard-csrf"))
	logout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logout.AddCookie(cookie)
	logoutResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusSeeOther || logoutResponse.Header().Get("Location") != "/login?logged_out=1" {
		t.Fatalf("dashboard logout = %d %q", logoutResponse.Code, logoutResponse.Header().Get("Location"))
	}
	cleared := strings.Join(logoutResponse.Header().Values("Set-Cookie"), "\n")
	if !strings.Contains(cleared, "localenv_dashboard=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax") {
		t.Fatalf("dashboard cookie was not safely cleared: %q", cleared)
	}

	signedOut := httptest.NewRecorder()
	app.Handler().ServeHTTP(signedOut, httptest.NewRequest(http.MethodGet, "/login?logged_out=1", nil))
	if signedOut.Code != http.StatusOK || !strings.Contains(html.UnescapeString(signedOut.Body.String()), `"kind":"signed_out"`) || strings.Contains(signedOut.Body.String(), "non-secret-dashboard-csrf") {
		t.Fatalf("signed-out page = %d %q", signedOut.Code, signedOut.Body.String())
	}

	unauthenticated := httptest.NewRecorder()
	app.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/repos", nil))
	if unauthenticated.Code != http.StatusFound || unauthenticated.Header().Get("Location") != "/login" {
		t.Fatalf("dashboard after logout = %d %q", unauthenticated.Code, unauthenticated.Header().Get("Location"))
	}
}

func TestDashboardLoginRejectsUsersWithoutConfiguredRepositoryWriteAccess(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.ConfigureGitHubInstance(context.Background(), 7, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ProcessGitHubWebhook(context.Background(), githubapp.WebhookEvent{DeliveryID: "installation-1", EventType: "installation", InstallationID: 9, InstallationOrgID: 7, InstallationOrgLogin: "acme", RepositoriesAdded: []githubapp.Repository{{GitHubRepoID: 42, Owner: "acme", Name: "api", DefaultBranch: "main"}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRepositoryConfigSnapshot(context.Background(), sqlite.RepositoryConfigSnapshot{GitHubRepoID: 42, Owner: "acme", Name: "api", DefaultBranch: "main", Files: []sqlite.RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}}); err != nil {
		t.Fatal(err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_, _ = w.Write([]byte(`{"access_token":"oauth-token"}`))
		case "/user":
			_, _ = w.Write([]byte(`{"id":11,"login":"outsider"}`))
		case "/app/installations/9/access_tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"installation-token"}`))
		case "/repos/acme/api/collaborators/outsider/permission":
			_, _ = w.Write([]byte(`{"permission":"read"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)
	app := NewWithGitHubClient(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), GitHubOAuthClientID: "client", GitHubOAuthClientSecret: "non-secret-test", GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.Client{HTTPClient: github.Client(), APIBaseURL: github.URL, OAuthURL: github.URL + "/login/oauth"})
	if err := app.credentials.Save(githubapp.Credentials{AppID: 9, ClientID: "test-client", ClientSecret: "non-secret-test-client-secret", PrivateKeyPEM: privateKeyPEM, WebhookSecret: "non-secret-test-webhook-secret"}); err != nil {
		t.Fatal(err)
	}
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
		t.Fatalf("repository-read dashboard callback = %d %q", response.Code, response.Body.String())
	}
}

func TestDashboardLoginUsesConfiguredRepositoryWriteAccess(t *testing.T) {
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.ConfigureGitHubInstance(context.Background(), 7, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ProcessGitHubWebhook(context.Background(), githubapp.WebhookEvent{DeliveryID: "installation-1", EventType: "installation", InstallationID: 9, InstallationOrgID: 7, InstallationOrgLogin: "acme", RepositoriesAdded: []githubapp.Repository{{GitHubRepoID: 42, Owner: "acme", Name: "api", DefaultBranch: "main"}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRepositoryConfigSnapshot(context.Background(), sqlite.RepositoryConfigSnapshot{GitHubRepoID: 42, Owner: "acme", Name: "api", DefaultBranch: "main", Files: []sqlite.RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}}); err != nil {
		t.Fatal(err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_, _ = w.Write([]byte(`{"access_token":"oauth-token"}`))
		case "/user":
			_, _ = w.Write([]byte(`{"id":11,"login":"member"}`))
		case "/app/installations/9/access_tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"installation-token"}`))
		case "/repos/acme/api/collaborators/member/permission":
			_, _ = w.Write([]byte(`{"permission":"write"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)
	app := NewWithGitHubClient(config.Config{DataDir: t.TempDir(), PublicURL: mustURL(t, "https://env.example.test"), GitHubOAuthClientID: "client", GitHubOAuthClientSecret: "non-secret-test", GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.Client{HTTPClient: github.Client(), APIBaseURL: github.URL, OAuthURL: github.URL + "/login/oauth"})
	if err := app.credentials.Save(githubapp.Credentials{AppID: 9, ClientID: "test-client", ClientSecret: "non-secret-test-client-secret", PrivateKeyPEM: privateKeyPEM, WebhookSecret: "non-secret-test-webhook-secret"}); err != nil {
		t.Fatal(err)
	}
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
