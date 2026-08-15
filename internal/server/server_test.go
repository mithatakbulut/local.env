package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/localenv/localenv/internal/config"
	"github.com/localenv/localenv/internal/cryptokit"
	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/internal/store/sqlite"
)

func TestCLIAuthenticationExchangesOneTimeCodeRegistersDeviceAndRevokesSession(t *testing.T) {
	gitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_, _ = w.Write([]byte(`{"access_token":"test-github-access-token"}`))
		case "/user":
			_, _ = w.Write([]byte(`{"id":31,"login":"developer"}`))
		case "/user/memberships/orgs":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(gitHub.Close)
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	app := NewWithGitHubClient(config.Config{
		DataDir:                           t.TempDir(),
		PublicURL:                         mustURL(t, "https://env.example.test"),
		GitHubOAuthClientID:               "test-client",
		GitHubOAuthClientSecret:           "non-secret-test-client-secret",
		GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32)),
	}, store, githubapp.Client{HTTPClient: gitHub.Client(), APIBaseURL: gitHub.URL, OAuthURL: gitHub.URL + "/login/oauth"})

	start := httptest.NewRecorder()
	app.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/auth/cli/start?redirect_uri=http%3A%2F%2F127.0.0.1%3A43124%2Fcallback", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("CLI auth start = %d, want 302", start.Code)
	}
	state := mustURL(t, start.Header().Get("Location")).Query().Get("state")
	callback := httptest.NewRequest(http.MethodGet, "/auth/cli/callback?code=github-code&state="+url.QueryEscape(state), nil)
	callback.AddCookie(cookieNamed(t, start.Result().Cookies(), cliOAuthStateCookie))
	complete := httptest.NewRecorder()
	app.Handler().ServeHTTP(complete, callback)
	if complete.Code != http.StatusFound {
		t.Fatalf("CLI auth callback = %d, want 302", complete.Code)
	}
	exchangeCode := mustURL(t, complete.Header().Get("Location")).Query().Get("code")
	if exchangeCode == "" {
		t.Fatal("CLI callback did not contain exchange code")
	}
	exchangeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/exchange", strings.NewReader(`{"code":"`+exchangeCode+`"}`))
	exchangeRequest.Header.Set("Content-Type", "application/json")
	exchange := httptest.NewRecorder()
	app.Handler().ServeHTTP(exchange, exchangeRequest)
	if exchange.Code != http.StatusOK {
		t.Fatalf("exchange = %d, body = %s", exchange.Code, exchange.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(exchange.Body.Bytes(), &session); err != nil || session.Token == "" {
		t.Fatalf("exchange session = %#v, %v", session, err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	registration := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(`{"id":"device-1","name":"laptop","public_recipient":"`+identity.Recipient().String()+`","fingerprint":"sha256:0000000000000000"}`))
	registration.Header.Set("Content-Type", "application/json")
	registration.Header.Set("Authorization", "Bearer "+session.Token)
	registered := httptest.NewRecorder()
	app.Handler().ServeHTTP(registered, registration)
	if registered.Code != http.StatusCreated || strings.Contains(registered.Body.String(), session.Token) {
		t.Fatalf("device registration = %d, body = %s", registered.Code, registered.Body.String())
	}
	meRequest := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	meRequest.Header.Set("Authorization", "Bearer "+session.Token)
	me := httptest.NewRecorder()
	app.Handler().ServeHTTP(me, meRequest)
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"login":"developer"`) || !strings.Contains(me.Body.String(), `"id":"device-1"`) || strings.Contains(me.Body.String(), session.Token) {
		t.Fatalf("me = %d, body = %s", me.Code, me.Body.String())
	}
	devicesRequest := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	devicesRequest.Header.Set("Authorization", "Bearer "+session.Token)
	devices := httptest.NewRecorder()
	app.Handler().ServeHTTP(devices, devicesRequest)
	if devices.Code != http.StatusOK || !strings.Contains(devices.Body.String(), `"fingerprint":"sha256:0000000000000000"`) {
		t.Fatalf("devices = %d, body = %s", devices.Code, devices.Body.String())
	}
	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutRequest.Header.Set("Authorization", "Bearer "+session.Token)
	logout := httptest.NewRecorder()
	app.Handler().ServeHTTP(logout, logoutRequest)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", logout.Code)
	}
	after := httptest.NewRecorder()
	app.Handler().ServeHTTP(after, meRequest)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session me = %d, want 401", after.Code)
	}
}

func TestRepositoryBootstrapRequiresGitHubWriteAccessAndStoresOnlyWrappedKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	permission := "write"
	fakeGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/7/access_tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"installation-token"}`))
		case "/repos/acme/api/collaborators/developer/permission", "/repos/acme/api/collaborators/new-developer/permission":
			_, _ = w.Write([]byte(`{"permission":"` + permission + `"}`))
		case "/repos/acme/api/contents/localenv.yaml":
			_, _ = w.Write([]byte(`{"type":"file","encoding":"base64","content":"dmVyc2lvbjogMQpmaWxlczoKICAtIHNjaGVtYTogLmVudi5leGFtcGxlCiAgICB0YXJnZXQ6IC5lbnYubG9jYWwK"}`))
		case "/repos/acme/api/contents/.env.example":
			_, _ = w.Write([]byte(`{"type":"file","encoding":"base64","content":"REFUQUJBU0VfVVJMPQo="}`))
		case "/repos/acme/api/pulls":
			_, _ = w.Write([]byte(`[{"number":100,"head":{"ref":"feature/sync"}}]`))
		case "/repos/acme/api/check-runs":
			_, _ = w.Write([]byte(`{"id":101}`))
		case "/repos/acme/api/issues/100/comments":
			_, _ = w.Write([]byte(`{"id":202}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fakeGitHub.Close)
	store, err := sqlite.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.ConfigureGitHubInstance(ctx, 2, "acme", 9, "https://env.example.test", "local.env"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ProcessGitHubWebhook(ctx, githubapp.WebhookEvent{DeliveryID: "installation-1", EventType: "installation", InstallationID: 7, InstallationOrgID: 2, InstallationOrgLogin: "acme", RepositoriesAdded: []githubapp.Repository{{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main"}}}); err != nil {
		t.Fatal(err)
	}
	user := githubapp.User{ID: 31, Login: "developer"}
	token := "non-secret-test-session"
	if err := store.CreateSession(ctx, user, token, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterDevice(ctx, token, "device-1", "laptop", identity.Recipient().String(), "sha256:0000000000000000"); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	app := NewWithGitHubClient(config.Config{DataDir: dataDir, PublicURL: mustURL(t, "https://env.example.test"), GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.Client{HTTPClient: fakeGitHub.Client(), APIBaseURL: fakeGitHub.URL})
	if err := app.credentials.Save(githubapp.Credentials{AppID: 9, ClientID: "test-client", ClientSecret: "test-client-secret", PrivateKeyPEM: pemKey, WebhookSecret: "test-webhook-secret"}); err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/api/v1/repos/acme/api", nil)
	get.Header.Set("Authorization", "Bearer "+token)
	getRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK || strings.Contains(getRecorder.Body.String(), "wrapped") {
		t.Fatalf("bootstrap state = %d, %s", getRecorder.Code, getRecorder.Body.String())
	}
	// The sentinel is client-only REK material; only its age-wrapped form is
	// sent to the server. SQLite storage is checked in the store test.
	rek := []byte("non-secret-test-rek-sentinel-000")
	wrapped, err := cryptokit.WrapREK(rek, identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		WrappedREK []byte `json:"wrapped_rek"`
	}{wrapped})
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest(http.MethodPost, "/api/v1/repos/acme/api/init", bytes.NewReader(payload))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Authorization", "Bearer "+token)
	postRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusCreated || strings.Contains(postRecorder.Body.String(), string(rek)) {
		t.Fatalf("bootstrap init = %d, %s", postRecorder.Code, postRecorder.Body.String())
	}
	newUser := githubapp.User{ID: 32, Login: "new-developer"}
	newToken := "non-secret-new-device-session"
	if err := store.CreateSession(ctx, newUser, newToken, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	newIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterDevice(ctx, newToken, "device-2", "new laptop", newIdentity.Recipient().String(), "sha256:new-device"); err != nil {
		t.Fatal(err)
	}
	beforeApproval := httptest.NewRequest(http.MethodGet, "/api/v1/repos/acme/api/snapshot", nil)
	beforeApproval.Header.Set("Authorization", "Bearer "+newToken)
	beforeApprovalRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(beforeApprovalRecorder, beforeApproval)
	if beforeApprovalRecorder.Code != http.StatusBadRequest {
		t.Fatalf("unapproved snapshot = %d, want 400", beforeApprovalRecorder.Code)
	}
	accessRequest := httptest.NewRequest(http.MethodPost, "/api/v1/repos/acme/api/device-access-requests", strings.NewReader(`{}`))
	accessRequest.Header.Set("Content-Type", "application/json")
	accessRequest.Header.Set("Authorization", "Bearer "+newToken)
	accessRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(accessRecorder, accessRequest)
	var access struct {
		Code        string `json:"code"`
		Fingerprint string `json:"fingerprint"`
	}
	if accessRecorder.Code != http.StatusCreated || json.Unmarshal(accessRecorder.Body.Bytes(), &access) != nil || access.Code == "" || access.Fingerprint != "sha256:new-device" || strings.Contains(accessRecorder.Body.String(), string(rek)) {
		t.Fatalf("device access request = %d, %s", accessRecorder.Code, accessRecorder.Body.String())
	}
	inspectPayload, _ := json.Marshal(map[string]string{"code": access.Code})
	inspect := httptest.NewRequest(http.MethodPost, "/api/v1/repos/acme/api/device-access-requests/inspect", bytes.NewReader(inspectPayload))
	inspect.Header.Set("Content-Type", "application/json")
	inspect.Header.Set("Authorization", "Bearer "+token)
	inspectRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(inspectRecorder, inspect)
	if inspectRecorder.Code != http.StatusOK || !strings.Contains(inspectRecorder.Body.String(), `"github_login":"new-developer"`) || !strings.Contains(inspectRecorder.Body.String(), `"fingerprint":"sha256:new-device"`) {
		t.Fatalf("device access inspect = %d, %s", inspectRecorder.Code, inspectRecorder.Body.String())
	}
	wrappedForNewDevice, err := cryptokit.WrapREK(rek, newIdentity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	approvePayload, _ := json.Marshal(struct {
		Code       string `json:"code"`
		WrappedREK []byte `json:"wrapped_rek"`
	}{access.Code, wrappedForNewDevice})
	approve := httptest.NewRequest(http.MethodPost, "/api/v1/repos/acme/api/device-access-requests/approve", bytes.NewReader(approvePayload))
	approve.Header.Set("Content-Type", "application/json")
	approve.Header.Set("Authorization", "Bearer "+token)
	approveRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(approveRecorder, approve)
	if approveRecorder.Code != http.StatusNoContent {
		t.Fatalf("device access approval = %d, %s", approveRecorder.Code, approveRecorder.Body.String())
	}
	afterApproval := httptest.NewRequest(http.MethodGet, "/api/v1/repos/acme/api/snapshot", nil)
	afterApproval.Header.Set("Authorization", "Bearer "+newToken)
	afterApprovalRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(afterApprovalRecorder, afterApproval)
	if afterApprovalRecorder.Code != http.StatusOK || strings.Contains(afterApprovalRecorder.Body.String(), string(rek)) {
		t.Fatalf("approved snapshot = %d, %s", afterApprovalRecorder.Code, afterApprovalRecorder.Body.String())
	}
	currentPull := httptest.NewRequest(http.MethodGet, "/api/v1/repos/acme/api/pulls/current?branch=feature%2Fsync", nil)
	currentPull.Header.Set("Authorization", "Bearer "+token)
	currentPullRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(currentPullRecorder, currentPull)
	if currentPullRecorder.Code != http.StatusOK || !strings.Contains(currentPullRecorder.Body.String(), `"number":100`) {
		t.Fatalf("current pull lookup = %d, %s", currentPullRecorder.Code, currentPullRecorder.Body.String())
	}
	cryptoState, err := store.RepositoryCryptoState(ctx, "acme", "api")
	if err != nil {
		t.Fatal(err)
	}
	fileID := pranalysis.FileID(17, ".env.example", ".env.local")
	pull := githubapp.PullRequest{Number: 100, BaseSHA: "base", HeadSHA: "head", AuthorID: user.ID, State: "open", Repository: githubapp.Repository{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main"}}
	if _, err := store.SavePullRequestRequirements(ctx, pull, []pranalysis.Requirement{{FileID: fileID, KeyName: "STRIPE_SECRET_KEY", State: pranalysis.StateMissing}}); err != nil {
		t.Fatal(err)
	}
	envelope, err := cryptokit.Encrypt(rek, []byte("non-secret-pr-value"), cryptokit.AAD{InstanceID: cryptoState.InstanceID, GitHubRepoID: 17, FilePath: ".env.local", KeyName: "STRIPE_SECRET_KEY", Scope: "pull_request", ScopeID: "100", Version: 1, KeyEpoch: cryptoState.ActiveKeyEpoch})
	if err != nil {
		t.Fatal(err)
	}
	updatePayload, err := json.Marshal(struct {
		ExpectedCurrentVersion int64              `json:"expected_current_version"`
		Envelope               cryptokit.Envelope `json:"envelope"`
	}{ExpectedCurrentVersion: 0, Envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	update := httptest.NewRequest(http.MethodPut, "/api/v1/repos/acme/api/pulls/100/secrets/"+url.PathEscape(fileID)+"/STRIPE_SECRET_KEY", bytes.NewReader(updatePayload))
	update.Header.Set("Content-Type", "application/json")
	update.Header.Set("Authorization", "Bearer "+token)
	updated := httptest.NewRecorder()
	app.Handler().ServeHTTP(updated, update)
	if updated.Code != http.StatusOK || strings.Contains(updated.Body.String(), "non-secret-pr-value") {
		t.Fatalf("encrypted PR update = %d, %s", updated.Code, updated.Body.String())
	}
	pendingSnapshotRequest := httptest.NewRequest(http.MethodGet, "/api/v1/repos/acme/api/pulls/100/snapshot", nil)
	pendingSnapshotRequest.Header.Set("Authorization", "Bearer "+token)
	pendingSnapshot := httptest.NewRecorder()
	app.Handler().ServeHTTP(pendingSnapshot, pendingSnapshotRequest)
	if pendingSnapshot.Code != http.StatusOK || strings.Contains(pendingSnapshot.Body.String(), "non-secret-pr-value") || !strings.Contains(pendingSnapshot.Body.String(), `"scope":"pull_request"`) {
		t.Fatalf("pending encrypted snapshot = %d, %s", pendingSnapshot.Code, pendingSnapshot.Body.String())
	}
	requirements, err := store.PullRequestRequirements(ctx, 17, 100)
	if err != nil || len(requirements) != 1 || requirements[0].State != pranalysis.StateReady {
		t.Fatalf("updated requirements = %#v, %v", requirements, err)
	}
	pull.State = "merged"
	if err := store.ClosePullRequest(ctx, pull); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.RepositorySnapshotForDevice(ctx, "acme", "api", user.ID, "device-1")
	if err != nil || len(snapshot.Secrets) != 1 || snapshot.Secrets[0].KeyName != "STRIPE_SECRET_KEY" || snapshot.Secrets[0].Scope != "pull_request" || strings.Contains(string(snapshot.Secrets[0].Envelope.Ciphertext), "non-secret-pr-value") {
		t.Fatalf("promoted PR snapshot = %#v, %v", snapshot, err)
	}
	permission = "read"
	denied := httptest.NewRequest(http.MethodGet, "/api/v1/repos/acme/api", nil)
	denied.Header.Set("Authorization", "Bearer "+token)
	deniedRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(deniedRecorder, denied)
	if deniedRecorder.Code != http.StatusForbidden {
		t.Fatalf("read-only GitHub permission bootstrap state = %d, want 403", deniedRecorder.Code)
	}
}

type testStore struct{ err error }

func (s testStore) Ready(context.Context) error { return s.err }

type webhookTestStore struct {
	testStore
	calls int
}

func (s *webhookTestStore) ProcessGitHubWebhook(_ context.Context, event githubapp.WebhookEvent) (bool, error) {
	s.calls++
	if event.EventType != "pull_request" || event.DeliveryID != "delivery-1" {
		return false, errors.New("unexpected webhook event")
	}
	return false, nil
}

func TestOperationalEndpoints(t *testing.T) {
	app := New(config.Config{}, testStore{})
	for _, path := range []string{"/healthz", "/readyz"} {
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, recorder.Code)
		}
	}
}

func TestReadyzFailsWhenStoreIsUnavailable(t *testing.T) {
	app := New(config.Config{}, testStore{err: errors.New("unavailable")})
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz status = %d, want 503", recorder.Code)
	}
}

func TestGitHubWebhookVerifiesSignatureBeforeProcessing(t *testing.T) {
	dataDir := t.TempDir()
	appKey := strings.Repeat("a", 32)
	store := &webhookTestStore{}
	app := New(config.Config{DataDir: dataDir, GitHubAppCredentialsEncryptionKey: []byte(appKey)}, store)
	if err := app.credentials.Save(githubapp.Credentials{AppID: 1, ClientID: "test-client", ClientSecret: "test-client-secret", PrivateKeyPEM: "test-private-key", WebhookSecret: "test-webhook-secret"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"action":"opened","number":100,"installation":{"id":7,"account":{"id":2,"login":"acme"}},"repository":{"id":17,"name":"api","owner":{"login":"acme"},"default_branch":"main"},"pull_request":{"head":{"sha":"head"},"base":{"sha":"base"},"user":{"id":5}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhook", strings.NewReader(string(payload)))
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-GitHub-Delivery", "delivery-1")
	request.Header.Set("X-Hub-Signature-256", webhookSignature("test-webhook-secret", payload))
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("verified webhook status = %d, want 202", recorder.Code)
	}
	if store.calls != 1 {
		t.Errorf("processed webhooks = %d, want 1", store.calls)
	}

	invalid := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhook", strings.NewReader(`not json`))
	invalid.Header.Set("X-GitHub-Event", "pull_request")
	invalid.Header.Set("X-GitHub-Delivery", "delivery-2")
	invalid.Header.Set("X-Hub-Signature-256", "sha256=00")
	invalidRecorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(invalidRecorder, invalid)
	if invalidRecorder.Code != http.StatusUnauthorized {
		t.Errorf("unverified webhook status = %d, want 401", invalidRecorder.Code)
	}
	if store.calls != 1 {
		t.Errorf("unverified webhook was processed")
	}
}

func TestPullRequestWebhookPublishesPreciseReadinessAndUpdatesStickyArtifacts(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	var checkMethods, commentMethods []string
	fakeGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/7/access_tokens":
			if r.Method != http.MethodPost {
				t.Errorf("installation token method = %s", r.Method)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"installation-token"}`))
		case "/repos/acme/api/contents/localenv.yaml":
			_, _ = w.Write(gitHubFile("version: 1\nfiles:\n  - schema: .env.example\n    target: .env.local\n"))
		case "/repos/acme/api/contents/.env.example":
			if r.URL.Query().Get("ref") == "base" {
				_, _ = w.Write(gitHubFile("EXISTING=non-secret-schema-default\n"))
				return
			}
			_, _ = w.Write(gitHubFile("EXISTING=non-secret-schema-default\nSTRIPE_SECRET_KEY=non-secret-schema-default\n"))
		case "/repos/acme/api/check-runs", "/repos/acme/api/check-runs/101":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "STRIPE_SECRET_KEY") || strings.Contains(string(body), "non-secret-schema-default") {
				t.Errorf("Check Run payload must contain only the missing key name: %s", body)
			}
			checkMethods = append(checkMethods, r.Method)
			_, _ = w.Write([]byte(`{"id":101}`))
		case "/repos/acme/api/issues/100/comments", "/repos/acme/api/issues/comments/202":
			commentMethods = append(commentMethods, r.Method)
			_, _ = w.Write([]byte(`{"id":202}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fakeGitHub.Close)

	dataDir := t.TempDir()
	store, err := sqlite.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveRepositoryConfigSnapshot(context.Background(), sqlite.RepositoryConfigSnapshot{GitHubRepoID: 17, Owner: "acme", Name: "api", DefaultBranch: "main", Files: []sqlite.RepositoryFile{{SchemaPath: ".env.example", TargetPath: ".env.local"}}}); err != nil {
		t.Fatal(err)
	}
	app := NewWithGitHubClient(config.Config{DataDir: dataDir, PublicURL: mustURL(t, "https://env.example.test"), GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32))}, store, githubapp.Client{HTTPClient: fakeGitHub.Client(), APIBaseURL: fakeGitHub.URL})
	if err := app.credentials.Save(githubapp.Credentials{AppID: 1, ClientID: "test-client", ClientSecret: "test-client-secret", PrivateKeyPEM: pemKey, WebhookSecret: "test-webhook-secret"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"action":"opened","number":100,"installation":{"id":7,"account":{"id":2,"login":"acme"}},"repository":{"id":17,"name":"api","owner":{"login":"acme"},"default_branch":"main"},"pull_request":{"head":{"sha":"head"},"base":{"sha":"base"},"user":{"id":5}}}`)
	for _, deliveryID := range []string{"delivery-pr-1", "delivery-pr-2"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhook", strings.NewReader(string(payload)))
		request.Header.Set("X-GitHub-Event", "pull_request")
		request.Header.Set("X-GitHub-Delivery", deliveryID)
		request.Header.Set("X-Hub-Signature-256", webhookSignature("test-webhook-secret", payload))
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("PR webhook status = %d, body = %q", recorder.Code, recorder.Body.String())
		}
	}
	if got, want := strings.Join(checkMethods, ","), "POST,PATCH"; got != want {
		t.Errorf("Check Run methods = %s, want %s", got, want)
	}
	if got, want := strings.Join(commentMethods, ","), "POST,PATCH"; got != want {
		t.Errorf("comment methods = %s, want %s", got, want)
	}
	requirements, err := store.PullRequestRequirements(context.Background(), 17, 100)
	if err != nil || len(requirements) != 1 || requirements[0].KeyName != "STRIPE_SECRET_KEY" || requirements[0].State != "missing" {
		t.Fatalf("stored requirements = %#v, %v", requirements, err)
	}
}

func gitHubFile(contents string) []byte {
	return []byte(`{"type":"file","encoding":"base64","content":"` + base64.StdEncoding.EncodeToString([]byte(contents)) + `"}`)
}

func TestSetupFlowStoresOnlyEncryptedGitHubCredentialsAndBecomesReady(t *testing.T) {
	gitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-access-token"}`))
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":1,"login":"admin"}`))
		case "/user/memberships/orgs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"state":"active","organization":{"id":2,"login":"acme"}}]`))
		case "/app-manifests/manifest-code/conversions":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":9,"pem":"non-secret-test-private-key","webhook_secret":"non-secret-test-webhook-secret","client_id":"manifest-client","client_secret":"non-secret-test-client-secret","html_url":"https://github.com/apps/acme-localenv"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(gitHub.Close)

	dataDir := t.TempDir()
	store, err := sqlite.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	app := NewWithGitHubClient(config.Config{
		DataDir:                           dataDir,
		PublicURL:                         mustURL(t, "https://env.example.test"),
		DisplayName:                       "local.env",
		GitHubOAuthClientID:               "bootstrap-client",
		GitHubOAuthClientSecret:           "non-secret-test-bootstrap-client-secret",
		GitHubAppCredentialsEncryptionKey: []byte(strings.Repeat("a", 32)),
	}, store, githubapp.Client{HTTPClient: gitHub.Client(), APIBaseURL: gitHub.URL, OAuthURL: gitHub.URL + "/login/oauth"})

	start := httptest.NewRecorder()
	app.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/auth/github/start", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("auth start status = %d, want 302", start.Code)
	}
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authCallback := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=oauth-code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	authCallback.AddCookie(cookieNamed(t, start.Result().Cookies(), oauthStateCookie))
	auth := httptest.NewRecorder()
	app.Handler().ServeHTTP(auth, authCallback)
	if auth.Code != http.StatusFound {
		t.Fatalf("auth callback status = %d, want 302", auth.Code)
	}
	setupSessionCookie := cookieNamed(t, auth.Result().Cookies(), setupCookie)
	setupRequest := httptest.NewRequest(http.MethodGet, "/setup", nil)
	setupRequest.AddCookie(setupSessionCookie)
	session, found := app.readSetupSession(setupRequest)
	if !found {
		t.Fatal("setup session was not stored in an encrypted cookie")
	}
	form := url.Values{"csrf_token": {session.CSRFToken}, "organization_id": {"2"}}
	createRequest := httptest.NewRequest(http.MethodPost, "/setup/github-app", strings.NewReader(form.Encode()))
	createRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createRequest.Header.Set("Origin", "https://env.example.test")
	createRequest.AddCookie(setupSessionCookie)
	create := httptest.NewRecorder()
	app.Handler().ServeHTTP(create, createRequest)
	if create.Code != http.StatusOK || !strings.Contains(create.Body.String(), `name="manifest"`) || !strings.Contains(create.Body.String(), `Continue to GitHub`) || strings.Contains(create.Body.String(), `<script>`) || strings.Contains(create.Body.String(), `src="http`) {
		t.Fatalf("create manifest status/body = %d/%q", create.Code, create.Body.String())
	}
	manifestCookie := cookieNamed(t, create.Result().Cookies(), setupCookie)
	manifestRequest := httptest.NewRequest(http.MethodGet, "/setup", nil)
	manifestRequest.AddCookie(manifestCookie)
	manifestSession, found := app.readSetupSession(manifestRequest)
	if !found || manifestSession.ManifestState == "" {
		t.Fatal("manifest state was not persisted")
	}
	callback := httptest.NewRequest(http.MethodGet, "/setup/github-app/callback?code=manifest-code&state="+url.QueryEscape(manifestSession.ManifestState), nil)
	callback.AddCookie(manifestCookie)
	complete := httptest.NewRecorder()
	app.Handler().ServeHTTP(complete, callback)
	if complete.Code != http.StatusFound {
		t.Fatalf("manifest callback status = %d, want 302", complete.Code)
	}
	credentials, found, err := app.credentials.Load()
	if err != nil || !found || credentials.AppID != 9 {
		t.Fatalf("stored credentials = (%#v, %v, %v), want app 9", credentials, found, err)
	}
	ready := httptest.NewRecorder()
	app.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Errorf("readyz after GitHub setup = %d, want 200", ready.Code)
	}
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatalf("cookie %q was not set", name)
	return nil
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func webhookSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
