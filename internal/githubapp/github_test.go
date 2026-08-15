package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublishReadinessClassifiesIssueCommentFailureAndRetainsCheckRunID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/7/access_tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"test-installation-token","permissions":{"checks":"write","contents":"read","issues":"write","metadata":"read","pull_requests":"read"}}`))
		case "/repos/acme/api/check-runs":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":101}`))
		case "/repos/acme/api/issues/100/comments":
			w.Header().Set("X-Accepted-GitHub-Permissions", "issues=write")
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(github.Close)

	publication, err := (Client{HTTPClient: github.Client(), APIBaseURL: github.URL}).PublishReadiness(context.Background(), Credentials{AppID: 1, PrivateKeyPEM: privateKeyPEM}, 7, PullRequest{Number: 100, HeadSHA: "head", Repository: Repository{Owner: "acme", Name: "api"}}, ReadinessPublication{Summary: "safe metadata", Comment: "safe metadata"})
	if publication.CheckRunID != 101 {
		t.Fatalf("CheckRunID = %d, want 101", publication.CheckRunID)
	}
	var githubError *HTTPError
	if !errors.As(err, &githubError) {
		t.Fatalf("PublishReadiness() error = %v, want HTTPError", err)
	}
	if githubError.Operation != "issue_comment" || githubError.StatusCode != http.StatusForbidden || githubError.StatusClass() != "forbidden" || githubError.PermissionRequirement != "issues_write" || githubError.GrantedPermissions != "checks_write+contents_read+issues_write+metadata_read+pull_requests_read" {
		t.Fatalf("HTTPError = %#v, class = %q", githubError, githubError.StatusClass())
	}
}

func TestHTTPErrorClassifiesSafeGitHub403ResponseHeaders(t *testing.T) {
	rateLimited := http.Header{}
	rateLimited.Set("Retry-After", "60")
	if got := safeResponseClass(http.StatusForbidden, rateLimited); got != "rate_limited" {
		t.Fatalf("retry-after class = %q, want rate_limited", got)
	}
	ssoRequired := http.Header{}
	ssoRequired.Set("X-GitHub-SSO", "required; url=https://github.com")
	if got := safeResponseClass(http.StatusForbidden, ssoRequired); got != "sso_authorization_required" {
		t.Fatalf("SSO class = %q, want sso_authorization_required", got)
	}
	if got := safeResponseClass(http.StatusForbidden, http.Header{}); got != "" {
		t.Fatalf("ordinary 403 class = %q, want empty", got)
	}
}
