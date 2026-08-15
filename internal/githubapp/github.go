package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const maxGitHubResponseBytes = 1 << 20

// Client implements only the unauthenticated manifest and OAuth requests P1
// needs. Its errors intentionally never include tokens, private keys, or bodies.
type Client struct {
	HTTPClient *http.Client
	APIBaseURL string
	OAuthURL   string
}

func DefaultClient() Client {
	return Client{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		APIBaseURL: "https://api.github.com",
		OAuthURL:   "https://github.com/login/oauth",
	}
}

type User struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type Organization struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

func (c Client) AuthorizationURL(clientID, redirectURI, state string) (string, error) {
	u, err := url.Parse(strings.TrimRight(c.oauthURL(), "/") + "/authorize")
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "read:org")
	query.Set("state", state)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (c Client) ExchangeOAuthCode(ctx context.Context, clientID, clientSecret, code, redirectURI string) (string, error) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.oauthURL(), "/")+"/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange GitHub OAuth code: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub OAuth exchange returned status %d", response.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeJSON(response.Body, &result); err != nil {
		return "", errors.New("decode GitHub OAuth exchange")
	}
	if result.AccessToken == "" {
		return "", errors.New("GitHub OAuth exchange did not return an access token")
	}
	return result.AccessToken, nil
}

func (c Client) UserAndOrganizations(ctx context.Context, token string) (User, []Organization, error) {
	var user User
	if err := c.getJSON(ctx, "/user", token, &user); err != nil {
		return User{}, nil, err
	}
	if user.ID <= 0 || user.Login == "" {
		return User{}, nil, errors.New("GitHub user response is incomplete")
	}
	var organizations []Organization
	if err := c.getJSON(ctx, "/user/orgs?per_page=100", token, &organizations); err != nil {
		return User{}, nil, err
	}
	filtered := organizations[:0]
	for _, organization := range organizations {
		if organization.ID > 0 && validGitHubLogin(organization.Login) {
			filtered = append(filtered, organization)
		}
	}
	return user, filtered, nil
}

type ManifestConversion struct {
	ID            int64  `json:"id"`
	PEM           string `json:"pem"`
	WebhookSecret string `json:"webhook_secret"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	HTMLURL       string `json:"html_url"`
}

func (c Client) ConvertManifest(ctx context.Context, code string) (ManifestConversion, error) {
	endpoint := strings.TrimRight(c.apiBaseURL(), "/") + "/app-manifests/" + url.PathEscape(code) + "/conversions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return ManifestConversion{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := c.httpClient().Do(req)
	if err != nil {
		return ManifestConversion{}, fmt.Errorf("convert GitHub App manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return ManifestConversion{}, fmt.Errorf("GitHub App manifest conversion returned status %d", response.StatusCode)
	}
	var conversion ManifestConversion
	if err := decodeJSON(response.Body, &conversion); err != nil {
		return ManifestConversion{}, errors.New("decode GitHub App manifest conversion")
	}
	if conversion.ID <= 0 || conversion.PEM == "" || conversion.WebhookSecret == "" || conversion.ClientID == "" || conversion.ClientSecret == "" {
		return ManifestConversion{}, errors.New("GitHub App manifest conversion returned incomplete credentials")
	}
	return conversion, nil
}

func (c Client) getJSON(ctx context.Context, path, token string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.apiBaseURL(), "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("call GitHub API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned status %d", response.StatusCode)
	}
	if err := decodeJSON(response.Body, target); err != nil {
		return errors.New("decode GitHub API response")
	}
	return nil
}

// ErrNotFound distinguishes an absent file at a specific commit from a GitHub
// transport failure. PR analysis treats an absent base schema as an empty set.
var ErrNotFound = errors.New("GitHub resource not found")

// ReadFile returns one repository file at an immutable Git commit. The
// returned bytes are schema/config source, never a managed secret value.
func (c Client) ReadFile(ctx context.Context, credentials Credentials, installationID int64, owner, repository, filename, ref string) ([]byte, error) {
	if installationID <= 0 || owner == "" || repository == "" || filename == "" || ref == "" {
		return nil, errors.New("incomplete GitHub file request")
	}
	token, err := c.installationToken(ctx, credentials, installationID)
	if err != nil {
		return nil, err
	}
	endpoint := c.apiURL("repos", owner, repository, "contents", filename)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?ref="+url.QueryEscape(ref), nil)
	if err != nil {
		return nil, err
	}
	response, err := c.authorized(request, token)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub file request returned status %d", response.StatusCode)
	}
	var result struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if err := decodeJSON(response.Body, &result); err != nil {
		return nil, errors.New("decode GitHub file response")
	}
	if result.Type != "file" || result.Encoding != "base64" {
		return nil, errors.New("GitHub file response is not a base64 file")
	}
	contents, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(result.Content, "\n", ""))
	if err != nil {
		return nil, errors.New("decode GitHub file content")
	}
	return contents, nil
}

// ReadinessPublication identifies the remote artifacts that must be updated,
// rather than recreated, for a PR.
type ReadinessPublication struct {
	CheckRunID int64
	CommentID  int64
	Success    bool
	Summary    string
	Comment    string
}

// PublishReadiness upserts the required Check Run and a single sticky comment.
// Its request payload contains key names and guidance only.
func (c Client) PublishReadiness(ctx context.Context, credentials Credentials, installationID int64, pull PullRequest, publication ReadinessPublication) (ReadinessPublication, error) {
	token, err := c.installationToken(ctx, credentials, installationID)
	if err != nil {
		return publication, err
	}
	conclusion, title := "failure", "Environment readiness failed"
	if publication.Success {
		conclusion, title = "success", "Environment readiness passed"
	}
	checkPayload := map[string]any{
		"name":       "local.env / readiness",
		"head_sha":   pull.HeadSHA,
		"status":     "completed",
		"conclusion": conclusion,
		"output":     map[string]string{"title": title, "summary": publication.Summary},
	}
	checkPath := []string{"repos", pull.Repository.Owner, pull.Repository.Name, "check-runs"}
	method := http.MethodPost
	if publication.CheckRunID > 0 {
		method = http.MethodPatch
		checkPath = append(checkPath, strconv.FormatInt(publication.CheckRunID, 10))
		delete(checkPayload, "head_sha")
	}
	var check struct {
		ID int64 `json:"id"`
	}
	if err := c.authorizedJSON(ctx, token, method, c.apiURL(checkPath...), checkPayload, &check, http.StatusCreated, http.StatusOK); err != nil {
		return publication, err
	}
	if check.ID <= 0 {
		return publication, errors.New("GitHub Check Run response is incomplete")
	}
	publication.CheckRunID = check.ID

	commentPayload := map[string]string{"body": "<!-- localenv:readiness -->\n" + publication.Comment}
	commentPath := []string{"repos", pull.Repository.Owner, pull.Repository.Name, "issues", strconv.Itoa(pull.Number), "comments"}
	method = http.MethodPost
	if publication.CommentID > 0 {
		method = http.MethodPatch
		commentPath = []string{"repos", pull.Repository.Owner, pull.Repository.Name, "issues", "comments", strconv.FormatInt(publication.CommentID, 10)}
	}
	var comment struct {
		ID int64 `json:"id"`
	}
	if err := c.authorizedJSON(ctx, token, method, c.apiURL(commentPath...), commentPayload, &comment, http.StatusCreated, http.StatusOK); err != nil {
		return publication, err
	}
	if comment.ID <= 0 {
		return publication, errors.New("GitHub issue comment response is incomplete")
	}
	publication.CommentID = comment.ID
	return publication, nil
}

func (c Client) installationToken(ctx context.Context, credentials Credentials, installationID int64) (string, error) {
	jwt, err := appJWT(credentials)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL("app", "installations", strconv.FormatInt(installationID, 10), "access_tokens"), nil)
	if err != nil {
		return "", err
	}
	response, err := c.authorized(request, jwt)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("GitHub installation token request returned status %d", response.StatusCode)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(response.Body, &result); err != nil || result.Token == "" {
		return "", errors.New("decode GitHub installation token")
	}
	return result.Token, nil
}

func (c Client) authorizedJSON(ctx context.Context, token, method, endpoint string, input, output any, statuses ...int) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.authorized(request, token)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	for _, status := range statuses {
		if response.StatusCode == status {
			if err := decodeJSON(response.Body, output); err != nil {
				return errors.New("decode GitHub write response")
			}
			return nil
		}
	}
	return fmt.Errorf("GitHub write request returned status %d", response.StatusCode)
}

func (c Client) authorized(request *http.Request, token string) (*http.Response, error) {
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("call GitHub API: %w", err)
	}
	return response, nil
}

func (c Client) apiURL(parts ...string) string {
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		escaped = append(escaped, url.PathEscape(part))
	}
	return strings.TrimRight(c.apiBaseURL(), "/") + "/" + path.Join(escaped...)
}

func appJWT(credentials Credentials) (string, error) {
	block, _ := pem.Decode([]byte(credentials.PrivateKeyPEM))
	if block == nil {
		return "", errors.New("decode GitHub App private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return "", errors.New("parse GitHub App private key")
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("GitHub App private key must be RSA")
		}
	}
	now := time.Now().UTC()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": strconv.FormatInt(credentials.AppID, 10)})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("sign GitHub App JWT")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c Client) apiBaseURL() string {
	if c.APIBaseURL != "" {
		return c.APIBaseURL
	}
	return "https://api.github.com"
}

func (c Client) oauthURL() string {
	if c.OAuthURL != "" {
		return c.OAuthURL
	}
	return "https://github.com/login/oauth"
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxGitHubResponseBytes))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected additional JSON values")
	}
	return nil
}

// Manifest contains precisely the permissions and events required by P1.
func Manifest(name, publicURL string) ([]byte, error) {
	if !validGitHubLogin(strings.TrimSuffix(name, "-localenv")) {
		return nil, errors.New("invalid GitHub organization login")
	}
	base, err := url.Parse(publicURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("invalid public URL")
	}
	join := func(path string) string {
		copy := *base
		copy.Path = strings.TrimRight(copy.Path, "/") + path
		copy.RawQuery = ""
		copy.Fragment = ""
		return copy.String()
	}
	return json.Marshal(struct {
		Name               string            `json:"name"`
		URL                string            `json:"url"`
		Public             bool              `json:"public"`
		RedirectURL        string            `json:"redirect_url"`
		CallbackURLs       []string          `json:"callback_urls"`
		HookAttributes     map[string]any    `json:"hook_attributes"`
		DefaultPermissions map[string]string `json:"default_permissions"`
		DefaultEvents      []string          `json:"default_events"`
	}{
		Name:         name,
		URL:          base.String(),
		Public:       false,
		RedirectURL:  join("/setup/github-app/callback"),
		CallbackURLs: []string{join("/auth/github/callback")},
		HookAttributes: map[string]any{
			"url":    join("/api/v1/github/webhook"),
			"active": true,
		},
		DefaultPermissions: map[string]string{
			"contents":      "read",
			"pull_requests": "read",
			"checks":        "write",
			"issues":        "write",
			"metadata":      "read",
		},
		DefaultEvents: []string{"pull_request", "installation", "installation_repositories"},
	})
}

func VerifyWebhookSignature(secret, signature string, payload []byte) bool {
	const prefix = "sha256="
	if secret == "" || !strings.HasPrefix(signature, prefix) {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, prefix))
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)
	return subtle.ConstantTimeCompare(provided, expected) == 1
}

type Repository struct {
	GitHubRepoID  int64  `json:"id"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
}

type WebhookEvent struct {
	DeliveryID           string
	EventType            string
	InstallationID       int64
	InstallationOrgID    int64
	InstallationOrgLogin string
	InstallationDeleted  bool
	RepositoriesAdded    []Repository
	RepositoriesRemoved  []Repository
	PullRequest          *PullRequest
}

// PullRequest contains only GitHub metadata required to calculate readiness.
// It intentionally has no changed file contents or secret values.
type PullRequest struct {
	Number     int
	BaseSHA    string
	HeadSHA    string
	AuthorID   int64
	Action     string
	State      string
	MergedAt   *time.Time
	Repository Repository
}

// ParseWebhook runs only after an HMAC has been verified by the handler.
func ParseWebhook(eventType, deliveryID string, payload []byte) (WebhookEvent, error) {
	if deliveryID == "" || eventType == "" {
		return WebhookEvent{}, errors.New("missing GitHub delivery metadata")
	}
	var envelope struct {
		Action       string `json:"action"`
		Installation struct {
			ID      int64 `json:"id"`
			Account struct {
				ID    int64  `json:"id"`
				Login string `json:"login"`
			} `json:"account"`
		} `json:"installation"`
		RepositoriesAdded   []repositoryPayload `json:"repositories_added"`
		RepositoriesRemoved []repositoryPayload `json:"repositories_removed"`
		Repositories        []repositoryPayload `json:"repositories"`
		Repository          repositoryPayload   `json:"repository"`
		Number              int                 `json:"number"`
		PullRequest         struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
			Base struct {
				SHA string `json:"sha"`
			} `json:"base"`
			User struct {
				ID int64 `json:"id"`
			} `json:"user"`
			Merged   bool       `json:"merged"`
			MergedAt *time.Time `json:"merged_at"`
		} `json:"pull_request"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&envelope); err != nil {
		return WebhookEvent{}, errors.New("invalid GitHub webhook JSON")
	}
	if eventType == "ping" {
		return WebhookEvent{DeliveryID: deliveryID, EventType: eventType}, nil
	}
	if envelope.Installation.ID <= 0 {
		return WebhookEvent{}, errors.New("GitHub webhook is missing an installation")
	}
	event := WebhookEvent{
		DeliveryID:           deliveryID,
		EventType:            eventType,
		InstallationID:       envelope.Installation.ID,
		InstallationOrgID:    envelope.Installation.Account.ID,
		InstallationOrgLogin: envelope.Installation.Account.Login,
	}
	switch eventType {
	case "pull_request":
		repositories := normalizeRepositories([]repositoryPayload{envelope.Repository})
		if envelope.Number <= 0 || len(repositories) != 1 || envelope.PullRequest.Base.SHA == "" || envelope.PullRequest.Head.SHA == "" || envelope.PullRequest.User.ID <= 0 {
			return WebhookEvent{}, errors.New("GitHub pull request webhook is incomplete")
		}
		state := "open"
		if envelope.Action == "closed" {
			state = "closed"
			if envelope.PullRequest.Merged {
				state = "merged"
			}
		}
		event.PullRequest = &PullRequest{Number: envelope.Number, BaseSHA: envelope.PullRequest.Base.SHA, HeadSHA: envelope.PullRequest.Head.SHA, AuthorID: envelope.PullRequest.User.ID, Action: envelope.Action, State: state, MergedAt: envelope.PullRequest.MergedAt, Repository: repositories[0]}
		return event, nil
	case "installation":
		event.InstallationDeleted = envelope.Action == "deleted"
		event.RepositoriesAdded = normalizeRepositories(envelope.Repositories)
	case "installation_repositories":
		event.RepositoriesAdded = normalizeRepositories(envelope.RepositoriesAdded)
		event.RepositoriesRemoved = normalizeRepositories(envelope.RepositoriesRemoved)
	default:
		return event, nil
	}
	return event, nil
}

type repositoryPayload struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func normalizeRepositories(payloads []repositoryPayload) []Repository {
	repositories := make([]Repository, 0, len(payloads))
	for _, repository := range payloads {
		owner, name := repository.Owner.Login, repository.Name
		if owner == "" || name == "" {
			owner, name, _ = strings.Cut(repository.FullName, "/")
		}
		if repository.ID <= 0 || !validGitHubLogin(owner) || name == "" {
			continue
		}
		branch := repository.DefaultBranch
		if branch == "" {
			branch = "HEAD"
		}
		repositories = append(repositories, Repository{GitHubRepoID: repository.ID, Owner: owner, Name: name, DefaultBranch: branch})
	}
	return repositories
}

func validGitHubLogin(value string) bool {
	if value == "" || len(value) > 39 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}
