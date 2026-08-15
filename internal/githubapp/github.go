package githubapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
