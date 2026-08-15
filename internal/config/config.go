// Package config loads the explicit server configuration used in v1.
package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	defaultDataDir    = "/data"
	defaultListenAddr = ":8080"
	defaultName       = "local.env"
)

// Config contains server configuration. Bootstrap OAuth and encryption values
// are secrets; callers must never log this structure.
type Config struct {
	DataDir                           string
	ListenAddr                        string
	PublicURL                         *url.URL
	DisplayName                       string
	LogoURL                           *url.URL
	FaviconURL                        *url.URL
	GitHubOAuthClientID               string
	GitHubOAuthClientSecret           string
	GitHubAppCredentialsEncryptionKey []byte
}

// LoadFromEnv loads and validates server configuration without logging values.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		DataDir:     valueOr("LOCALENV_DATA_DIR", defaultDataDir),
		ListenAddr:  valueOr("LOCALENV_LISTEN_ADDR", defaultListenAddr),
		DisplayName: valueOr("LOCALENV_DISPLAY_NAME", defaultName),
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return Config{}, fmt.Errorf("LOCALENV_DATA_DIR must not be empty")
	}
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		return Config{}, fmt.Errorf("LOCALENV_LISTEN_ADDR must not be empty")
	}
	if strings.TrimSpace(cfg.DisplayName) == "" {
		return Config{}, fmt.Errorf("LOCALENV_DISPLAY_NAME must not be empty")
	}

	var err error
	if cfg.PublicURL, err = parseHTTPURL("LOCALENV_PUBLIC_URL", os.Getenv("LOCALENV_PUBLIC_URL"), true); err != nil {
		return Config{}, err
	}
	if cfg.LogoURL, err = parseHTTPURL("LOCALENV_LOGO_URL", os.Getenv("LOCALENV_LOGO_URL"), false); err != nil {
		return Config{}, err
	}
	if cfg.FaviconURL, err = parseHTTPURL("LOCALENV_FAVICON_URL", os.Getenv("LOCALENV_FAVICON_URL"), false); err != nil {
		return Config{}, err
	}
	cfg.GitHubOAuthClientID = strings.TrimSpace(os.Getenv("LOCALENV_GITHUB_OAUTH_CLIENT_ID"))
	cfg.GitHubOAuthClientSecret = strings.TrimSpace(os.Getenv("LOCALENV_GITHUB_OAUTH_CLIENT_SECRET"))
	if (cfg.GitHubOAuthClientID == "") != (cfg.GitHubOAuthClientSecret == "") {
		return Config{}, fmt.Errorf("LOCALENV_GITHUB_OAUTH_CLIENT_ID and LOCALENV_GITHUB_OAUTH_CLIENT_SECRET must be set together")
	}
	if rawKey := strings.TrimSpace(os.Getenv("LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY")); rawKey != "" {
		key, err := base64.StdEncoding.DecodeString(rawKey)
		if err != nil || len(key) != 32 {
			return Config{}, fmt.Errorf("LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY must be a base64-encoded 32-byte key")
		}
		cfg.GitHubAppCredentialsEncryptionKey = key
	}
	return cfg, nil
}

// GitHubSetupConfigured reports whether this deployment can safely complete
// the first-run GitHub setup flow.
func (c Config) GitHubSetupConfigured() bool {
	return c.GitHubOAuthClientID != "" && c.GitHubOAuthClientSecret != "" && len(c.GitHubAppCredentialsEncryptionKey) == 32
}

func valueOr(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func parseHTTPURL(name, raw string, required bool) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		if required {
			return nil, fmt.Errorf("%s is required", name)
		}
		return nil, nil
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute HTTP(S) URL", name)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%s must use http or https", name)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must not contain credentials, a query, or a fragment", name)
	}
	return parsed, nil
}
