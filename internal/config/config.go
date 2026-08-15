// Package config loads the explicit server configuration used in v1.
package config

import (
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

// Config contains only non-secret server configuration. GitHub credentials are
// intentionally introduced with the setup flow in P1.
type Config struct {
	DataDir     string
	ListenAddr  string
	PublicURL   *url.URL
	DisplayName string
	LogoURL     *url.URL
	FaviconURL  *url.URL
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
	return cfg, nil
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
