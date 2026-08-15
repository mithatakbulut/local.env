package config

import "testing"

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("LOCALENV_PUBLIC_URL", "https://env.example.test")
	t.Setenv("LOCALENV_DATA_DIR", t.TempDir())
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if got, want := cfg.DisplayName, "local.env"; got != want {
		t.Errorf("DisplayName = %q, want %q", got, want)
	}
	if got, want := cfg.PublicURL.String(), "https://env.example.test"; got != want {
		t.Errorf("PublicURL = %q, want %q", got, want)
	}
}

func TestLoadFromEnvRejectsUnsafeURL(t *testing.T) {
	t.Setenv("LOCALENV_PUBLIC_URL", "https://user:password@env.example.test")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("LoadFromEnv() succeeded with URL credentials")
	}
}
