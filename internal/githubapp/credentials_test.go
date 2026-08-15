package githubapp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialStoreEncryptsPrivateKeyAtRest(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	store := NewCredentialStore(t.TempDir(), key)
	credentials := Credentials{
		AppID:         123,
		ClientID:      "Iv1.test",
		ClientSecret:  "non-secret-test-client-secret",
		PrivateKeyPEM: "non-secret-test-private-key",
		WebhookSecret: "non-secret-test-webhook-secret",
	}
	if err := store.Save(credentials); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	persisted, err := os.ReadFile(filepath.Join(filepath.Dir(store.path), credentialsFilename))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted, []byte(credentials.PrivateKeyPEM)) || bytes.Contains(persisted, []byte(credentials.WebhookSecret)) {
		t.Fatal("encrypted credential file contains test credential plaintext")
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("credential file permissions = %o, want %o", got, want)
	}
	loaded, found, err := store.Load()
	if err != nil || !found {
		t.Fatalf("Load() = (%v, %v), want credentials", found, err)
	}
	if loaded != credentials {
		t.Error("Load() did not return the encrypted credentials")
	}
}

func TestVerifyWebhookSignature(t *testing.T) {
	payload := []byte(`{"action":"opened"}`)
	secret := "non-secret-test-webhook-secret"
	if !VerifyWebhookSignature(secret, "sha256=cf0ce383e5aa5dd563e53eed521399a14c596a863a631d5317619e99365e777e", payload) {
		t.Fatal("VerifyWebhookSignature() rejected known valid HMAC")
	}
	if VerifyWebhookSignature(secret, "sha256=cf0ce383e5aa5dd563e53eed521399a14c596a863a631d5317619e99365e7770", payload) {
		t.Fatal("VerifyWebhookSignature() accepted invalid HMAC")
	}
}

func TestManifestRequestsOnlyRequiredPermissionsAndEvents(t *testing.T) {
	manifest, err := Manifest("acme-localenv", "https://env.example.test")
	if err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	for _, forbidden := range []string{`"contents":"write"`, `"actions":"write"`, `"administration":"write"`, `"secrets":"write"`} {
		if bytes.Contains(manifest, []byte(forbidden)) {
			t.Errorf("manifest requests forbidden permission %s", forbidden)
		}
	}
	for _, required := range []string{`"contents":"read"`, `"pull_requests":"read"`, `"checks":"write"`, `"issues":"write"`, `"pull_request"`, `"installation"`, `"installation_repositories"`} {
		if !bytes.Contains(manifest, []byte(required)) {
			t.Errorf("manifest is missing %s", required)
		}
	}
}
