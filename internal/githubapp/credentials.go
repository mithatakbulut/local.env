// Package githubapp contains the narrow GitHub App integration used by the server.
package githubapp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const credentialsFilename = "github-app-credentials.enc"

// Credentials are GitHub integration credentials, never managed developer
// secrets. They are kept encrypted at rest and must never be logged.
type Credentials struct {
	AppID         int64  `json:"app_id"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	PrivateKeyPEM string `json:"private_key_pem"`
	WebhookSecret string `json:"webhook_secret"`
	AppHTMLURL    string `json:"app_html_url"`
}

// CredentialStore encrypts GitHub App credentials using a deployment-supplied
// key that is deliberately kept outside the persistent data directory.
type CredentialStore struct {
	path string
	key  []byte
}

func NewCredentialStore(dataDir string, key []byte) *CredentialStore {
	return &CredentialStore{path: filepath.Join(dataDir, credentialsFilename), key: append([]byte(nil), key...)}
}

func (s *CredentialStore) Configured() bool { return len(s.key) == 32 }

func (s *CredentialStore) Load() (Credentials, bool, error) {
	if !s.Configured() {
		return Credentials{}, false, errors.New("GitHub credential encryption is not configured")
	}
	contents, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Credentials{}, false, nil
	}
	if err != nil {
		return Credentials{}, false, fmt.Errorf("read encrypted GitHub credentials: %w", err)
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return Credentials{}, false, fmt.Errorf("stat encrypted GitHub credentials: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Credentials{}, false, errors.New("encrypted GitHub credentials have unsafe permissions")
	}
	plaintext, err := s.open(contents, "github-app-credentials")
	if err != nil {
		return Credentials{}, false, errors.New("decrypt GitHub credentials")
	}
	var credentials Credentials
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		return Credentials{}, false, errors.New("decode GitHub credentials")
	}
	if err := credentials.Valid(); err != nil {
		return Credentials{}, false, err
	}
	return credentials, true, nil
}

func (s *CredentialStore) Save(credentials Credentials) error {
	if !s.Configured() {
		return errors.New("GitHub credential encryption is not configured")
	}
	if err := credentials.Valid(); err != nil {
		return err
	}
	plaintext, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("encode GitHub credentials: %w", err)
	}
	ciphertext, err := s.seal(plaintext, "github-app-credentials")
	if err != nil {
		return fmt.Errorf("encrypt GitHub credentials: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".github-app-credentials-")
	if err != nil {
		return fmt.Errorf("create encrypted GitHub credentials: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("secure encrypted GitHub credentials: %w", err)
	}
	if _, err := temp.Write(ciphertext); err != nil {
		temp.Close()
		return fmt.Errorf("write encrypted GitHub credentials: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync encrypted GitHub credentials: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close encrypted GitHub credentials: %w", err)
	}
	if err := os.Rename(tempName, s.path); err != nil {
		return fmt.Errorf("activate encrypted GitHub credentials: %w", err)
	}
	return os.Chmod(s.path, 0o600)
}

func (c Credentials) Valid() error {
	if c.AppID <= 0 || c.ClientID == "" || c.ClientSecret == "" || c.PrivateKeyPEM == "" || c.WebhookSecret == "" {
		return errors.New("incomplete GitHub credentials")
	}
	return nil
}

// SealCookie and OpenCookie provide authenticated, confidential temporary
// browser state without persisting OAuth codes or access tokens server-side.
func (s *CredentialStore) SealCookie(plaintext []byte, purpose string) ([]byte, error) {
	if !s.Configured() {
		return nil, errors.New("GitHub credential encryption is not configured")
	}
	return s.seal(plaintext, "cookie:"+purpose)
}

func (s *CredentialStore) OpenCookie(ciphertext []byte, purpose string) ([]byte, error) {
	if !s.Configured() {
		return nil, errors.New("GitHub credential encryption is not configured")
	}
	return s.open(ciphertext, "cookie:"+purpose)
}

func (s *CredentialStore) seal(plaintext []byte, purpose string) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plaintext, []byte(purpose))...), nil
}

func (s *CredentialStore) open(ciphertext []byte, purpose string) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	return aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], []byte(purpose))
}
