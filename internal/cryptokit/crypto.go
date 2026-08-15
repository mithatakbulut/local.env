// Package cryptokit implements the client-side cryptographic protocol.
//
// It deliberately has no database or HTTP dependency: managed values and
// repository encryption keys must be encrypted or decrypted on a CLI device.
package cryptokit

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Algorithm = "XCHACHA20-POLY1305"
	REKSize   = chacha20poly1305.KeySize
)

// AAD identifies one secret version. Its byte representation is protocol
// data, not JSON, so field ordering is fixed across CLI versions.
type AAD struct {
	InstanceID   string
	GitHubRepoID int64
	FilePath     string
	KeyName      string
	Scope        string
	ScopeID      string
	Version      int64
	KeyEpoch     int64
}

// Bytes serializes AAD in the v1 fixed-field format. NUL is forbidden in all
// string fields because it is the unambiguous field separator.
func (a AAD) Bytes() ([]byte, error) {
	if a.GitHubRepoID <= 0 || a.Version <= 0 || a.KeyEpoch <= 0 || a.InstanceID == "" || a.FilePath == "" || a.KeyName == "" {
		return nil, errors.New("incomplete associated data")
	}
	if a.Scope != "baseline" && a.Scope != "pull_request" {
		return nil, errors.New("invalid associated data scope")
	}
	if (a.Scope == "baseline" && a.ScopeID != "") || (a.Scope == "pull_request" && a.ScopeID == "") {
		return nil, errors.New("invalid associated data scope ID")
	}
	fields := []string{a.InstanceID, strconv.FormatInt(a.GitHubRepoID, 10), a.FilePath, a.KeyName, a.Scope, a.ScopeID, strconv.FormatInt(a.Version, 10), strconv.FormatInt(a.KeyEpoch, 10)}
	for index, field := range fields {
		if (index != 5 && field == "") || strings.ContainsRune(field, '\x00') {
			return nil, errors.New("invalid associated data field")
		}
	}
	return []byte("localenv:v1\x00" + strings.Join(fields, "\x00")), nil
}

// Envelope is the ciphertext-only record carried to and stored by the
// server. []byte JSON encoding is base64; it has no plaintext field.
type Envelope struct {
	Algorithm  string `json:"algorithm"`
	KeyEpoch   int64  `json:"key_epoch"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Version    int64  `json:"version"`
}

// GenerateREK returns one random 32-byte repository encryption key.
func GenerateREK() ([]byte, error) {
	key := make([]byte, REKSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate repository key: %w", err)
	}
	return key, nil
}

// Encrypt seals plaintext with an XChaCha20-Poly1305 key and random nonce.
func Encrypt(rek, plaintext []byte, aad AAD) (Envelope, error) {
	if len(rek) != REKSize {
		return Envelope{}, errors.New("invalid repository key")
	}
	associated, err := aad.Bytes()
	if err != nil {
		return Envelope{}, err
	}
	aead, err := chacha20poly1305.NewX(rek)
	if err != nil {
		return Envelope{}, errors.New("initialize secret encryption")
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate secret nonce: %w", err)
	}
	return Envelope{Algorithm: Algorithm, KeyEpoch: aad.KeyEpoch, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, associated), Version: aad.Version}, nil
}

// Decrypt authenticates and opens an encrypted secret. Authentication errors
// intentionally do not include ciphertext or plaintext material.
func Decrypt(rek []byte, envelope Envelope, aad AAD) ([]byte, error) {
	if len(rek) != REKSize || envelope.Algorithm != Algorithm || envelope.KeyEpoch != aad.KeyEpoch || envelope.Version != aad.Version || len(envelope.Nonce) != chacha20poly1305.NonceSizeX || len(envelope.Ciphertext) < chacha20poly1305.Overhead {
		return nil, errors.New("invalid encrypted secret envelope")
	}
	associated, err := aad.Bytes()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(rek)
	if err != nil {
		return nil, errors.New("initialize secret decryption")
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associated)
	if err != nil {
		return nil, errors.New("encrypted secret authentication failed")
	}
	return plaintext, nil
}

// WrapREK encrypts a REK to one age X25519 device recipient.
func WrapREK(rek []byte, recipient string) ([]byte, error) {
	if len(rek) != REKSize {
		return nil, errors.New("invalid repository key")
	}
	parsed, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, errors.New("invalid device recipient")
	}
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, parsed)
	if err != nil {
		return nil, errors.New("wrap repository key")
	}
	if _, err := io.Copy(writer, bytes.NewReader(rek)); err != nil {
		return nil, errors.New("wrap repository key")
	}
	if err := writer.Close(); err != nil {
		return nil, errors.New("wrap repository key")
	}
	return output.Bytes(), nil
}

// UnwrapREK decrypts a device-specific wrapped repository key locally.
func UnwrapREK(identity age.Identity, wrapped []byte) ([]byte, error) {
	if identity == nil || len(wrapped) == 0 {
		return nil, errors.New("invalid wrapped repository key")
	}
	reader, err := age.Decrypt(bytes.NewReader(wrapped), identity)
	if err != nil {
		return nil, errors.New("wrapped repository key authentication failed")
	}
	key, err := io.ReadAll(io.LimitReader(reader, REKSize+1))
	if err != nil || len(key) != REKSize {
		return nil, errors.New("invalid wrapped repository key")
	}
	return key, nil
}
