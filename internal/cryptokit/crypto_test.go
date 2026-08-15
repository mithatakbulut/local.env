package cryptokit

import (
	"bytes"
	"encoding/json"
	"testing"

	"filippo.io/age"
)

func testAAD() AAD {
	return AAD{InstanceID: "edb7f4f6-4bc5-4eca-91cd-bfde8588e2a9", GitHubRepoID: 17, FilePath: "apps/api/.env.local", KeyName: "TEST_SECRET", Scope: "baseline", Version: 1, KeyEpoch: 1}
}

func TestEncryptDecryptAndCanonicalAAD(t *testing.T) {
	rek, err := GenerateREK()
	if err != nil {
		t.Fatal(err)
	}
	aad := testAAD()
	first, err := aad.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	second, err := aad.Bytes()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("AAD is not deterministic: %q, %q, %v", first, second, err)
	}
	const expectedAAD = "localenv:v1\x00edb7f4f6-4bc5-4eca-91cd-bfde8588e2a9\x0017\x00apps/api/.env.local\x00TEST_SECRET\x00baseline\x00\x001\x001"
	if string(first) != expectedAAD {
		t.Fatalf("AAD = %q, want %q", first, expectedAAD)
	}
	plaintext := []byte("non-secret-test-value")
	envelope, err := Encrypt(rek, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(rek, envelope, aad)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt() = %q, %v", got, err)
	}
	serialized, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, plaintext) {
		t.Fatal("serialized envelope contains plaintext")
	}
	other := aad
	other.KeyName = "OTHER_SECRET"
	if _, err := Decrypt(rek, envelope, other); err == nil {
		t.Fatal("altered AAD decrypted ciphertext")
	}
}

func TestTamperingAndWrongKeyFailAuthentication(t *testing.T) {
	rek, err := GenerateREK()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Encrypt(rek, []byte("non-secret-test-value"), testAAD())
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	if _, err := Decrypt(rek, envelope, testAAD()); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	other, err := GenerateREK()
	if err != nil {
		t.Fatal(err)
	}
	clean, err := Encrypt(rek, []byte("non-secret-test-value"), testAAD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(other, clean, testAAD()); err == nil {
		t.Fatal("wrong key decrypted ciphertext")
	}
	clean.Nonce[0] ^= 1
	if _, err := Decrypt(rek, clean, testAAD()); err == nil {
		t.Fatal("tampered nonce decrypted")
	}
}

func TestWrapAndUnwrapREK(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rek, err := GenerateREK()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapREK(rek, identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapREK(identity, wrapped)
	if err != nil || !bytes.Equal(got, rek) {
		t.Fatalf("UnwrapREK() = %x, %v", got, err)
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapREK(wrong, wrapped); err == nil {
		t.Fatal("wrong identity unwrapped repository key")
	}
}
