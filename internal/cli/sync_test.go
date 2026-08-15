package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/localenv/localenv/internal/cryptokit"
	"github.com/localenv/localenv/internal/pranalysis"
)

func TestApplySnapshotPreservesDeveloperContentWrites0600AndDryRunDoesNotWrite(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, ".env.local")
	initial := []byte("LOCAL_ONLY=true\n")
	if err := os.WriteFile(target, initial, 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".env.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	remote := decryptedSnapshot{".env.local": {"DATABASE_URL": []byte("non-secret-test-sentinel")}}
	var out, errOut bytes.Buffer
	if err := applySnapshot(root, remote, false, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, initial) || !strings.Contains(string(data), "DATABASE_URL=") || strings.Contains(out.String(), "non-secret-test-sentinel") || errOut.Len() != 0 {
		t.Fatalf("unsafe sync output/content: out=%q err=%q content=%q", out.String(), errOut.String(), data)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("target permissions = %v, %v", info.Mode().Perm(), err)
	}
	before := append([]byte(nil), data...)
	remote = decryptedSnapshot{".env.local": {"DATABASE_URL": []byte("changed-non-secret-sentinel")}}
	out.Reset()
	if err := applySnapshot(root, remote, true, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(before, after) || !strings.Contains(out.String(), "Would update: .env.local: DATABASE_URL") || strings.Contains(out.String(), "changed-non-secret-sentinel") {
		t.Fatalf("dry run modified or exposed data: out=%q err=%v", out.String(), err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applySnapshot(root, decryptedSnapshot{".env.local": {"DATABASE_URL": []byte("non-secret-test-sentinel")}}, false, &bytes.Buffer{}, &errOut); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unchanged target permissions = %v, %v", info.Mode().Perm(), err)
	}
}

func TestApplySnapshotRefusesDeveloperOwnedDuplicate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env.local"), []byte("DATABASE_URL=developer-owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := applySnapshot(root, decryptedSnapshot{".env.local": {"DATABASE_URL": []byte("non-secret-test-sentinel")}}, false, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("error = %v", err)
	}
}

func TestDiffSnapshotPrintsKeysButNotValues(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env.local"), []byte("LOCAL_ONLY=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := decryptedSnapshot{".env.local": {"DATABASE_URL": []byte("non-secret-test-sentinel")}}
	var out bytes.Buffer
	if err := diffSnapshot(root, remote, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Missing locally: .env.local: DATABASE_URL") || !strings.Contains(out.String(), "Local-only: .env.local: LOCAL_ONLY") || strings.Contains(out.String(), "non-secret-test-sentinel") {
		t.Fatalf("diff output = %q", out.String())
	}
}

func TestSecondDeveloperSyncDecryptsMergedSnapshotWithoutChangingLocalContent(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if output, err := exec.Command("git", "-C", root, "remote", "add", "origin", "https://github.com/acme/api.git").CombinedOutput(); err != nil {
		t.Fatalf("git remote: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(root, "localenv.yaml"), []byte("version: 1\nfiles:\n  - schema: .env.example\n    target: .env.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.example"), []byte("DATABASE_URL=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.local"), []byte("MY_DEBUG_FLAG=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rek := []byte("non-secret-test-rek-sentinel-000")
	wrapped, err := cryptokit.WrapREK(rek, identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	fileID := pranalysis.FileID(17, ".env.example", ".env.local")
	envelope, err := cryptokit.Encrypt(rek, []byte("non-secret-merged-value"), cryptokit.AAD{InstanceID: "edb7f4f6-4bc5-4eca-91cd-bfde8588e2a9", GitHubRepoID: 17, FilePath: ".env.local", KeyName: "DATABASE_URL", Scope: "baseline", Version: 1, KeyEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-session" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/repos/acme/api/pulls/current":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/repos/acme/api/snapshot":
			_ = json.NewEncoder(w).Encode(apiRepositorySnapshot{Repository: apiRepositoryCryptoState{InstanceID: "edb7f4f6-4bc5-4eca-91cd-bfde8588e2a9", GitHubRepoID: 17, Owner: "acme", Name: "api", ActiveKeyEpoch: 1, Initialized: true}, WrappedREK: wrapped, Secrets: []apiSecretSnapshot{{FileID: fileID, FilePath: ".env.local", KeyName: "DATABASE_URL", Scope: "baseline", Envelope: envelope}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	credentials := &fileStore{path: filepath.Join(t.TempDir(), "credentials.json")}
	if err := credentials.Set("last-instance", server.URL); err != nil {
		t.Fatal(err)
	}
	if err := credentials.Set(sessionKey(server.URL), "test-session"); err != nil {
		t.Fatal(err)
	}
	saved, err := json.Marshal(struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Identity string `json:"identity"`
	}{ID: "device-2", Name: "second developer", Identity: identity.String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.Set(identityKey(server.URL), string(saved)); err != nil {
		t.Fatal(err)
	}
	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWorkingDirectory) })
	remote, detectedRoot, err := syncSnapshot("", server.URL, credentials.path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := applySnapshot(detectedRoot, remote, false, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, ".env.local"))
	if err != nil || !strings.HasPrefix(string(content), "MY_DEBUG_FLAG=true\n") || !strings.Contains(string(content), "DATABASE_URL=") || strings.Contains(out.String()+errOut.String(), "non-secret-merged-value") {
		t.Fatalf("second developer sync = content %q, out %q, err %q, read %v", content, out.String(), errOut.String(), err)
	}
}

func TestDeviceIdentityUsesDeviceRegistrationPayloadNames(t *testing.T) {
	encoded, err := json.Marshal(deviceIdentity{
		ID:          "device-test-id",
		Name:        "test device",
		Recipient:   "age1testrecipient",
		Fingerprint: "sha256:0000000000000000",
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["public_recipient"] != "age1testrecipient" || payload["id"] != "device-test-id" || payload["name"] != "test device" || payload["fingerprint"] != "sha256:0000000000000000" {
		t.Fatalf("device registration payload = %#v", payload)
	}
	if _, found := payload["Recipient"]; found {
		t.Fatalf("device registration payload used Go field name: %#v", payload)
	}
}

func TestNormalizeSingleArgumentFirstAcceptsDocumentedSyntax(t *testing.T) {
	got := normalizeSingleArgumentFirst([]string{".env.local", "--instance", "https://env.example.test", "--repo", "acme/api"})
	want := []string{"--instance", "https://env.example.test", "--repo", "acme/api", ".env.local"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized arguments = %#v, want %#v", got, want)
	}
	got = normalizeSingleArgumentFirst([]string{"REDIS_URL", "--pr", "1"})
	want = []string{"--pr", "1", "REDIS_URL"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized set arguments = %#v, want %#v", got, want)
	}
}

func TestMaskedValueShowsOnlyAsterisksAndHandlesBackspace(t *testing.T) {
	var output bytes.Buffer
	value, err := maskedValue(strings.NewReader("value\bX\n"), &output)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(value), "valuX"; got != want {
		t.Fatalf("masked value = %q, want %q", got, want)
	}
	if got, want := output.String(), "*****\b \b*\r\n"; got != want || strings.Contains(got, "value") {
		t.Fatalf("masked output = %q, want only %q", got, want)
	}
}

func TestStyledOutputPreservesPlainTextWithoutTerminalColor(t *testing.T) {
	var output bytes.Buffer
	writer := styledOutput{writer: &output}
	if got := styled(writer, ansiGreen, "OK"); got != "OK" {
		t.Fatalf("plain styled text = %q", got)
	}
	if _, err := writer.Write([]byte("problem")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "problem" {
		t.Fatalf("plain writer output = %q", got)
	}
}

func TestStyledOutputColorsInteractiveErrors(t *testing.T) {
	var output bytes.Buffer
	writer := styledOutput{writer: &output, enabled: true, errorOutput: true}
	if got := styled(writer, ansiGreen, "OK"); got != ansiGreen+"OK"+ansiReset {
		t.Fatalf("styled text = %q", got)
	}
	if _, err := writer.Write([]byte("problem")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != ansiRed+"problem"+ansiReset {
		t.Fatalf("colored writer output = %q", got)
	}
}

func TestSetEncryptedPRValueAcceptsPendingReadinessPublication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.Contains(r.URL.Path, "/pulls/7/secrets/file-id/REDIS_URL") {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "non-secret-pending-value") {
			t.Fatalf("secret value was sent as plaintext: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"state":"stored","readiness":"pending"}`))
	}))
	t.Cleanup(server.Close)
	var out, errOut bytes.Buffer
	published, ok := setEncryptedPRValue(&out, &errOut, server.URL, "test-token", "acme", "api", 7, apiRepositoryCryptoState{InstanceID: "instance", GitHubRepoID: 17, ActiveKeyEpoch: 1}, bytes.Repeat([]byte{'k'}, 32), apiPullRequirement{FileID: "file-id", FilePath: ".env.local", KeyName: "REDIS_URL"}, []byte("non-secret-pending-value"))
	if !ok || published || errOut.Len() != 0 {
		t.Fatalf("pending update = published:%t ok:%t out:%q err:%q", published, ok, out.String(), errOut.String())
	}
}

func TestRuntimeHelperProcess(t *testing.T) {
	if os.Getenv("LOCALENV_RUNTIME_HELPER") != "1" {
		return
	}
	if os.Getenv("DATABASE_URL") != "runtime-test-sentinel" {
		os.Exit(55)
	}
	if os.Getenv("LOCALENV_RUNTIME_HELPER_MODE") == "fail" {
		os.Exit(42)
	}
	os.Exit(0)
}

func TestRunInjectsManagedValuesWithoutWritingDotenvTarget(t *testing.T) {
	root, server, credentials := runtimeTestRepository(t)
	defer server.Close()
	t.Setenv("LOCALENV_RUNTIME_HELPER", "1")
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	target := filepath.Join(root, ".env.local")
	var out, errOut bytes.Buffer
	code := runRuntime([]string{"--instance", server.URL, "--credential-file", credentials.path, "--", os.Args[0], "-test.run=^TestRuntimeHelperProcess$", "--"}, &out, &errOut)
	if code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("runtime result = code %d, out %q, err %q", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("runtime created dotenv target: %v", err)
	}
}

func TestRunReturnsChildExitStatusWithoutExposingSnapshotValue(t *testing.T) {
	root, server, credentials := runtimeTestRepository(t)
	defer server.Close()
	t.Setenv("LOCALENV_RUNTIME_HELPER", "1")
	t.Setenv("LOCALENV_RUNTIME_HELPER_MODE", "fail")
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	var out, errOut bytes.Buffer
	code := runRuntime([]string{"--instance", server.URL, "--credential-file", credentials.path, "--", os.Args[0], "-test.run=^TestRuntimeHelperProcess$", "--"}, &out, &errOut)
	if code != 42 || !strings.Contains(errOut.String(), "status 42") || strings.Contains(out.String()+errOut.String(), "runtime-test-sentinel") {
		t.Fatalf("runtime failure = code %d, out %q, err %q", code, out.String(), errOut.String())
	}
}

func TestDoctorChecksRuntimePrerequisites(t *testing.T) {
	root, server, credentials := runtimeTestRepository(t)
	defer server.Close()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.WriteFile(filepath.Join(root, ".env.local"), []byte("LOCAL_ONLY=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runDoctor([]string{"--instance", server.URL, "--credential-file", credentials.path}, &out, &errOut)
	if code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), "OK instance reachable") || !strings.Contains(out.String(), "OK GitHub authentication") || !strings.Contains(out.String(), "OK repository recognized") || !strings.Contains(out.String(), "OK localenv.yaml") || !strings.Contains(out.String(), "OK target .env.local") || !strings.Contains(out.String(), "OK device key") || !strings.Contains(out.String(), "OK repository encryption key") || strings.Contains(out.String(), "runtime-test-sentinel") {
		t.Fatalf("doctor result = code %d, out %q, err %q", code, out.String(), errOut.String())
	}
	if err := os.Chmod(filepath.Join(root, ".env.local"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code = runDoctor([]string{"--instance", server.URL, "--credential-file", credentials.path}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "FAIL target .env.local") {
		t.Fatalf("doctor unsafe target = code %d, out %q", code, out.String())
	}
}

func runtimeTestRepository(t *testing.T) (string, *httptest.Server, *fileStore) {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if output, err := exec.Command("git", "-C", root, "remote", "add", "origin", "https://github.com/acme/api.git").CombinedOutput(); err != nil {
		t.Fatalf("git remote: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(root, "localenv.yaml"), []byte("version: 1\nfiles:\n  - schema: .env.example\n    target: .env.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.example"), []byte("DATABASE_URL=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".env.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rek := []byte("non-secret-test-rek-sentinel-000")
	wrapped, err := cryptokit.WrapREK(rek, identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	fileID := pranalysis.FileID(17, ".env.example", ".env.local")
	envelope, err := cryptokit.Encrypt(rek, []byte("runtime-test-sentinel"), cryptokit.AAD{InstanceID: "edb7f4f6-4bc5-4eca-91cd-bfde8588e2a9", GitHubRepoID: 17, FilePath: ".env.local", KeyName: "DATABASE_URL", Scope: "baseline", Version: 1, KeyEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-session" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/repos/acme/api/pulls/current":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/repos/acme/api/snapshot":
			_ = json.NewEncoder(w).Encode(apiRepositorySnapshot{Repository: apiRepositoryCryptoState{InstanceID: "edb7f4f6-4bc5-4eca-91cd-bfde8588e2a9", GitHubRepoID: 17, Owner: "acme", Name: "api", ActiveKeyEpoch: 1, Initialized: true}, WrappedREK: wrapped, Secrets: []apiSecretSnapshot{{FileID: fileID, FilePath: ".env.local", KeyName: "DATABASE_URL", Scope: "baseline", Envelope: envelope}}})
		case "/api/v1/me":
			_ = json.NewEncoder(w).Encode(apiMe{})
		default:
			http.NotFound(w, r)
		}
	}))
	credentials := &fileStore{path: filepath.Join(t.TempDir(), "credentials.json")}
	if err := credentials.Set("last-instance", server.URL); err != nil {
		t.Fatal(err)
	}
	if err := credentials.Set(sessionKey(server.URL), "test-session"); err != nil {
		t.Fatal(err)
	}
	saved, err := json.Marshal(struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Identity string `json:"identity"`
	}{ID: "device-runtime", Name: "runtime device", Identity: identity.String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.Set(identityKey(server.URL), string(saved)); err != nil {
		t.Fatal(err)
	}
	return root, server, credentials
}
