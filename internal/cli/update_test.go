package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseArchiveName(t *testing.T) {
	name, err := releaseArchiveName("v1.2.3", "darwin", "arm64")
	if err != nil || name != "localenv_v1.2.3_darwin_arm64.tar.gz" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	if _, err := releaseArchiveName("v1.2.3", "windows", "amd64"); err == nil {
		t.Fatal("expected unsupported platform error")
	}
}

func TestChecksumForAsset(t *testing.T) {
	want := sha256.Sum256([]byte("archive"))
	data := []byte(fmt.Sprintf("%x  localenv_v1.2.3_linux_amd64.tar.gz\n", want))
	got, err := checksumForAsset(data, "localenv_v1.2.3_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("checksum=%x want=%x", got, want)
	}
}

func TestExtractCLIRejectsMissingBinary(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "release.tar.gz")
	writeTestArchive(t, archive, map[string][]byte{"localenv-server": []byte("server")})
	if _, err := extractCLI(archive, t.TempDir()); err == nil {
		t.Fatal("expected missing localenv error")
	}
}

func TestVersionUpdateDownloadsVerifiesAndReplacesBinary(t *testing.T) {
	isolateUpdateState(t)
	Version = "v1.0.0"
	updateGOOS = "linux"
	updateGOARCH = "amd64"
	updateAllowHTTP = true

	archiveName := "localenv_v1.1.0_linux_amd64.tar.gz"
	archivePath := filepath.Join(t.TempDir(), archiveName)
	writeTestArchive(t, archivePath, map[string][]byte{
		"localenv":        []byte("new-localenv-binary"),
		"localenv-server": []byte("new-server-binary"),
	})
	archiveData, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archiveData)
	checksums := []byte(fmt.Sprintf("%x  %s\n", digest, archiveName))
	bundle := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":"v1.1.0","html_url":"%s/release","assets":[{"name":%q,"browser_download_url":"%s/archive"},{"name":"checksums.txt","browser_download_url":"%s/checksums"},{"name":"checksums.txt.bundle","browser_download_url":"%s/bundle"}]}`, server.URL, archiveName, server.URL, server.URL, server.URL)
		case "/archive":
			_, _ = w.Write(archiveData)
		case "/checksums":
			_, _ = w.Write(checksums)
		case "/bundle":
			_, _ = w.Write(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	latestReleaseAPI = server.URL + "/latest"

	fakeCosign := filepath.Join(t.TempDir(), "cosign")
	if err := os.WriteFile(fakeCosign, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	updateLookPath = func(name string) (string, error) {
		if name != "cosign" {
			return "", fmt.Errorf("unexpected binary %q", name)
		}
		return fakeCosign, nil
	}

	destination := filepath.Join(t.TempDir(), "localenv")
	if err := os.WriteFile(destination, []byte("old-localenv-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	updateExecutablePath = func() (string, error) { return destination, nil }

	var out, errOut bytes.Buffer
	if code := runVersion([]string{"--update"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-localenv-binary" {
		t.Fatalf("binary=%q", got)
	}
	if !strings.Contains(out.String(), "Updated localenv v1.0.0 → v1.1.0") || errOut.Len() != 0 {
		t.Fatalf("out=%q err=%q", out.String(), errOut.String())
	}
}

func TestVersionUpdateRejectsChecksumMismatch(t *testing.T) {
	temp := t.TempDir()
	archive := filepath.Join(temp, "archive.tar.gz")
	writeTestArchive(t, archive, map[string][]byte{"localenv": []byte("new")})
	wrong := sha256.Sum256([]byte("different"))
	if err := verifyFileChecksum(archive, wrong); err == nil {
		t.Fatal("expected checksum verification failure")
	}
}

func TestPromptDeclineDoesNotInstall(t *testing.T) {
	isolateUpdateState(t)
	updatePromptTTYOnly = false
	updatePromptInput = strings.NewReader("n\n")
	var out bytes.Buffer
	if err := promptAndMaybeInstallUpdate(githubRelease{TagName: "v1.1.0"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Update now? [y/N]") || strings.Contains(out.String(), "Updating") {
		t.Fatalf("output=%q", out.String())
	}
}

func writeTestArchive(t *testing.T, destination string, files map[string][]byte) {
	t.Helper()
	file, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, data := range files {
		header := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tarWriter, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
