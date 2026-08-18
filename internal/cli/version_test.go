package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCompareRelease(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    releaseStatus
	}{
		{current: "v1.1.0", latest: "v1.1.3", want: releaseBehind},
		{current: "1.1.3", latest: "v1.1.3", want: releaseCurrent},
		{current: "v1.2.0", latest: "v1.1.3", want: releaseAhead},
		{current: "dev", latest: "v1.1.3", want: releaseUnknown},
		{current: "acceptance", latest: "v1.1.3", want: releaseUnknown},
		{current: "v1.1.3-29-gc437091", latest: "v1.1.3", want: releaseUnknown},
	}
	for _, test := range tests {
		if got := compareRelease(test.current, test.latest); got != test.want {
			t.Fatalf("compareRelease(%q, %q) = %v, want %v", test.current, test.latest, got, test.want)
		}
	}
}

func TestVersionCommandReportsUpdateWhenBehind(t *testing.T) {
	isolateUpdateState(t)
	Version = "v1.1.0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases/latest" || r.Header.Get("User-Agent") == "" {
			t.Fatalf("unexpected request %s ua=%q", r.URL.Path, r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.1.3","html_url":"https://github.com/mithatakbulut/local.env/releases/tag/v1.1.3"}`))
	}))
	t.Cleanup(server.Close)
	latestReleaseAPI = server.URL + "/releases/latest"

	var out, errOut bytes.Buffer
	if code := Run([]string{"version"}, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("version exit %d err=%q", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "v1.1.0") || !strings.Contains(got, "Update available:") || !strings.Contains(got, "v1.1.3") || !strings.Contains(got, "https://github.com/mithatakbulut/local.env/releases/tag/v1.1.3") || !strings.Contains(got, "localenv version --update") {
		t.Fatalf("version output = %q", got)
	}
}

func TestVersionFlagPrintsOnlyBuildVersion(t *testing.T) {
	isolateUpdateState(t)
	Version = "v1.1.0"
	var out, errOut bytes.Buffer
	if code := Run([]string{"--version"}, &out, &errOut); code != 0 || errOut.Len() != 0 || strings.TrimSpace(out.String()) != "v1.1.0" {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestVersionCommandStaysCurrentWithoutFailingLookup(t *testing.T) {
	isolateUpdateState(t)
	Version = "v1.1.3"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	latestReleaseAPI = server.URL

	var out, errOut bytes.Buffer
	if code := Run([]string{"version"}, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("version exit %d err=%q", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "v1.1.3") || !strings.Contains(got, "Could not check for updates") || strings.Contains(got, "Update available:") {
		t.Fatalf("version output = %q", got)
	}
}

func TestVersionCommandReportsUpToDate(t *testing.T) {
	isolateUpdateState(t)
	Version = "v1.1.3"
	stubLatestRelease(t, "v1.1.3")

	var out bytes.Buffer
	if code := Run([]string{"version"}, &out, io.Discard); code != 0 {
		t.Fatalf("version exit %d", code)
	}
	got := out.String()
	if !strings.Contains(got, "v1.1.3") || !strings.Contains(got, "Up to date") {
		t.Fatalf("version output = %q", got)
	}
}

func TestHelpPrintsUpdateNoticeWhenBehind(t *testing.T) {
	isolateUpdateState(t)
	updateNoticeTTYOnly = false
	Version = "v1.1.0"
	stubLatestRelease(t, "v1.1.3")

	var out, errOut bytes.Buffer
	if code := Run([]string{"help"}, &out, &errOut); code != 0 {
		t.Fatalf("help exit %d", code)
	}
	if strings.Contains(out.String(), "Update available:") {
		t.Fatalf("notice leaked to stdout: %q", out.String())
	}
	got := errOut.String()
	if !strings.Contains(got, "Update available:") || !strings.Contains(got, "v1.1.0 → v1.1.3") || !strings.Contains(got, "https://github.com/"+githubReleasesRepo+"/releases/tag/v1.1.3") || !strings.Contains(got, "localenv version --update") {
		t.Fatalf("update notice = %q", got)
	}
}

func TestVersionFlagDoesNotPrintUpdateNotice(t *testing.T) {
	isolateUpdateState(t)
	updateNoticeTTYOnly = false
	Version = "v1.1.0"
	stubLatestRelease(t, "v1.1.3")

	var out, errOut bytes.Buffer
	if code := Run([]string{"--version"}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "v1.1.0" || errOut.Len() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestUpdateNoticeUsesCachedReleaseWithoutRefetchingAndDoesNotRepeat(t *testing.T) {
	isolateUpdateState(t)
	updateNoticeTTYOnly = false
	Version = "v1.1.0"
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"tag_name":"v1.1.3","html_url":"https://github.com/` + githubReleasesRepo + `/releases/tag/v1.1.3"}`))
	}))
	t.Cleanup(server.Close)
	latestReleaseAPI = server.URL

	var first, second bytes.Buffer
	notifyUpdate(&first)
	notifyUpdate(&second)
	if hits != 1 {
		t.Fatalf("lookups = %d, want 1", hits)
	}
	if !strings.Contains(first.String(), "v1.1.0 → v1.1.3") || second.Len() != 0 {
		t.Fatalf("first=%q second=%q", first.String(), second.String())
	}
}

func TestUpdateNoticePromptsOnInteractiveInput(t *testing.T) {
	isolateUpdateState(t)
	updateNoticeTTYOnly = false
	updatePromptTTYOnly = false
	updatePromptInput = strings.NewReader("n\n")
	Version = "v1.1.0"
	stubLatestRelease(t, "v1.1.3")

	var out bytes.Buffer
	notifyUpdate(&out)
	if !strings.Contains(out.String(), "Update now? [y/N]") {
		t.Fatalf("notice=%q", out.String())
	}
}

func TestUpdateNoticeBacksOffAfterFailedLookup(t *testing.T) {
	isolateUpdateState(t)
	updateNoticeTTYOnly = false
	Version = "v1.1.0"
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	latestReleaseAPI = server.URL

	var first, second bytes.Buffer
	notifyUpdate(&first)
	notifyUpdate(&second)
	if hits != 1 {
		t.Fatalf("lookups = %d, want 1", hits)
	}
	if first.Len() != 0 || second.Len() != 0 {
		t.Fatalf("first=%q second=%q", first.String(), second.String())
	}
}

func TestLookupLatestReleaseAllowsLargeGitHubPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"body":"`+strings.Repeat("x", 40<<10)+`","tag_name":"v1.1.3","html_url":"https://github.com/`+githubReleasesRepo+`/releases/tag/v1.1.3"}`)
	}))
	t.Cleanup(server.Close)
	original := latestReleaseAPI
	latestReleaseAPI = server.URL
	t.Cleanup(func() { latestReleaseAPI = original })

	release, err := lookupLatestRelease(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if release.TagName != "v1.1.3" {
		t.Fatalf("tag = %q", release.TagName)
	}
}

func TestUpdateNoticeDisabledByEnv(t *testing.T) {
	isolateUpdateState(t)
	updateNoticeTTYOnly = false
	t.Setenv("LOCALENV_NO_UPDATE_NOTIFIER", "1")
	Version = "v1.1.0"
	stubLatestRelease(t, "v1.1.3")

	var errOut bytes.Buffer
	notifyUpdate(&errOut)
	if errOut.Len() != 0 {
		t.Fatalf("notice = %q", errOut.String())
	}
}

func isolateUpdateState(t *testing.T) {
	t.Helper()
	t.Setenv("CI", "")
	t.Setenv("LOCALENV_NO_UPDATE_NOTIFIER", "")
	originalPath := updateStatePath
	originalNoticeTTY := updateNoticeTTYOnly
	originalVersion := Version
	originalFailureRetryInterval := updateFailureRetryInterval
	originalLatestReleaseAPI := latestReleaseAPI
	originalPromptInput := updatePromptInput
	originalPromptTTY := updatePromptTTYOnly
	originalExecutablePath := updateExecutablePath
	originalLookPath := updateLookPath
	originalGOOS := updateGOOS
	originalGOARCH := updateGOARCH
	originalAllowHTTP := updateAllowHTTP
	originalHTTPClient := updateHTTPClient
	updateStatePath = filepath.Join(t.TempDir(), "update-check.json")
	updatePromptInput = os.Stdin
	updatePromptTTYOnly = true
	updateExecutablePath = os.Executable
	updateLookPath = exec.LookPath
	updateGOOS = runtime.GOOS
	updateGOARCH = runtime.GOARCH
	updateAllowHTTP = false
	updateHTTPClient = &http.Client{Timeout: 60 * time.Second}
	t.Cleanup(func() {
		updateStatePath = originalPath
		updateNoticeTTYOnly = originalNoticeTTY
		Version = originalVersion
		updateFailureRetryInterval = originalFailureRetryInterval
		latestReleaseAPI = originalLatestReleaseAPI
		updatePromptInput = originalPromptInput
		updatePromptTTYOnly = originalPromptTTY
		updateExecutablePath = originalExecutablePath
		updateLookPath = originalLookPath
		updateGOOS = originalGOOS
		updateGOARCH = originalGOARCH
		updateAllowHTTP = originalAllowHTTP
		updateHTTPClient = originalHTTPClient
	})
}

func stubLatestRelease(t *testing.T, tag string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"` + tag + `","html_url":"https://github.com/` + githubReleasesRepo + `/releases/tag/` + tag + `"}`))
	}))
	t.Cleanup(server.Close)
	latestReleaseAPI = server.URL
}
