package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const githubReleasesRepo = "mithatakbulut/local.env"

// Version is the CLI build version. Release builds set it via -X main.version.
var Version = "dev"

var (
	latestReleaseAPI       = "https://api.github.com/repos/" + githubReleasesRepo + "/releases/latest"
	updateCheckInterval    = 24 * time.Hour
	updateStatePath        string
	updateNoticeTTYOnly    = true
	opportunisticLookupFor = 2 * time.Second
	explicitLookupFor      = 5 * time.Second
)

type releaseStatus int

const (
	releaseUnknown releaseStatus = iota
	releaseBehind
	releaseCurrent
	releaseAhead
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

type updateState struct {
	CheckedAt string `json:"checked_at"`
	TagName   string `json:"tag_name"`
	HTMLURL   string `json:"html_url"`
}

func runVersion(args []string, out, errOut io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(errOut, "Usage: localenv version")
		return 2
	}
	fmt.Fprintln(out, Version)
	release, err := lookupLatestRelease(context.Background(), explicitLookupFor)
	if err != nil {
		fmt.Fprintln(out, "Could not check for updates")
		return 0
	}
	_ = writeUpdateState(release)
	switch compareRelease(Version, release.TagName) {
	case releaseBehind:
		fmt.Fprintf(out, "%s %s\n", styled(out, ansiYellow, "Update available:"), release.TagName)
		fmt.Fprintln(out, releasePage(release))
	case releaseCurrent:
		fmt.Fprintln(out, "Up to date")
	case releaseAhead:
		fmt.Fprintf(out, "Newer than latest release %s\n", release.TagName)
	default:
		fmt.Fprintf(out, "Latest release: %s\n", release.TagName)
		fmt.Fprintln(out, releasePage(release))
	}
	return 0
}

func doctorCLIVersion(out io.Writer) {
	detail := Version
	if release, ok := cachedOrLookupLatest(); ok {
		switch compareRelease(Version, release.TagName) {
		case releaseBehind:
			detail = Version + " (update available: " + release.TagName + ")"
		case releaseUnknown:
			detail = Version + " (latest release: " + release.TagName + ")"
		}
	}
	doctorResult(out, "cli version", true, detail)
}

func shouldNotifyUpdate(command string) bool {
	switch command {
	case "--version", "version":
		return false
	default:
		return true
	}
}

func notifyUpdate(errOut io.Writer) {
	if os.Getenv("LOCALENV_NO_UPDATE_NOTIFIER") != "" || os.Getenv("CI") != "" {
		return
	}
	if updateNoticeTTYOnly && !writerIsTerminal(errOut) {
		return
	}
	release, ok := cachedOrLookupLatest()
	if !ok || compareRelease(Version, release.TagName) != releaseBehind {
		return
	}
	raw := unwrapWriter(errOut)
	fmt.Fprintln(raw)
	fmt.Fprintf(raw, "%s %s → %s\n", styled(errOut, ansiYellow, "Update available:"), Version, release.TagName)
	fmt.Fprintln(raw, releasePage(release))
}

func cachedOrLookupLatest() (githubRelease, bool) {
	state, ok := readUpdateState()
	if ok && state.release.TagName != "" && time.Since(state.checkedAt) < updateCheckInterval {
		return state.release, true
	}
	release, err := lookupLatestRelease(context.Background(), opportunisticLookupFor)
	if err != nil {
		if ok && state.release.TagName != "" {
			return state.release, true
		}
		return githubRelease{}, false
	}
	_ = writeUpdateState(release)
	return release, true
}

func lookupLatestRelease(ctx context.Context, timeout time.Duration) (githubRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseAPI, nil)
	if err != nil {
		return githubRelease{}, err
	}
	request.Header.Set("User-Agent", "localenv")
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := (&http.Client{Timeout: timeout}).Do(request)
	if err != nil {
		return githubRelease{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return githubRelease{}, errors.New("latest release lookup failed")
	}
	var release githubRelease
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&release); err != nil {
		return githubRelease{}, err
	}
	release.TagName = strings.TrimSpace(release.TagName)
	if release.TagName == "" {
		return githubRelease{}, errors.New("latest release lookup failed")
	}
	return release, nil
}

func releasePage(release githubRelease) string {
	if release.HTMLURL != "" {
		return release.HTMLURL
	}
	return "https://github.com/" + githubReleasesRepo + "/releases/tag/" + release.TagName
}

type parsedUpdateState struct {
	checkedAt time.Time
	release   githubRelease
}

func readUpdateState() (parsedUpdateState, bool) {
	data, err := os.ReadFile(updateStateFile())
	if err != nil {
		return parsedUpdateState{}, false
	}
	var state updateState
	if json.Unmarshal(data, &state) != nil || strings.TrimSpace(state.TagName) == "" {
		return parsedUpdateState{}, false
	}
	checkedAt, err := time.Parse(time.RFC3339, state.CheckedAt)
	if err != nil {
		return parsedUpdateState{}, false
	}
	return parsedUpdateState{
		checkedAt: checkedAt,
		release: githubRelease{
			TagName: strings.TrimSpace(state.TagName),
			HTMLURL: strings.TrimSpace(state.HTMLURL),
		},
	}, true
}

func writeUpdateState(release githubRelease) error {
	path := updateStateFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(updateState{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		TagName:   release.TagName,
		HTMLURL:   release.HTMLURL,
	})
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".localenv-update-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err == nil {
		_, err = temp.Write(data)
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func updateStateFile() string {
	if updateStatePath != "" {
		return updateStatePath
	}
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "localenv", "update-check.json")
}

func unwrapWriter(w io.Writer) io.Writer {
	if styled, ok := w.(styledOutput); ok {
		return styled.writer
	}
	return w
}

func writerIsTerminal(w io.Writer) bool {
	switch typed := unwrapWriter(w).(type) {
	case *os.File:
		return term.IsTerminal(int(typed.Fd()))
	default:
		return false
	}
}

type semver struct {
	major int
	minor int
	patch int
}

func compareRelease(current, latest string) releaseStatus {
	currentVersion, currentOK := parseReleaseVersion(current)
	latestVersion, latestOK := parseReleaseVersion(latest)
	if !currentOK || !latestOK {
		return releaseUnknown
	}
	switch {
	case currentVersion.less(latestVersion):
		return releaseBehind
	case latestVersion.less(currentVersion):
		return releaseAhead
	default:
		return releaseCurrent
	}
}

func parseReleaseVersion(value string) (semver, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "v")
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	major, ok := parseVersionPart(parts[0])
	if !ok {
		return semver{}, false
	}
	minor, ok := parseVersionPart(parts[1])
	if !ok {
		return semver{}, false
	}
	patch, ok := parseVersionPart(parts[2])
	if !ok {
		return semver{}, false
	}
	return semver{major: major, minor: minor, patch: patch}, true
}

func parseVersionPart(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (v semver) less(other semver) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}
