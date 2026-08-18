package cli

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	maxChecksumBytes = 1 << 20
	maxBundleBytes   = 8 << 20
	maxArchiveBytes  = 256 << 20
	maxBinaryBytes   = 128 << 20
	sigstoreIssuer   = "https://token.actions.githubusercontent.com"
)

var (
	updatePromptInput    io.Reader = os.Stdin
	updatePromptTTYOnly            = true
	updateExecutablePath           = os.Executable
	updateLookPath                 = exec.LookPath
	updateGOOS                     = runtime.GOOS
	updateGOARCH                   = runtime.GOARCH
	updateAllowHTTP                = false
	updateHTTPClient               = &http.Client{Timeout: 60 * time.Second}
)

func runSelfUpdate(out, errOut io.Writer) int {
	if _, ok := parseReleaseVersion(Version); !ok {
		fmt.Fprintln(errOut, "localenv: self-update is only available for release builds")
		return 1
	}
	release, err := lookupLatestRelease(context.Background(), explicitLookupFor)
	if err != nil {
		state, _ := readUpdateState()
		_ = writeUpdateFailure(state)
		fmt.Fprintln(errOut, "localenv: could not check the latest release")
		return 1
	}
	_ = writeUpdateState(release)
	switch compareRelease(Version, release.TagName) {
	case releaseCurrent:
		fmt.Fprintf(out, "localenv %s is up to date\n", Version)
		return 0
	case releaseAhead:
		fmt.Fprintf(out, "localenv %s is newer than latest release %s\n", Version, release.TagName)
		return 0
	case releaseBehind:
		fmt.Fprintf(out, "Updating localenv %s → %s...\n", Version, release.TagName)
		if err := installRelease(release); err != nil {
			fmt.Fprintf(errOut, "localenv: update failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "Updated localenv %s → %s\n", Version, release.TagName)
		return 0
	default:
		fmt.Fprintln(errOut, "localenv: current build version cannot be compared with the latest release")
		return 1
	}
}

func promptAndMaybeInstallUpdate(release githubRelease, out io.Writer) error {
	if updatePromptTTYOnly && !readerIsTerminal(updatePromptInput) {
		fmt.Fprintln(out, "Run `localenv version --update` to install.")
		return nil
	}
	fmt.Fprint(out, "Update now? [y/N] ")
	answer, err := bufio.NewReader(updatePromptInput).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("could not read update confirmation: %w", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return nil
	}
	fmt.Fprintf(out, "Updating localenv %s → %s...\n", Version, release.TagName)
	if err := installRelease(release); err != nil {
		return err
	}
	fmt.Fprintf(out, "Updated localenv %s → %s\n", Version, release.TagName)
	return nil
}

func readerIsTerminal(r io.Reader) bool {
	file, ok := r.(*os.File)
	return ok && termIsTerminal(file)
}

func termIsTerminal(file *os.File) bool {
	return terminalFD(int(file.Fd()))
}

var terminalFD = func(fd int) bool {
	return term.IsTerminal(fd)
}

func installRelease(release githubRelease) error {
	archiveName, err := releaseArchiveName(release.TagName, updateGOOS, updateGOARCH)
	if err != nil {
		return err
	}
	archiveAsset, err := findReleaseAsset(release, archiveName)
	if err != nil {
		return err
	}
	checksumsAsset, err := findReleaseAsset(release, "checksums.txt")
	if err != nil {
		return err
	}
	bundleAsset, err := findReleaseAsset(release, "checksums.txt.bundle")
	if err != nil {
		return err
	}
	cosignPath, err := updateLookPath("cosign")
	if err != nil {
		return errors.New("automatic update requires cosign for Sigstore verification; install cosign and retry")
	}

	tempDir, err := os.MkdirTemp("", "localenv-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	checksumsPath := filepath.Join(tempDir, "checksums.txt")
	bundlePath := filepath.Join(tempDir, "checksums.txt.bundle")
	archivePath := filepath.Join(tempDir, archiveName)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := downloadReleaseAsset(ctx, checksumsAsset, checksumsPath, maxChecksumBytes); err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	if err := downloadReleaseAsset(ctx, bundleAsset, bundlePath, maxBundleBytes); err != nil {
		return fmt.Errorf("download signature bundle: %w", err)
	}
	if err := verifyChecksumSignature(ctx, cosignPath, release.TagName, checksumsPath, bundlePath); err != nil {
		return err
	}
	checksumData, err := os.ReadFile(checksumsPath)
	if err != nil {
		return err
	}
	expected, err := checksumForAsset(checksumData, archiveName)
	if err != nil {
		return err
	}
	if err := downloadReleaseAsset(ctx, archiveAsset, archivePath, maxArchiveBytes); err != nil {
		return fmt.Errorf("download release archive: %w", err)
	}
	if err := verifyFileChecksum(archivePath, expected); err != nil {
		return err
	}
	binaryPath, err := extractCLI(archivePath, tempDir)
	if err != nil {
		return err
	}
	if err := replaceCurrentExecutable(binaryPath); err != nil {
		return err
	}
	return nil
}

func releaseArchiveName(tag, goos, goarch string) (string, error) {
	if goos != "darwin" && goos != "linux" {
		return "", fmt.Errorf("automatic update is not supported on %s/%s", goos, goarch)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return "", fmt.Errorf("automatic update is not supported on %s/%s", goos, goarch)
	}
	return fmt.Sprintf("localenv_%s_%s_%s.tar.gz", tag, goos, goarch), nil
}

func findReleaseAsset(release githubRelease, name string) (githubReleaseAsset, error) {
	for _, asset := range release.Assets {
		if asset.Name == name && strings.TrimSpace(asset.BrowserDownloadURL) != "" {
			return asset, nil
		}
	}
	return githubReleaseAsset{}, fmt.Errorf("release %s does not contain %s", release.TagName, name)
}

func downloadReleaseAsset(ctx context.Context, asset githubReleaseAsset, destination string, maxBytes int64) error {
	parsed, err := url.Parse(asset.BrowserDownloadURL)
	if err != nil {
		return errors.New("invalid release asset URL")
	}
	if updateAllowHTTP {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("invalid release asset URL")
		}
	} else if parsed.Scheme != "https" || parsed.Hostname() != "github.com" {
		return errors.New("release asset URL is not an HTTPS github.com URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "localenv")
	response, err := updateHTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("release asset returned HTTP %d", response.StatusCode)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, maxBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written > maxBytes {
		return fmt.Errorf("release asset %s exceeds size limit", asset.Name)
	}
	return nil
}

func verifyChecksumSignature(ctx context.Context, cosignPath, tag, checksumsPath, bundlePath string) error {
	identity := fmt.Sprintf("https://github.com/%s/.github/workflows/release.yml@refs/tags/%s", githubReleasesRepo, tag)
	command := exec.CommandContext(ctx, cosignPath,
		"verify-blob",
		"--bundle", bundlePath,
		"--certificate-identity", identity,
		"--certificate-oidc-issuer", sigstoreIssuer,
		checksumsPath,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			return errors.New("release signature verification failed")
		}
		return fmt.Errorf("release signature verification failed: %s", detail)
	}
	return nil
}

func checksumForAsset(data []byte, assetName string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name != assetName {
			continue
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return zero, fmt.Errorf("invalid checksum for %s", assetName)
		}
		var result [sha256.Size]byte
		copy(result[:], digest)
		return result, nil
	}
	if err := scanner.Err(); err != nil {
		return zero, err
	}
	return zero, fmt.Errorf("checksums.txt does not contain %s", assetName)
}

func verifyFileChecksum(path string, expected [sha256.Size]byte) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hash.Sum(nil)
	if !equalDigest(actual, expected[:]) {
		return errors.New("release archive checksum verification failed")
	}
	return nil
}

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func extractCLI(archivePath, tempDir string) (string, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Name != "localenv" {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > maxBinaryBytes {
			return "", errors.New("release archive contains an invalid localenv binary")
		}
		path := filepath.Join(tempDir, "localenv.new")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
		if err != nil {
			return "", err
		}
		written, copyErr := io.Copy(file, io.LimitReader(tarReader, maxBinaryBytes+1))
		closeErr := file.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		if written != header.Size || written > maxBinaryBytes {
			return "", errors.New("release archive contains an invalid localenv binary")
		}
		return path, nil
	}
	return "", errors.New("release archive does not contain localenv")
}

func replaceCurrentExecutable(source string) error {
	destination, err := updateExecutablePath()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(destination); resolveErr == nil {
		destination = resolved
	}
	info, err := os.Stat(destination)
	if err != nil {
		return fmt.Errorf("inspect current executable: %w", err)
	}
	mode := info.Mode().Perm()
	if mode&0o111 == 0 {
		mode |= 0o755
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temp, err := os.CreateTemp(filepath.Dir(destination), ".localenv-update-")
	if err != nil {
		return fmt.Errorf("create replacement beside %s: %w", destination, err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := io.Copy(temp, input); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, destination); err != nil {
		return fmt.Errorf("replace current executable: %w", err)
	}
	return nil
}
