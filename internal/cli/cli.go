// Package cli implements the intentionally small P4 localenv command surface.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/localenv/localenv/internal/cryptokit"
	"github.com/localenv/localenv/internal/dotenv"
	"github.com/localenv/localenv/internal/pranalysis"
	"github.com/localenv/localenv/internal/repository"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const keyringService = "localenv"

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

type styledOutput struct {
	writer      io.Writer
	enabled     bool
	errorOutput bool
}

func (w styledOutput) Write(data []byte) (int, error) {
	if !w.enabled || !w.errorOutput || len(data) == 0 {
		return w.writer.Write(data)
	}
	if _, err := io.WriteString(w.writer, ansiRed); err != nil {
		return 0, err
	}
	n, err := w.writer.Write(data)
	if _, resetErr := io.WriteString(w.writer, ansiReset); err == nil {
		err = resetErr
	}
	return n, err
}

func decorateOutput(writer io.Writer, errorOutput bool) io.Writer {
	file, isFile := writer.(*os.File)
	return styledOutput{writer: writer, enabled: isFile && term.IsTerminal(int(file.Fd())) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb", errorOutput: errorOutput}
}

func styled(out io.Writer, color, text string) string {
	writer, ok := out.(styledOutput)
	if !ok || !writer.enabled {
		return text
	}
	return color + text + ansiReset
}

// Run executes P4 commands. Values stored by this package are session tokens
// and age identities only; neither is ever printed.
func Run(args []string, out, errOut io.Writer) int {
	out = decorateOutput(out, false)
	errOut = decorateOutput(errOut, true)
	if len(args) == 0 {
		usage(out)
		return 2
	}
	switch args[0] {
	case "login":
		return runLogin(args[1:], out, errOut)
	case "status":
		return runStatus(args[1:], out, errOut)
	case "logout":
		return runLogout(args[1:], out, errOut)
	case "repo":
		return runRepo(args[1:], out, errOut)
	case "resolve":
		return runResolve(args[1:], out, errOut)
	case "set":
		return runSet(args[1:], out, errOut)
	case "import":
		return runImport(args[1:], out, errOut)
	case "sync":
		return runSync(args[1:], out, errOut)
	case "diff":
		return runDiff(args[1:], out, errOut)
	case "run":
		return runRuntime(args[1:], out, errOut)
	case "doctor":
		return runDoctor(args[1:], out, errOut)
	case "devices":
		return runDevices(args[1:], out, errOut)
	case "keys":
		return runKeys(args[1:], out, errOut)
	case "--version", "version":
		return 0
	case "--help", "help":
		usage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "localenv: unknown command %q\n", args[0])
		usage(errOut)
		return 2
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, styled(out, ansiCyan, "Usage: localenv <command>"))
	fmt.Fprintln(out, "\n"+styled(out, ansiCyan, "Commands:"))
	fmt.Fprintln(out, "  login <instance-url>  Sign in with GitHub and register this device")
	fmt.Fprintln(out, "  status                Show signed-in user, repository, and device")
	fmt.Fprintln(out, "  logout                Revoke and remove the local session")
	fmt.Fprintln(out, "  repo init             Initialize client-side repository encryption")
	fmt.Fprintln(out, "  resolve --pr NUMBER   Encrypt and resolve missing PR values")
	fmt.Fprintln(out, "  set KEY --pr NUMBER   Encrypt and set one PR value")
	fmt.Fprintln(out, "  import FILE           Encrypt declared values from a local dotenv file")
	fmt.Fprintln(out, "  sync                  Download, decrypt, and safely update local dotenv files")
	fmt.Fprintln(out, "  diff                  Show key-level local/remote dotenv differences")
	fmt.Fprintln(out, "  run -- COMMAND        Run a command with managed values injected in memory")
	fmt.Fprintln(out, "  doctor                Check local.env connectivity and local configuration")
	fmt.Fprintln(out, "  devices               List, approve, or revoke repository devices")
	fmt.Fprintln(out, "  keys rotate           Re-encrypt current values with a new repository key")
}

// runRuntime decrypts the repository snapshot only in this process, adds its
// declared values to a child environment, and never touches dotenv targets.
func runRuntime(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(errOut)
	pr := flags.Int("pr", 0, "include pending values from this pull request")
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() == 0 || *pr < 0 {
		fmt.Fprintln(errOut, "Usage: localenv run [--pr NUMBER] [--repo owner/name] [--instance instance-url] [--credential-file path] -- COMMAND [ARG...]")
		return 2
	}
	snapshot, _, err := syncSnapshot(*repositoryFlag, *instanceFlag, *credentialFile, *pr)
	if err != nil {
		var pending deviceAccessPendingError
		if errors.As(err, &pending) {
			fmt.Fprintf(errOut, "Access pending. Approval code: %s\n", pending.Code)
			return 1
		}
		fmt.Fprintln(errOut, "localenv: could not download and decrypt the repository snapshot; no command was started")
		return 1
	}
	defer clearSnapshot(snapshot)
	environment, err := runtimeEnvironment(os.Environ(), snapshot)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: the repository contract assigns one environment key to multiple targets; no command was started")
		return 1
	}
	commandArgs := flags.Args()
	command := exec.Command(commandArgs[0], commandArgs[1:]...)
	command.Env = environment
	command.Stdin = os.Stdin
	command.Stdout = out
	command.Stderr = errOut
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			fmt.Fprintf(errOut, "localenv: command exited with status %d\n", exit.ExitCode())
			return exit.ExitCode()
		}
		fmt.Fprintln(errOut, "localenv: could not start command")
		return 1
	}
	return 0
}

// runtimeEnvironment replaces inherited keys once and rejects ambiguous
// duplicate managed keys rather than silently selecting one dotenv target.
func runtimeEnvironment(inherited []string, snapshot decryptedSnapshot) ([]string, error) {
	managed := make(map[string][]byte)
	for _, target := range sortedTargets(snapshot) {
		for key, value := range snapshot[target] {
			if _, exists := managed[key]; exists {
				return nil, errors.New("duplicate runtime key")
			}
			managed[key] = value
		}
	}
	environment := make([]string, 0, len(inherited)+len(managed))
	for _, entry := range inherited {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, overridden := managed[key]; !overridden {
			environment = append(environment, entry)
		}
	}
	for _, key := range sortedRuntimeKeys(managed) {
		environment = append(environment, key+"="+string(managed[key]))
	}
	return environment, nil
}

func sortedRuntimeKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func runDoctor(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(errOut)
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(errOut, "Usage: localenv doctor [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}

	ok := true
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		doctorResult(out, "credential storage", false, "unavailable")
		return 1
	}
	instance, token, sessionErr := currentSession(secrets, *instanceFlag)
	if sessionErr != nil {
		doctorResult(out, "GitHub authentication", false, "not signed in")
		ok = false
	} else {
		if instanceReachable(instance) {
			doctorResult(out, "instance reachable", true, "")
		} else {
			doctorResult(out, "instance reachable", false, "unavailable")
			ok = false
		}
		if _, err := fetchMe(context.Background(), instance, token); err != nil {
			doctorResult(out, "GitHub authentication", false, "invalid or expired")
			ok = false
		} else {
			doctorResult(out, "GitHub authentication", true, "")
		}
	}

	gitIdentity, gitErr := repository.Detect(context.Background(), ".")
	if gitErr != nil {
		doctorResult(out, "repository recognized", false, "not a supported GitHub repository")
		return 1
	}
	doctorResult(out, "repository recognized", true, "")
	owner, name := gitIdentity.Owner, gitIdentity.Name
	if *repositoryFlag != "" {
		var err error
		owner, name, err = selectedRepository(*repositoryFlag)
		if err != nil {
			doctorResult(out, "selected repository", false, "invalid")
			return 1
		}
	}
	contract, contractErr := repository.LoadSnapshot(gitIdentity.Root)
	if contractErr != nil {
		doctorResult(out, "localenv.yaml", false, "invalid")
		ok = false
	} else {
		doctorResult(out, "localenv.yaml", true, "")
		for _, file := range contract.Files {
			targetOK, detail := doctorTarget(gitIdentity.Root, file.Target)
			doctorResult(out, "target "+file.Target, targetOK, detail)
			if !targetOK {
				ok = false
			}
		}
	}
	if sessionErr != nil {
		return 1
	}
	identity, identityErr := loadIdentity(secrets, instance)
	if identityErr != nil {
		doctorResult(out, "device key", false, "not found")
		return 1
	}
	doctorResult(out, "device key", true, "")
	snapshot, snapshotErr := fetchRepositorySnapshot(context.Background(), instance, token, owner, name)
	if snapshotErr != nil {
		doctorResult(out, "repository encryption key", false, "unavailable")
		return 1
	}
	rek, unwrapErr := cryptokit.UnwrapREK(identity.Identity, snapshot.WrappedREK)
	if unwrapErr != nil {
		doctorResult(out, "repository encryption key", false, "unavailable for this device")
		return 1
	}
	clear(rek)
	doctorResult(out, "repository encryption key", true, "")
	return boolExit(ok)
}

func boolExit(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

func doctorResult(out io.Writer, check string, ok bool, detail string) {
	status := "FAIL"
	color := ansiRed
	if ok {
		status = "OK"
		color = ansiGreen
	}
	if detail == "" {
		fmt.Fprintf(out, "%s %s\n", styled(out, color, status), check)
		return
	}
	fmt.Fprintf(out, "%s %s: %s\n", styled(out, color, status), check, detail)
}

func instanceReachable(instance string) bool {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, instance+"/healthz", nil)
	if err != nil {
		return false
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode >= 200 && response.StatusCode < 300
}

func doctorTarget(root, target string) (bool, string) {
	ignored, err := gitIgnored(root, target)
	if err != nil || !ignored {
		return false, "must be Git-ignored"
	}
	path, err := safeLocalTarget(root, target)
	if err != nil {
		return false, "must not be a symlink and must stay inside the repository"
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, "ignored and safe"
	}
	if err != nil {
		return false, "could not inspect"
	}
	if info.Mode().Perm() != 0o600 {
		return false, "must be mode 0600; run localenv import or localenv sync"
	}
	return true, "ignored and safe"
}

func runSync(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	flags.SetOutput(errOut)
	pr := flags.Int("pr", 0, "include pending values from this pull request")
	dryRun := flags.Bool("dry-run", false, "show key-level changes without writing files")
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *pr < 0 {
		fmt.Fprintln(errOut, "Usage: localenv sync [--pr NUMBER] [--dry-run] [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	remote, root, err := syncSnapshot(*repositoryFlag, *instanceFlag, *credentialFile, *pr)
	if err != nil {
		var pending deviceAccessPendingError
		if errors.As(err, &pending) {
			fmt.Fprintf(errOut, "Access pending. Approval code: %s\n", pending.Code)
			return 1
		}
		fmt.Fprintln(errOut, "localenv: could not download and decrypt the repository snapshot")
		return 1
	}
	if err := applySnapshot(root, remote, *dryRun, out, errOut); err != nil {
		fmt.Fprintln(errOut, "localenv: could not safely synchronize local dotenv files")
		return 1
	}
	if *dryRun {
		fmt.Fprintln(out, "Dry run complete; no local dotenv files were changed.")
	} else {
		fmt.Fprintln(out, "Local environment synchronized.")
	}
	return 0
}

func runDiff(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(errOut)
	pr := flags.Int("pr", 0, "include pending values from this pull request")
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *pr < 0 {
		fmt.Fprintln(errOut, "Usage: localenv diff [--pr NUMBER] [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	remote, root, err := syncSnapshot(*repositoryFlag, *instanceFlag, *credentialFile, *pr)
	if err != nil {
		var pending deviceAccessPendingError
		if errors.As(err, &pending) {
			fmt.Fprintf(errOut, "Access pending. Approval code: %s\n", pending.Code)
			return 1
		}
		fmt.Fprintln(errOut, "localenv: could not download and decrypt the repository snapshot")
		return 1
	}
	if err := diffSnapshot(root, remote, out); err != nil {
		fmt.Fprintln(errOut, "localenv: could not safely inspect local dotenv files")
		return 1
	}
	return 0
}

type decryptedSnapshot map[string]map[string][]byte // target path -> key -> value

type deviceAccessPendingError struct{ Code string }

func (e deviceAccessPendingError) Error() string { return "device access is pending approval" }

func syncSnapshot(repositoryFlag, instanceFlag, credentialFile string, pr int) (decryptedSnapshot, string, error) {
	secrets, err := credentialStore(credentialFile)
	if err != nil {
		return nil, "", err
	}
	instance, token, err := currentSession(secrets, instanceFlag)
	if err != nil {
		return nil, "", err
	}
	identity, err := loadIdentity(secrets, instance)
	if err != nil {
		return nil, "", err
	}
	gitIdentity, err := repository.Detect(context.Background(), ".")
	if err != nil {
		return nil, "", err
	}
	owner, name := gitIdentity.Owner, gitIdentity.Name
	if repositoryFlag != "" {
		owner, name, err = selectedRepository(repositoryFlag)
		if err != nil {
			return nil, "", err
		}
	}
	contract, err := repository.LoadSnapshot(gitIdentity.Root)
	if err != nil {
		return nil, "", err
	}
	if pr == 0 && gitIdentity.Branch != "" {
		pr, err = fetchCurrentPullRequest(context.Background(), instance, token, owner, name, gitIdentity.Branch)
		if err != nil {
			return nil, "", err
		}
	}
	var snapshot apiRepositorySnapshot
	if pr > 0 {
		snapshot, err = fetchPullRequestSnapshot(context.Background(), instance, token, owner, name, pr)
	} else {
		snapshot, err = fetchRepositorySnapshot(context.Background(), instance, token, owner, name)
	}
	if err != nil {
		pending, requestErr := createDeviceAccessRequest(context.Background(), instance, token, owner, name)
		if requestErr == nil {
			return nil, "", deviceAccessPendingError{Code: pending.Code}
		}
		return nil, "", err
	}
	rek, err := cryptokit.UnwrapREK(identity.Identity, snapshot.WrappedREK)
	if err != nil {
		return nil, "", err
	}
	defer clear(rek)
	files := make(map[string]repository.SchemaFile, len(contract.Files))
	for _, file := range contract.Files {
		files[pranalysis.FileID(snapshot.Repository.GitHubRepoID, file.Schema, file.Target)] = file
	}
	result := make(decryptedSnapshot)
	for _, file := range contract.Files {
		result[file.Target] = make(map[string][]byte)
	}
	for _, secret := range snapshot.Secrets {
		file, exists := files[secret.FileID]
		if !exists || secret.FilePath != file.Target || !containsKey(file.Keys, secret.KeyName) {
			continue // old/replaced contracts must not write a current local file.
		}
		value, err := cryptokit.Decrypt(rek, secret.Envelope, cryptokit.AAD{InstanceID: snapshot.Repository.InstanceID, GitHubRepoID: snapshot.Repository.GitHubRepoID, FilePath: secret.FilePath, KeyName: secret.KeyName, Scope: secret.Scope, ScopeID: secret.ScopeID, Version: secret.Envelope.Version, KeyEpoch: secret.Envelope.KeyEpoch})
		if err != nil {
			clearSnapshot(result)
			return nil, "", err
		}
		if result[file.Target] == nil {
			result[file.Target] = make(map[string][]byte)
		}
		// Pending PR values are returned after baseline values and deliberately
		// override them for an explicit --pr sync.
		if previous := result[file.Target][secret.KeyName]; previous != nil {
			clear(previous)
		}
		result[file.Target][secret.KeyName] = value
	}
	return result, gitIdentity.Root, nil
}

func applySnapshot(root string, remote decryptedSnapshot, dryRun bool, out, errOut io.Writer) error {
	defer clearSnapshot(remote)
	for _, target := range sortedTargets(remote) {
		path, err := safeLocalTarget(root, target)
		if err != nil {
			return err
		}
		source, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		targetExists := err == nil
		if errors.Is(err, os.ErrNotExist) {
			source = nil
		}
		change, err := dotenv.UpdateManaged(source, remote[target])
		if err != nil {
			return err
		}
		if ignored, err := gitIgnored(root, target); err != nil {
			return err
		} else if !ignored {
			fmt.Fprintf(errOut, "localenv: warning: %s is not covered by .gitignore\n", target)
		}
		if !change.Changed {
			if !dryRun && targetExists {
				tightened, err := ensureLocalTargetMode0600(root, target)
				if err != nil {
					return err
				}
				if tightened {
					fmt.Fprintf(out, "%s: set mode 0600\n", target)
				}
			}
			fmt.Fprintf(out, "%s: already up to date\n", target)
			continue
		}
		printChange(out, target, change, dryRun)
		if dryRun {
			continue
		}
		if err := atomicWrite0600(path, change.Content); err != nil {
			return err
		}
	}
	return nil
}

func diffSnapshot(root string, remote decryptedSnapshot, out io.Writer) error {
	defer clearSnapshot(remote)
	for _, target := range sortedTargets(remote) {
		path, err := safeLocalTarget(root, target)
		if err != nil {
			return err
		}
		source, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if errors.Is(err, os.ErrNotExist) {
			source = nil
		}
		change, err := dotenv.UpdateManaged(source, remote[target])
		if err != nil {
			return err
		}
		developerKeys, err := dotenv.DeveloperKeys(source)
		if err != nil {
			return err
		}
		for _, key := range change.Updated {
			fmt.Fprintf(out, "Remote newer: %s: %s\n", target, key)
		}
		for _, key := range change.Added {
			fmt.Fprintf(out, "Missing locally: %s: %s\n", target, key)
		}
		for _, key := range sortedKeys(developerKeys) {
			fmt.Fprintf(out, "Local-only: %s: %s\n", target, key)
		}
	}
	return nil
}

func safeLocalTarget(root, target string) (string, error) {
	if target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid configured local target")
	}
	path := filepath.Join(root, filepath.FromSlash(target))
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || !withinRoot(root, parent) {
		return "", errors.New("local target directory is unsafe")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("local target must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, nil
}

func ensureLocalTargetMode0600(root, target string) (bool, error) {
	path, err := safeLocalTarget(root, target)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode().Perm() == 0o600 {
		return false, nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func withinRoot(root, candidate string) bool {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(resolvedRoot, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func atomicWrite0600(path string, content []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".localenv-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err == nil {
		_, err = temp.Write(content)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func gitIgnored(root, target string) (bool, error) {
	command := exec.Command("git", "-C", root, "check-ignore", "-q", "--", filepath.FromSlash(target))
	err := command.Run()
	if err == nil {
		return true, nil
	}
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func printChange(out io.Writer, target string, change dotenv.ManagedResult, dryRun bool) {
	prefix := ""
	if dryRun {
		prefix = "Would "
	}
	for _, key := range change.Added {
		fmt.Fprintf(out, "%s: %s: %s\n", styled(out, ansiGreen, prefix+"add"), target, key)
	}
	for _, key := range change.Updated {
		fmt.Fprintf(out, "%s: %s: %s\n", styled(out, ansiYellow, prefix+"update"), target, key)
	}
	for _, key := range change.Removed {
		fmt.Fprintf(out, "%s: %s: %s\n", styled(out, ansiRed, prefix+"remove"), target, key)
	}
}

func sortedTargets(values decryptedSnapshot) []string {
	result := make([]string, 0, len(values))
	for target := range values {
		result = append(result, target)
	}
	sort.Strings(result)
	return result
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func containsKey(keys []string, expected string) bool {
	for _, key := range keys {
		if key == expected {
			return true
		}
	}
	return false
}

func clearSnapshot(snapshot decryptedSnapshot) {
	for _, values := range snapshot {
		for _, value := range values {
			clear(value)
		}
	}
}

func runImport(args []string, out, errOut io.Writer) int {
	args = normalizeSingleArgumentFirst(args)
	flags := flag.NewFlagSet("import", flag.ContinueOnError)
	flags.SetOutput(errOut)
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		fmt.Fprintln(errOut, "Usage: localenv import FILE [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instance, token, err := currentSession(secrets, *instanceFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
		return 1
	}
	identity, err := loadIdentity(secrets, instance)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: this machine has no registered device identity; run localenv login again")
		return 1
	}
	gitIdentity, err := repository.Detect(context.Background(), ".")
	if err != nil {
		fmt.Fprintln(errOut, "localenv: repository was not detected")
		return 1
	}
	owner, name := gitIdentity.Owner, gitIdentity.Name
	if *repositoryFlag != "" {
		owner, name, err = selectedRepository(*repositoryFlag)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: invalid repository")
			return 1
		}
	}
	contract, err := repository.LoadSnapshot(gitIdentity.Root)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: localenv.yaml or schema is invalid")
		return 1
	}
	target := filepath.ToSlash(filepath.Clean(flags.Arg(0)))
	var schema repository.SchemaFile
	found := false
	for _, file := range contract.Files {
		if file.Target == target {
			schema, found = file, true
			break
		}
	}
	if !found {
		fmt.Fprintln(errOut, "localenv: import file is not a declared localenv.yaml target")
		return 1
	}
	tightened, err := ensureLocalTargetMode0600(gitIdentity.Root, schema.Target)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not set safe permissions on the local dotenv file")
		return 1
	}
	values, err := dotenvValues(filepath.Join(gitIdentity.Root, schema.Target))
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not parse the local dotenv file")
		return 1
	}
	snapshot, err := fetchRepositorySnapshot(context.Background(), instance, token, owner, name)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: repository snapshot is unavailable")
		return 1
	}
	rek, err := cryptokit.UnwrapREK(identity.Identity, snapshot.WrappedREK)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not unwrap this repository's encryption key")
		return 1
	}
	defer clear(rek)
	current := make(map[string]int64)
	for _, secret := range snapshot.Secrets {
		if secret.Scope == "baseline" && secret.FileID == pranalysis.FileID(snapshot.Repository.GitHubRepoID, schema.Schema, schema.Target) {
			current[secret.KeyName] = secret.Envelope.Version
		}
	}
	fileID := pranalysis.FileID(snapshot.Repository.GitHubRepoID, schema.Schema, schema.Target)
	count := 0
	for _, key := range schema.Keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		if current[key] > 0 && !confirmReplace(out) {
			clear(value)
			continue
		}
		envelope, err := cryptokit.Encrypt(rek, value, cryptokit.AAD{InstanceID: snapshot.Repository.InstanceID, GitHubRepoID: snapshot.Repository.GitHubRepoID, FilePath: schema.Target, KeyName: key, Scope: "baseline", Version: current[key] + 1, KeyEpoch: snapshot.Repository.ActiveKeyEpoch})
		clear(value)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: could not encrypt a local value")
			return 1
		}
		payload := struct {
			ExpectedCurrentVersion int64              `json:"expected_current_version"`
			Envelope               cryptokit.Envelope `json:"envelope"`
		}{current[key], envelope}
		endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/secrets/%s/%s", instance, url.PathEscape(owner), url.PathEscape(name), url.PathEscape(fileID), url.PathEscape(key))
		if err := requestJSON(context.Background(), http.MethodPut, endpoint, token, payload, nil); err != nil {
			fmt.Fprintln(errOut, "localenv: encrypted import was rejected or conflicted")
			return 1
		}
		count++
	}
	fmt.Fprintf(out, "Encrypted and imported %d declared local value(s).\n", count)
	if tightened {
		fmt.Fprintf(out, "Set %s to mode 0600.\n", schema.Target)
	}
	return 0
}

// normalizeSingleArgumentFirst preserves documented command forms such as
// `localenv import FILE [flags]` and `localenv set KEY [flags]` while also
// accepting the standard Go flag spelling with the positional argument last.
// The flag package otherwise stops parsing at the first positional argument.
func normalizeSingleArgumentFirst(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	return append(append([]string{}, args[1:]...), args[0])
}

func confirmReplace(out io.Writer) bool {
	fmt.Fprint(out, "A remote value already exists. Replace it? [y/N] ")
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return err == nil && strings.EqualFold(strings.TrimSpace(answer), "y")
}

func dotenvValues(path string) (map[string][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]byte)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			return nil, errors.New("invalid dotenv assignment")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("duplicate dotenv key")
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		result[key] = []byte(value)
	}
	return result, nil
}

func runResolve(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("resolve", flag.ContinueOnError)
	flags.SetOutput(errOut)
	pr := flags.Int("pr", 0, "pull request number")
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *pr <= 0 {
		fmt.Fprintln(errOut, "Usage: localenv resolve --pr NUMBER [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instance, token, err := currentSession(secrets, *instanceFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
		return 1
	}
	identity, err := loadIdentity(secrets, instance)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: this machine has no registered device identity; run localenv login again")
		return 1
	}
	owner, name, err := selectedRepository(*repositoryFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: repository was not detected; pass --repo owner/name")
		return 1
	}
	response, err := fetchPullRequirements(context.Background(), instance, token, owner, name, *pr)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: pull request requirements are unavailable")
		return 1
	}
	rek, err := cryptokit.UnwrapREK(identity.Identity, response.WrappedREK)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not unwrap this repository's encryption key")
		return 1
	}
	defer clear(rek)
	missing := 0
	readinessPending := false
	for _, requirement := range response.Requirements {
		if requirement.State != "missing" {
			continue
		}
		missing++
		published, ok := setEncryptedPRValue(out, errOut, instance, token, owner, name, *pr, response.Repository, rek, requirement, nil)
		if !ok {
			return 1
		}
		readinessPending = readinessPending || !published
	}
	if missing == 0 {
		fmt.Fprintln(out, "All PR local environment requirements are already resolved.")
	} else if readinessPending {
		fmt.Fprintf(out, "Encrypted and uploaded %d PR value(s). GitHub readiness publication is pending.\n", missing)
	} else {
		fmt.Fprintf(out, "Encrypted and uploaded %d PR value(s). GitHub readiness was refreshed.\n", missing)
	}
	return 0
}

func runSet(args []string, out, errOut io.Writer) int {
	args = normalizeSingleArgumentFirst(args)
	flags := flag.NewFlagSet("set", flag.ContinueOnError)
	flags.SetOutput(errOut)
	pr := flags.Int("pr", 0, "pull request number")
	stdin := flags.Bool("stdin", false, "read the value from standard input")
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || *pr <= 0 {
		fmt.Fprintln(errOut, "Usage: localenv set KEY --pr NUMBER [--stdin] [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	key := flags.Arg(0)
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instance, token, err := currentSession(secrets, *instanceFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
		return 1
	}
	identity, err := loadIdentity(secrets, instance)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: this machine has no registered device identity; run localenv login again")
		return 1
	}
	owner, name, err := selectedRepository(*repositoryFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: repository was not detected; pass --repo owner/name")
		return 1
	}
	response, err := fetchPullRequirements(context.Background(), instance, token, owner, name, *pr)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: pull request requirements are unavailable")
		return 1
	}
	rek, err := cryptokit.UnwrapREK(identity.Identity, response.WrappedREK)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not unwrap this repository's encryption key")
		return 1
	}
	defer clear(rek)
	for _, requirement := range response.Requirements {
		if requirement.KeyName == key && requirement.State != "removed" {
			var value []byte
			if *stdin {
				value, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
				value = bytes.TrimSuffix(value, []byte("\n"))
			} else {
				value, err = hiddenValue(out)
			}
			if err != nil {
				fmt.Fprintln(errOut, "localenv: could not read a secret value")
				return 1
			}
			defer clear(value)
			published, ok := setEncryptedPRValue(out, errOut, instance, token, owner, name, *pr, response.Repository, rek, requirement, value)
			if !ok {
				return 1
			}
			if published {
				fmt.Fprintln(out, "Encrypted locally, uploaded, and refreshed GitHub readiness.")
			} else {
				fmt.Fprintln(out, "Encrypted locally and uploaded. GitHub readiness publication is pending.")
			}
			return 0
		}
	}
	fmt.Fprintf(errOut, "localenv: %s is not required by PR #%d\n", key, *pr)
	return 1
}

func hiddenValue(out io.Writer) ([]byte, error) {
	fmt.Fprint(out, styled(out, ansiCyan, "Value:")+" ")
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	value, readErr := maskedValue(os.Stdin, out)
	restoreErr := term.Restore(int(os.Stdin.Fd()), state)
	if readErr != nil {
		return nil, readErr
	}
	if restoreErr != nil {
		clear(value)
		return nil, restoreErr
	}
	return value, nil
}

// maskedValue accepts a terminal value without echoing its contents while
// showing one asterisk per typed byte. The asterisks deliberately reveal only
// input length, never plaintext bytes.
func maskedValue(input io.Reader, out io.Writer) ([]byte, error) {
	value := make([]byte, 0, 64)
	var byteBuffer [1]byte
	for {
		n, err := input.Read(byteBuffer[:])
		if n > 0 {
			switch byteBuffer[0] {
			case '\r', '\n':
				fmt.Fprint(out, "\r\n")
				return value, nil
			case 3, 4:
				fmt.Fprint(out, "\r\n")
				clear(value)
				return nil, errors.New("secret input interrupted")
			case '\b', 127:
				if len(value) > 0 {
					value = value[:len(value)-1]
					fmt.Fprint(out, "\b \b")
				}
			default:
				if len(value) >= 1<<20 {
					clear(value)
					return nil, errors.New("secret input is too large")
				}
				value = append(value, byteBuffer[0])
				fmt.Fprint(out, "*")
			}
		}
		if err != nil {
			clear(value)
			return nil, err
		}
	}
}

func setEncryptedPRValue(out, errOut io.Writer, instance, token, owner, name string, pr int, state apiRepositoryCryptoState, rek []byte, requirement apiPullRequirement, supplied []byte) (bool, bool) {
	value := supplied
	if value == nil {
		var err error
		value, err = hiddenValue(out)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: could not read a secret value")
			return false, false
		}
		defer clear(value)
	}
	envelope, err := cryptokit.Encrypt(rek, value, cryptokit.AAD{InstanceID: state.InstanceID, GitHubRepoID: state.GitHubRepoID, FilePath: requirement.FilePath, KeyName: requirement.KeyName, Scope: "pull_request", ScopeID: fmt.Sprintf("%d", pr), Version: requirement.CurrentVersion + 1, KeyEpoch: state.ActiveKeyEpoch})
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not encrypt the secret")
		return false, false
	}
	payload := struct {
		ExpectedCurrentVersion int64              `json:"expected_current_version"`
		Envelope               cryptokit.Envelope `json:"envelope"`
	}{requirement.CurrentVersion, envelope}
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/pulls/%d/secrets/%s/%s", instance, url.PathEscape(owner), url.PathEscape(name), pr, url.PathEscape(requirement.FileID), url.PathEscape(requirement.KeyName))
	var result struct {
		Readiness string `json:"readiness"`
	}
	if err := requestJSON(context.Background(), http.MethodPut, endpoint, token, payload, &result); err != nil {
		fmt.Fprintln(errOut, "localenv: encrypted secret update was rejected or conflicted")
		return false, false
	}
	return result.Readiness != "pending", true
}

func runLogin(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	flags.SetOutput(errOut)
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		fmt.Fprintln(errOut, "Usage: localenv login [--credential-file path] <instance-url>")
		return 2
	}
	instance, err := normalizeInstance(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(errOut, "localenv: invalid instance URL")
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable; use --credential-file only for an explicit headless fallback")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	identity, err := loadOrCreateIdentity(secrets, instance)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not create device identity")
		return 1
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not start local login callback")
		return 1
	}
	defer listener.Close()
	callback := "http://" + listener.Addr().String() + "/callback"
	start, _ := url.Parse(instance + "/auth/cli/start")
	query := start.Query()
	query.Set("redirect_uri", callback)
	start.RawQuery = query.Encode()
	fmt.Fprintln(out, "Opening your browser to sign in with GitHub…")
	if err := openBrowser(start.String()); err != nil {
		fmt.Fprintln(errOut, "localenv: could not open a browser")
		return 1
	}
	code, err := receiveCode(ctx, listener)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: browser sign-in did not complete")
		return 1
	}
	session, err := exchange(ctx, instance, code)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: sign-in exchange failed")
		return 1
	}
	if err := secrets.Set(sessionKey(instance), session.Token); err != nil {
		fmt.Fprintln(errOut, "localenv: could not store session securely")
		return 1
	}
	if err := secrets.Set("last-instance", instance); err != nil {
		_ = secrets.Delete(sessionKey(instance))
		fmt.Fprintln(errOut, "localenv: could not store instance selection")
		return 1
	}
	device, err := register(ctx, instance, session.Token, identity)
	if err != nil {
		_ = secrets.Delete(sessionKey(instance))
		fmt.Fprintln(errOut, "localenv: device registration failed")
		return 1
	}
	fmt.Fprintf(out, "Signed in as %s\nDevice: %s (%s)\n", session.User.Login, device.Name, device.Fingerprint)
	return 0
}

func runStatus(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(errOut)
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instanceRaw := *instanceFlag
	if instanceRaw == "" {
		instanceRaw, err = secrets.Get("last-instance")
		if err != nil {
			fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
			return 1
		}
	}
	instance, err := normalizeInstance(instanceRaw)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: invalid stored instance URL")
		return 1
	}
	token, err := secrets.Get(sessionKey(instance))
	if err != nil || token == "" {
		fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
		return 1
	}
	me, err := fetchMe(context.Background(), instance, token)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: session is invalid or the instance is unavailable")
		return 1
	}
	identity, detectErr := repository.Detect(context.Background(), ".")
	fmt.Fprintf(out, "Instance: %s\nGitHub user: %s\n", instance, me.User.Login)
	if detectErr == nil {
		fmt.Fprintf(out, "Repository: %s/%s\nBranch: %s\n", identity.Owner, identity.Name, detachedLabel(identity.Branch))
	} else {
		fmt.Fprintln(out, "Repository: not detected")
	}
	if me.Device.ID == "" {
		fmt.Fprintln(out, "Device: not registered")
	} else {
		fmt.Fprintf(out, "Device: %s (%s)\n", me.Device.Name, me.Device.Fingerprint)
	}
	return 0
}

func runLogout(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("logout", flag.ContinueOnError)
	flags.SetOutput(errOut)
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(errOut, "Usage: localenv logout [--instance instance-url] [--credential-file path]")
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instanceRaw := *instanceFlag
	if instanceRaw == "" {
		instanceRaw, err = secrets.Get("last-instance")
		if err != nil {
			fmt.Fprintln(errOut, "localenv: not signed in")
			return 1
		}
	}
	instance, err := normalizeInstance(instanceRaw)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: invalid stored instance URL")
		return 1
	}
	token, getErr := secrets.Get(sessionKey(instance))
	if getErr == nil && token != "" {
		_ = revoke(context.Background(), instance, token)
	}
	if err := secrets.Delete(sessionKey(instance)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		fmt.Fprintln(errOut, "localenv: could not remove local session")
		return 1
	}
	if *instanceFlag == "" {
		_ = secrets.Delete("last-instance")
	}
	fmt.Fprintln(out, "Signed out. The device identity was kept on this machine.")
	return 0
}

func runRepo(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(errOut, "Usage: localenv repo init [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	flags := flag.NewFlagSet("repo init", flag.ContinueOnError)
	flags.SetOutput(errOut)
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(errOut, "Usage: localenv repo init [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instance, token, err := currentSession(secrets, *instanceFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
		return 1
	}
	identity, err := loadIdentity(secrets, instance)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: this machine has no registered device identity; run localenv login again")
		return 1
	}
	owner, name, err := selectedRepository(*repositoryFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: repository was not detected; pass --repo owner/name")
		return 1
	}
	endpoint := instance + "/api/v1/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	var state apiRepositoryCryptoState
	if err := requestJSON(context.Background(), http.MethodGet, endpoint, token, nil, &state); err != nil {
		fmt.Fprintln(errOut, "localenv: repository access is unavailable or you do not have GitHub write access")
		return 1
	}
	if state.Initialized || state.ActiveKeyEpoch != 0 {
		fmt.Fprintln(errOut, "localenv: repository encryption is already initialized")
		return 1
	}
	rek, err := cryptokit.GenerateREK()
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not generate repository encryption key")
		return 1
	}
	defer clear(rek)
	wrapped, err := cryptokit.WrapREK(rek, identity.Recipient)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not wrap repository encryption key")
		return 1
	}
	if err := requestJSON(context.Background(), http.MethodPost, endpoint+"/init", token, struct {
		WrappedREK []byte `json:"wrapped_rek"`
	}{WrappedREK: wrapped}, &state); err != nil {
		fmt.Fprintln(errOut, "localenv: repository encryption initialization failed")
		return 1
	}
	if state.ActiveKeyEpoch != 1 || !state.Initialized {
		fmt.Fprintln(errOut, "localenv: repository encryption initialization failed")
		return 1
	}
	fmt.Fprintf(out, "Repository encryption initialized for %s/%s (epoch 1).\n", state.Owner, state.Name)
	return 0
}

func runDevices(args []string, out, errOut io.Writer) int {
	command := "list"
	if len(args) > 0 && (args[0] == "approve" || args[0] == "revoke") {
		command, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("devices "+command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args); err != nil || (command == "list" && flags.NArg() != 0) || ((command == "approve" || command == "revoke") && flags.NArg() != 1) {
		fmt.Fprintln(errOut, "Usage: localenv devices [approve CODE|revoke DEVICE-ID] [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instance, token, err := currentSession(secrets, *instanceFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
		return 1
	}
	identity, err := loadIdentity(secrets, instance)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: this machine has no registered device identity; run localenv login again")
		return 1
	}
	owner, name, err := selectedRepository(*repositoryFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: repository was not detected; pass --repo owner/name")
		return 1
	}
	switch command {
	case "list":
		devices, err := fetchRepositoryDevices(context.Background(), instance, token, owner, name)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: repository devices are unavailable")
			return 1
		}
		requests, err := fetchPendingDeviceAccessRequests(context.Background(), instance, token, owner, name)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: pending device access requests are unavailable")
			return 1
		}
		for _, device := range devices {
			access := "pending"
			if device.HasKey {
				access = "approved"
			}
			fmt.Fprintf(out, "%s  %s  %s  %s  %s\n", device.ID, access, device.GitHubLogin, device.Name, device.Fingerprint)
		}
		for _, request := range requests {
			fmt.Fprintf(out, "pending request  %s  %s  %s  %s\n", request.GitHubLogin, request.DeviceName, request.Fingerprint, request.ID)
		}
		return 0
	case "approve":
		code := flags.Arg(0)
		request, err := inspectDeviceAccessRequest(context.Background(), instance, token, owner, name, code)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: device access request was not found")
			return 1
		}
		fmt.Fprintf(out, "Approve device access?\nGitHub user: %s\nRepository: %s/%s\nNew device: %s\nPublic-key fingerprint: %s\nRequest code: %s\n", request.GitHubLogin, owner, name, request.DeviceName, request.Fingerprint, code)
		if !confirm(out) {
			fmt.Fprintln(out, "Device access approval cancelled.")
			return 1
		}
		snapshot, err := fetchRepositorySnapshot(context.Background(), instance, token, owner, name)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: could not retrieve this device's wrapped repository key")
			return 1
		}
		rek, err := cryptokit.UnwrapREK(identity.Identity, snapshot.WrappedREK)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: could not unwrap this repository's encryption key")
			return 1
		}
		defer clear(rek)
		wrapped, err := cryptokit.WrapREK(rek, request.PublicRecipient)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: could not wrap the repository encryption key for the new device")
			return 1
		}
		if err := approveDeviceAccess(context.Background(), instance, token, owner, name, code, wrapped); err != nil {
			fmt.Fprintln(errOut, "localenv: device access approval was rejected")
			return 1
		}
		fmt.Fprintln(out, "Device access approved. The new device can now sync.")
		return 0
	case "revoke":
		deviceID := flags.Arg(0)
		fmt.Fprintf(out, "Revoke device %s? This stops future snapshots and removes its wrapped repository keys. [y/N] ", deviceID)
		if !confirmResponse() {
			fmt.Fprintln(out, "Device revocation cancelled.")
			return 1
		}
		if err := revokeRepositoryDevice(context.Background(), instance, token, owner, name, deviceID); err != nil {
			fmt.Fprintln(errOut, "localenv: device revocation was rejected")
			return 1
		}
		fmt.Fprintln(out, "Device revoked. Rotate the repository key to cryptographically protect future ciphertext from a retained old key.")
		return 0
	}
	return 2
}

// runKeys performs the entire rotation locally: it opens the current
// ciphertext with the caller's old REK, creates a new REK, and uploads only
// new ciphertext plus device-specific age wraps.
func runKeys(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "rotate" {
		fmt.Fprintln(errOut, "Usage: localenv keys rotate [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	flags := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
	flags.SetOutput(errOut)
	repositoryFlag := flags.String("repo", "", "GitHub repository as owner/name")
	instanceFlag := flags.String("instance", "", "local.env instance URL")
	credentialFile := flags.String("credential-file", "", "explicit 0600 headless credential fallback")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(errOut, "Usage: localenv keys rotate [--repo owner/name] [--instance instance-url] [--credential-file path]")
		return 2
	}
	secrets, err := credentialStore(*credentialFile)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: credential storage is unavailable")
		return 1
	}
	instance, token, err := currentSession(secrets, *instanceFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: not signed in; run localenv login <instance-url>")
		return 1
	}
	identity, err := loadIdentity(secrets, instance)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: this machine has no registered device identity; run localenv login again")
		return 1
	}
	owner, name, err := selectedRepository(*repositoryFlag)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: repository was not detected; pass --repo owner/name")
		return 1
	}
	snapshot, err := fetchRepositorySnapshot(context.Background(), instance, token, owner, name)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not retrieve the current encrypted repository snapshot")
		return 1
	}
	oldREK, err := cryptokit.UnwrapREK(identity.Identity, snapshot.WrappedREK)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not unwrap the current repository encryption key")
		return 1
	}
	defer clear(oldREK)
	devices, err := fetchRepositoryDevices(context.Background(), instance, token, owner, name)
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not retrieve active repository devices")
		return 1
	}
	active := 0
	for _, device := range devices {
		if device.HasKey {
			active++
		}
	}
	fmt.Fprintf(out, "Rotate repository key for %s/%s? This re-encrypts %d current value(s) for %d active device(s). [y/N] ", owner, name, len(snapshot.Secrets), active)
	if !confirmResponse() {
		fmt.Fprintln(out, "Repository key rotation cancelled.")
		return 1
	}
	newREK, err := cryptokit.GenerateREK()
	if err != nil {
		fmt.Fprintln(errOut, "localenv: could not generate a new repository encryption key")
		return 1
	}
	defer clear(newREK)
	rotation := apiKeyRotation{ExpectedEpoch: snapshot.Repository.ActiveKeyEpoch}
	for _, device := range devices {
		if !device.HasKey || device.PublicRecipient == "" {
			continue
		}
		wrapped, err := cryptokit.WrapREK(newREK, device.PublicRecipient)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: could not wrap the new repository key for every active device")
			return 1
		}
		rotation.WrappedKeys = append(rotation.WrappedKeys, apiRotationWrappedKey{DeviceID: device.ID, WrappedREK: wrapped})
	}
	for _, secret := range snapshot.Secrets {
		aad := cryptokit.AAD{InstanceID: snapshot.Repository.InstanceID, GitHubRepoID: snapshot.Repository.GitHubRepoID, FilePath: secret.FilePath, KeyName: secret.KeyName, Scope: secret.Scope, ScopeID: secret.ScopeID, Version: secret.Envelope.Version, KeyEpoch: secret.Envelope.KeyEpoch}
		plaintext, err := cryptokit.Decrypt(oldREK, secret.Envelope, aad)
		if err != nil {
			fmt.Fprintln(errOut, "localenv: could not authenticate the current encrypted repository snapshot")
			return 1
		}
		rotatedAAD := aad
		rotatedAAD.Version++
		rotatedAAD.KeyEpoch++
		envelope, encryptErr := cryptokit.Encrypt(newREK, plaintext, rotatedAAD)
		clear(plaintext)
		if encryptErr != nil {
			fmt.Fprintln(errOut, "localenv: could not re-encrypt the current repository snapshot")
			return 1
		}
		rotation.Secrets = append(rotation.Secrets, apiRotationSecret{FileID: secret.FileID, FilePath: secret.FilePath, KeyName: secret.KeyName, Scope: secret.Scope, ScopeID: secret.ScopeID, Envelope: envelope})
	}
	var state apiRepositoryCryptoState
	if err := rotateRepositoryKey(context.Background(), instance, token, owner, name, rotation, &state); err != nil {
		fmt.Fprintln(errOut, "localenv: repository key rotation was rejected; no new epoch was activated")
		return 1
	}
	fmt.Fprintf(out, "Repository key rotated to epoch %d. Revoked devices cannot decrypt this epoch.\n", state.ActiveKeyEpoch)
	return 0
}

func confirm(out io.Writer) bool {
	fmt.Fprint(out, "Continue? [y/N] ")
	return confirmResponse()
}

func confirmResponse() bool {
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return err == nil && strings.EqualFold(strings.TrimSpace(answer), "y")
}

func currentSession(secrets secretStore, instanceFlag string) (string, string, error) {
	instanceRaw := instanceFlag
	var err error
	if instanceRaw == "" {
		instanceRaw, err = secrets.Get("last-instance")
		if err != nil {
			return "", "", err
		}
	}
	instance, err := normalizeInstance(instanceRaw)
	if err != nil {
		return "", "", err
	}
	token, err := secrets.Get(sessionKey(instance))
	if err != nil || token == "" {
		return "", "", errors.New("session not found")
	}
	return instance, token, nil
}

func selectedRepository(raw string) (string, string, error) {
	if raw != "" {
		owner, name, found := strings.Cut(raw, "/")
		if !found || owner == "" || name == "" || strings.ContainsAny(owner, "/\\\x00") || strings.ContainsAny(name, "/\\\x00") {
			return "", "", errors.New("invalid repository")
		}
		return owner, name, nil
	}
	identity, err := repository.Detect(context.Background(), ".")
	if err != nil {
		return "", "", err
	}
	return identity.Owner, identity.Name, nil
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

type secretStore interface {
	Get(string) (string, error)
	Set(string, string) error
	Delete(string) error
}
type systemStore struct{}

func (systemStore) Get(key string) (string, error) { return keyring.Get(keyringService, key) }
func (systemStore) Set(key, value string) error    { return keyring.Set(keyringService, key, value) }
func (systemStore) Delete(key string) error        { return keyring.Delete(keyringService, key) }

func credentialStore(explicitFile string) (secretStore, error) {
	if explicitFile == "" {
		return systemStore{}, nil
	}
	if !filepath.IsAbs(explicitFile) {
		return nil, errors.New("credential file must be absolute")
	}
	return &fileStore{path: explicitFile}, nil
}

type fileStore struct{ path string }

func (s *fileStore) read() (map[string]string, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(s.path)
	if err != nil || info.Mode().Perm() != 0o600 {
		return nil, errors.New("credential file must have 0600 permissions")
	}
	var result map[string]string
	if json.Unmarshal(data, &result) != nil {
		return nil, errors.New("invalid credential file")
	}
	return result, nil
}
func (s *fileStore) write(values map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".localenv-credentials-")
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
	return os.Rename(tempName, s.path)
}
func (s *fileStore) Get(key string) (string, error) {
	values, err := s.read()
	if err != nil {
		return "", err
	}
	value, ok := values[key]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}
func (s *fileStore) Set(key, value string) error {
	values, err := s.read()
	if err != nil {
		return err
	}
	values[key] = value
	return s.write(values)
}
func (s *fileStore) Delete(key string) error {
	values, err := s.read()
	if err != nil {
		return err
	}
	delete(values, key)
	return s.write(values)
}

type deviceIdentity struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Recipient   string              `json:"public_recipient"`
	Fingerprint string              `json:"fingerprint"`
	Identity    *age.X25519Identity `json:"-"`
}

func loadOrCreateIdentity(store secretStore, instance string) (deviceIdentity, error) {
	if identity, err := loadIdentity(store, instance); err == nil {
		return identity, nil
	} else if !errors.Is(err, keyring.ErrNotFound) {
		return deviceIdentity{}, err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return deviceIdentity{}, err
	}
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		name = "local device"
	}
	id, err := randomID()
	if err != nil {
		return deviceIdentity{}, err
	}
	saved, _ := json.Marshal(struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Identity string `json:"identity"`
	}{id, name, identity.String()})
	if err := store.Set(identityKey(instance), string(saved)); err != nil {
		return deviceIdentity{}, err
	}
	return identityFrom(id, name, identity), nil
}
func identityFrom(id, name string, identity *age.X25519Identity) deviceIdentity {
	recipient := identity.Recipient().String()
	sum := sha256.Sum256([]byte(recipient))
	return deviceIdentity{ID: id, Name: name, Recipient: recipient, Fingerprint: "sha256:" + hex.EncodeToString(sum[:8]), Identity: identity}
}

func loadIdentity(store secretStore, instance string) (deviceIdentity, error) {
	raw, err := store.Get(identityKey(instance))
	if err != nil {
		return deviceIdentity{}, err
	}
	var saved struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Identity string `json:"identity"`
	}
	if json.Unmarshal([]byte(raw), &saved) != nil || saved.ID == "" || saved.Name == "" {
		return deviceIdentity{}, errors.New("stored device identity is invalid")
	}
	identity, err := age.ParseX25519Identity(saved.Identity)
	if err != nil {
		return deviceIdentity{}, errors.New("stored device identity is invalid")
	}
	return identityFrom(saved.ID, saved.Name, identity), nil
}
func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
func sessionKey(instance string) string  { return "session:" + instance }
func identityKey(instance string) string { return "device:" + instance }

type apiSession struct {
	Token string `json:"token"`
	User  struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"user"`
}
type apiDevice struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}
type apiMe struct {
	User struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"user"`
	Device apiDevice `json:"device"`
}

type apiRepositoryCryptoState struct {
	InstanceID     string `json:"instance_id"`
	GitHubRepoID   int64  `json:"github_repo_id"`
	Owner          string `json:"owner"`
	Name           string `json:"name"`
	ActiveKeyEpoch int64  `json:"active_key_epoch"`
	Initialized    bool   `json:"initialized"`
}

type apiPullRequirement struct {
	FileID         string `json:"file_id"`
	FilePath       string `json:"file_path"`
	KeyName        string `json:"key_name"`
	State          string `json:"state"`
	CurrentVersion int64  `json:"current_version"`
}

type apiPullRequirements struct {
	Repository   apiRepositoryCryptoState `json:"repository"`
	WrappedREK   []byte                   `json:"wrapped_rek"`
	Requirements []apiPullRequirement     `json:"requirements"`
}

type apiSecretSnapshot struct {
	FileID   string             `json:"file_id"`
	FilePath string             `json:"file_path"`
	KeyName  string             `json:"key_name"`
	Scope    string             `json:"scope"`
	ScopeID  string             `json:"scope_id"`
	Envelope cryptokit.Envelope `json:"envelope"`
}

type apiRepositorySnapshot struct {
	Repository apiRepositoryCryptoState `json:"repository"`
	WrappedREK []byte                   `json:"wrapped_rek"`
	Secrets    []apiSecretSnapshot      `json:"secrets"`
}

type apiDeviceAccessRequest struct {
	ID              string `json:"id"`
	GitHubLogin     string `json:"github_login"`
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name"`
	PublicRecipient string `json:"public_recipient"`
	Fingerprint     string `json:"fingerprint"`
	Code            string `json:"code"`
}

type apiRepositoryDevice struct {
	ID              string `json:"id"`
	GitHubLogin     string `json:"github_login"`
	Name            string `json:"name"`
	PublicRecipient string `json:"public_recipient"`
	Fingerprint     string `json:"fingerprint"`
	HasKey          bool   `json:"has_key"`
}

type apiRotationWrappedKey struct {
	DeviceID   string `json:"device_id"`
	WrappedREK []byte `json:"wrapped_rek"`
}

type apiRotationSecret struct {
	FileID   string             `json:"file_id"`
	FilePath string             `json:"file_path"`
	KeyName  string             `json:"key_name"`
	Scope    string             `json:"scope"`
	ScopeID  string             `json:"scope_id"`
	Envelope cryptokit.Envelope `json:"envelope"`
}

type apiKeyRotation struct {
	ExpectedEpoch int64                   `json:"expected_epoch"`
	WrappedKeys   []apiRotationWrappedKey `json:"wrapped_keys"`
	Secrets       []apiRotationSecret     `json:"secrets"`
}

func exchange(ctx context.Context, instance, code string) (apiSession, error) {
	var out apiSession
	return out, requestJSON(ctx, http.MethodPost, instance+"/api/v1/auth/exchange", "", map[string]string{"code": code}, &out)
}
func register(ctx context.Context, instance, token string, identity deviceIdentity) (apiDevice, error) {
	var out apiDevice
	err := requestJSON(ctx, http.MethodPost, instance+"/api/v1/devices", token, identity, &out)
	return out, err
}
func fetchMe(ctx context.Context, instance, token string) (apiMe, error) {
	var out apiMe
	return out, requestJSON(ctx, http.MethodGet, instance+"/api/v1/me", token, nil, &out)
}
func revoke(ctx context.Context, instance, token string) error {
	return requestJSON(ctx, http.MethodPost, instance+"/api/v1/auth/logout", token, nil, nil)
}
func fetchPullRequirements(ctx context.Context, instance, token, owner, name string, number int) (apiPullRequirements, error) {
	var result apiPullRequirements
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/pulls/%d/requirements", instance, url.PathEscape(owner), url.PathEscape(name), number)
	return result, requestJSON(ctx, http.MethodGet, endpoint, token, nil, &result)
}
func fetchRepositorySnapshot(ctx context.Context, instance, token, owner, name string) (apiRepositorySnapshot, error) {
	var result apiRepositorySnapshot
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/snapshot", instance, url.PathEscape(owner), url.PathEscape(name))
	return result, requestJSON(ctx, http.MethodGet, endpoint, token, nil, &result)
}
func createDeviceAccessRequest(ctx context.Context, instance, token, owner, name string) (apiDeviceAccessRequest, error) {
	var result apiDeviceAccessRequest
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/device-access-requests", instance, url.PathEscape(owner), url.PathEscape(name))
	return result, requestJSON(ctx, http.MethodPost, endpoint, token, map[string]string{}, &result)
}
func fetchPendingDeviceAccessRequests(ctx context.Context, instance, token, owner, name string) ([]apiDeviceAccessRequest, error) {
	var result []apiDeviceAccessRequest
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/device-access-requests", instance, url.PathEscape(owner), url.PathEscape(name))
	return result, requestJSON(ctx, http.MethodGet, endpoint, token, nil, &result)
}
func inspectDeviceAccessRequest(ctx context.Context, instance, token, owner, name, code string) (apiDeviceAccessRequest, error) {
	var result apiDeviceAccessRequest
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/device-access-requests/inspect", instance, url.PathEscape(owner), url.PathEscape(name))
	return result, requestJSON(ctx, http.MethodPost, endpoint, token, map[string]string{"code": code}, &result)
}
func approveDeviceAccess(ctx context.Context, instance, token, owner, name, code string, wrappedREK []byte) error {
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/device-access-requests/approve", instance, url.PathEscape(owner), url.PathEscape(name))
	return requestJSON(ctx, http.MethodPost, endpoint, token, struct {
		Code       string `json:"code"`
		WrappedREK []byte `json:"wrapped_rek"`
	}{code, wrappedREK}, nil)
}
func fetchRepositoryDevices(ctx context.Context, instance, token, owner, name string) ([]apiRepositoryDevice, error) {
	var result []apiRepositoryDevice
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/devices", instance, url.PathEscape(owner), url.PathEscape(name))
	return result, requestJSON(ctx, http.MethodGet, endpoint, token, nil, &result)
}
func revokeRepositoryDevice(ctx context.Context, instance, token, owner, name, deviceID string) error {
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/devices/%s", instance, url.PathEscape(owner), url.PathEscape(name), url.PathEscape(deviceID))
	return requestJSON(ctx, http.MethodDelete, endpoint, token, nil, nil)
}
func rotateRepositoryKey(ctx context.Context, instance, token, owner, name string, rotation apiKeyRotation, target *apiRepositoryCryptoState) error {
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/key-epochs", instance, url.PathEscape(owner), url.PathEscape(name))
	return requestJSON(ctx, http.MethodPost, endpoint, token, rotation, target)
}
func fetchCurrentPullRequest(ctx context.Context, instance, token, owner, name, branch string) (int, error) {
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/pulls/current?branch=%s", instance, url.PathEscape(owner), url.PathEscape(name), url.QueryEscape(branch))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return 0, nil
	}
	if response.StatusCode != http.StatusOK {
		return 0, errors.New("current pull request lookup failed")
	}
	var result struct {
		Number int `json:"number"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&result); err != nil || result.Number <= 0 {
		return 0, errors.New("current pull request lookup failed")
	}
	return result.Number, nil
}
func fetchPullRequestSnapshot(ctx context.Context, instance, token, owner, name string, number int) (apiRepositorySnapshot, error) {
	var result apiRepositorySnapshot
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/pulls/%d/snapshot", instance, url.PathEscape(owner), url.PathEscape(name), number)
	return result, requestJSON(ctx, http.MethodGet, endpoint, token, nil, &result)
}
func requestJSON(ctx context.Context, method, endpoint, token string, payload, target any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("API request failed")
	}
	if target == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(target)
}
func normalizeInstance(raw string) (string, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid instance")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
func openBrowser(address string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", address)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", address)
	default:
		command = exec.Command("xdg-open", address)
	}
	return command.Start()
}
func receiveCode(ctx context.Context, listener net.Listener) (string, error) {
	type result struct {
		code string
		err  error
	}
	received := make(chan result, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if r.URL.Path != "/callback" || code == "" {
			http.Error(w, "invalid login callback", http.StatusBadRequest)
			received <- result{err: errors.New("invalid callback")}
			return
		}
		fmt.Fprintln(w, "Sign-in complete. You can close this window.")
		received <- result{code: code}
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())
	select {
	case outcome := <-received:
		return outcome.code, outcome.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
func detachedLabel(branch string) string {
	if branch == "" {
		return "detached"
	}
	return branch
}
