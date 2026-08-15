// Package cli implements the intentionally small P4 localenv command surface.
package cli

import (
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
	"strings"
	"time"

	"filippo.io/age"
	"github.com/localenv/localenv/internal/cryptokit"
	"github.com/localenv/localenv/internal/repository"
	"github.com/zalando/go-keyring"
)

const keyringService = "localenv"

// Run executes P4 commands. Values stored by this package are session tokens
// and age identities only; neither is ever printed.
func Run(args []string, out, errOut io.Writer) int {
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
	fmt.Fprintln(out, "Usage: localenv <command>")
	fmt.Fprintln(out, "\nCommands:")
	fmt.Fprintln(out, "  login <instance-url>  Sign in with GitHub and register this device")
	fmt.Fprintln(out, "  status                Show signed-in user, repository, and device")
	fmt.Fprintln(out, "  logout                Revoke and remove the local session")
	fmt.Fprintln(out, "  repo init             Initialize client-side repository encryption")
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
	ID, Name, Recipient, Fingerprint string
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
	return deviceIdentity{ID: id, Name: name, Recipient: recipient, Fingerprint: "sha256:" + hex.EncodeToString(sum[:8])}
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
