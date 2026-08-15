package repository

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"path"
	"strings"
)

// Identity is the non-secret local Git context used to identify a repository.
type Identity struct {
	Root   string
	Owner  string
	Name   string
	Branch string
}

// Detect reads the configured origin remote and checked-out branch. It does
// not inspect arbitrary source code or transmit data.
func Detect(ctx context.Context, directory string) (Identity, error) {
	root, err := git(ctx, directory, "rev-parse", "--show-toplevel")
	if err != nil {
		return Identity{}, errors.New("not inside a Git repository")
	}
	remote, err := git(ctx, root, "remote", "get-url", "origin")
	if err != nil {
		return Identity{}, errors.New("Git remote origin is not configured")
	}
	owner, name, err := NormalizeGitHubRemote(remote)
	if err != nil {
		return Identity{}, err
	}
	branch, err := git(ctx, root, "branch", "--show-current")
	if err != nil {
		return Identity{}, errors.New("could not determine current Git branch")
	}
	return Identity{Root: root, Owner: owner, Name: name, Branch: branch}, nil
}

// NormalizeGitHubRemote converts supported GitHub SSH and HTTPS remotes into
// owner/repository components. Other hosts are rejected to avoid a mistaken
// match with a GitHub App repository.
func NormalizeGitHubRemote(remote string) (owner, name string, err error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", "", errors.New("Git remote must not be empty")
	}
	if strings.HasPrefix(remote, "git@github.com:") {
		return githubPath(strings.TrimPrefix(remote, "git@github.com:"))
	}
	parsed, parseErr := url.Parse(remote)
	if parseErr != nil || (parsed.Scheme != "https" && parsed.Scheme != "ssh") || !strings.EqualFold(parsed.Hostname(), "github.com") {
		return "", "", errors.New("Git remote must be a GitHub HTTPS or SSH URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil && parsed.Scheme == "https" {
		return "", "", errors.New("Git remote is malformed")
	}
	if parsed.Scheme == "ssh" && (parsed.User == nil || parsed.User.Username() != "git") {
		return "", "", errors.New("Git SSH remote must use the git user")
	}
	return githubPath(strings.TrimPrefix(parsed.EscapedPath(), "/"))
}

func githubPath(raw string) (string, string, error) {
	if strings.HasSuffix(raw, ".git") {
		raw = strings.TrimSuffix(raw, ".git")
	}
	if path.Clean(raw) != raw || strings.Contains(raw, "//") {
		return "", "", errors.New("Git remote path is malformed")
	}
	parts := strings.Split(raw, "/")
	if len(parts) != 2 || !validGitHubComponent(parts[0]) || !validGitHubComponent(parts[1]) {
		return "", "", errors.New("Git remote must identify owner/repository")
	}
	return parts[0], parts[1], nil
}

func validGitHubComponent(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func git(ctx context.Context, directory string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", directory}, arguments...)...)
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("run Git command: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
