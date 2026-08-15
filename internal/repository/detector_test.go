package repository

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNormalizeGitHubRemote(t *testing.T) {
	for remote, want := range map[string][2]string{
		"git@github.com:acme/api.git":       {"acme", "api"},
		"https://github.com/acme/api.git":   {"acme", "api"},
		"ssh://git@github.com/acme/api.git": {"acme", "api"},
	} {
		owner, name, err := NormalizeGitHubRemote(remote)
		if err != nil || owner != want[0] || name != want[1] {
			t.Errorf("NormalizeGitHubRemote(%q) = (%q, %q, %v), want (%q, %q, nil)", remote, owner, name, err, want[0], want[1])
		}
	}
	for _, remote := range []string{"https://gitlab.com/acme/api.git", "https://github.com/acme/api/extra", "git@github.com:../api.git"} {
		if _, _, err := NormalizeGitHubRemote(remote); err == nil {
			t.Errorf("NormalizeGitHubRemote(%q) succeeded, want error", remote)
		}
	}
}

func TestDetectReadsRepositoryOriginAndBranch(t *testing.T) {
	root := t.TempDir()
	gitCommand(t, root, "init", "--initial-branch=main")
	gitCommand(t, root, "remote", "add", "origin", "git@github.com:acme/api.git")
	identity, err := Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Root != resolvedRoot || identity.Owner != "acme" || identity.Name != "api" || identity.Branch != "main" {
		t.Errorf("Detect() = %#v", identity)
	}
}

func TestDetectAllowsDetachedHead(t *testing.T) {
	root := t.TempDir()
	gitCommand(t, root, "init", "--initial-branch=main")
	gitCommand(t, root, "-c", "user.name=Local Env Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "--message", "initial")
	gitCommand(t, root, "remote", "add", "origin", "https://github.com/acme/api.git")
	gitCommand(t, root, "checkout", "--detach")
	identity, err := Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("Detect() detached error = %v", err)
	}
	if identity.Branch != "" {
		t.Errorf("detached branch = %q, want empty", identity.Branch)
	}
}

func gitCommand(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", filepath.Clean(root)}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}
