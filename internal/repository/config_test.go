package repository

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseConfigAcceptsSingleRepositoryAndMonorepo(t *testing.T) {
	for name, source := range map[string]string{
		"single repository": "version: 1\nfiles:\n  - schema: .env.example\n    target: .env.local\n",
		"monorepo":          "version: 1\nfiles:\n  - schema: apps/web/.env.example\n    target: apps/web/.env.local\n  - schema: apps/api/.env.example\n    target: apps/api/.env.local\n",
	} {
		t.Run(name, func(t *testing.T) {
			config, err := ParseConfig([]byte(source))
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}
			if config.Version != 1 || len(config.Files) == 0 {
				t.Errorf("ParseConfig() = %#v", config)
			}
		})
	}
}

func TestParseConfigRejectsMalformedEscapingAndUnknownContract(t *testing.T) {
	for name, source := range map[string]string{
		"unknown field":      "version: 1\nfiles: []\nmode: permissive\n",
		"version":            "version: 2\nfiles:\n  - schema: .env.example\n    target: .env.local\n",
		"absolute schema":    "version: 1\nfiles:\n  - schema: /tmp/schema\n    target: .env.local\n",
		"parent target":      "version: 1\nfiles:\n  - schema: .env.example\n    target: ../.env.local\n",
		"duplicate yaml key": "version: 1\nversion: 1\nfiles:\n  - schema: .env.example\n    target: .env.local\n",
		"alias":              "version: 1\nfiles: &files\n  - schema: .env.example\n    target: .env.local\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(source)); err == nil {
				t.Fatal("ParseConfig() succeeded, want error")
			}
		})
	}
}

func TestLoadSnapshotRejectsEscapingSymlinkAndDropsSchemaValues(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "localenv.yaml"), []byte("version: 1\nfiles:\n  - schema: schemas/.env.example\n    target: local/.env.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "schemas"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "schemas", ".env.example"), []byte("PUBLIC_KEY=example-default\nPRIVATE_KEY=another-default\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadSnapshot(root)
	if err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}
	if want := []string{"PUBLIC_KEY", "PRIVATE_KEY"}; !reflect.DeepEqual(snapshot.Files[0].Keys, want) {
		t.Errorf("snapshot keys = %#v, want %#v", snapshot.Files[0].Keys, want)
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, ".env.example"), []byte("OUTSIDE=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "schemas", ".env.example")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, ".env.example"), filepath.Join(root, "schemas", ".env.example")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(root); err == nil {
		t.Fatal("LoadSnapshot() accepted schema symlink escaping repository root")
	}
}
