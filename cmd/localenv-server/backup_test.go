package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupCreatesRestrictedArchiveWithSQLiteSnapshot(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("LOCALENV_DATA_DIR", dataDir)
	t.Setenv("LOCALENV_PUBLIC_URL", "https://env.example.test")
	output := filepath.Join(t.TempDir(), "localenv.tar.gz")
	var stdout, stderr bytes.Buffer
	if code := runBackup([]string{"--output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("runBackup() = %d, stderr = %s", code, stderr.String())
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup archive permissions = %v, %v", info, err)
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	header, err := archive.Next()
	if err != nil || header.Name != "localenv.db" || header.Mode != 0o600 {
		t.Fatalf("backup member = %#v, %v", header, err)
	}
	if _, err := archive.Next(); err == nil {
		t.Fatal("empty instance backup unexpectedly included additional files")
	}
	if code := runBackup([]string{"--output", output}, &stdout, &stderr); code == 0 {
		t.Fatal("backup overwrote an existing archive")
	}
}
