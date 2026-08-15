package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/localenv/localenv/internal/config"
	"github.com/localenv/localenv/internal/store/sqlite"
)

// runBackup writes a portable gzip tar archive. Its database member is made
// using SQLite's online backup mechanism, so copying live WAL side files is
// neither needed nor permitted.
func runBackup(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(errOut)
	output := flags.String("output", "", "destination .tar.gz archive")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *output == "" {
		fmt.Fprintln(errOut, "Usage: localenv-server backup --output /absolute/path/localenv-YYYY-MM-DD.tar.gz")
		return 2
	}
	archivePath, err := filepath.Abs(*output)
	if err != nil {
		fmt.Fprintln(errOut, "localenv-server: invalid backup output path")
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not create the backup output directory")
		return 1
	}
	if _, err := os.Lstat(archivePath); err == nil || !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(errOut, "localenv-server: backup output already exists or cannot be inspected")
		return 1
	}
	cfg, err := config.LoadFromEnv()
	if err != nil {
		fmt.Fprintln(errOut, "localenv-server: invalid configuration")
		return 1
	}
	store, err := sqlite.Open(context.Background(), cfg.DataDir)
	if err != nil {
		fmt.Fprintln(errOut, "localenv-server: database initialization failed")
		return 1
	}
	defer store.Close()
	temporary, err := os.CreateTemp(cfg.DataDir, ".localenv-backup-*.db")
	if err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not prepare the online database backup")
		return 1
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil || os.Remove(temporaryPath) != nil {
		fmt.Fprintln(errOut, "localenv-server: could not prepare the online database backup")
		return 1
	}
	defer os.Remove(temporaryPath)
	if err := store.BackupTo(context.Background(), temporaryPath); err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not create the online database backup")
		return 1
	}
	archive, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not create the backup archive")
		return 1
	}
	completed := false
	defer func() {
		archive.Close()
		if !completed {
			_ = os.Remove(archivePath)
		}
	}()
	gzipWriter := gzip.NewWriter(archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := addArchiveFile(tarWriter, temporaryPath, "localenv.db"); err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not write the database backup archive")
		return 1
	}
	for _, name := range []string{"github-app-credentials.enc", "github-app-private-key.pem", "instance.json"} {
		path := filepath.Join(cfg.DataDir, name)
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			fmt.Fprintln(errOut, "localenv-server: could not read a persistent instance file")
			return 1
		}
		if err := addArchiveFile(tarWriter, path, name); err != nil {
			fmt.Fprintln(errOut, "localenv-server: could not write a persistent instance file")
			return 1
		}
	}
	if err := tarWriter.Close(); err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not finalize backup archive")
		return 1
	}
	if err := gzipWriter.Close(); err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not finalize backup archive")
		return 1
	}
	if err := archive.Close(); err != nil {
		fmt.Fprintln(errOut, "localenv-server: could not finalize backup archive")
		return 1
	}
	completed = true
	fmt.Fprintf(out, "Backup created: %s\n", archivePath)
	return 0
}

func addArchiveFile(writer *tar.Writer, source, archiveName string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("backup source is not a regular file")
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()
	header := &tar.Header{Name: archiveName, Mode: 0o600, Size: info.Size(), ModTime: time.Now().UTC(), Typeflag: tar.TypeReg}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(writer, file)
	return err
}
