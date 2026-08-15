// Package pranalysis deterministically compares complete dotenv schemas at a
// pull request's base and head commits. It carries only config and key names.
package pranalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/localenv/localenv/internal/dotenv"
	"github.com/localenv/localenv/internal/githubapp"
	"github.com/localenv/localenv/internal/repository"
)

const (
	StateMissing = "missing"
	StateReady   = "ready"
	StateRemoved = "removed"
)

// FileReader is the narrow authenticated GitHub boundary the analyzer needs.
type FileReader interface {
	ReadFile(context.Context, githubapp.Credentials, int64, string, string, string, string) ([]byte, error)
}

// Requirement describes one public key-name requirement, never its value.
type Requirement struct {
	FileID     string
	SchemaPath string
	TargetPath string
	KeyName    string
	State      string
}

// Result contains the complete head contract and differences from base.
type Result struct {
	Requirements []Requirement
}

// Analyze fetches localenv.yaml from head, then every configured schema at both
// immutable commits. Missing base files are empty schemas; missing head files
// are invalid PR contracts and fail analysis rather than silently passing.
func Analyze(ctx context.Context, reader FileReader, credentials githubapp.Credentials, installationID int64, pull githubapp.PullRequest) (Result, error) {
	headConfig, err := reader.ReadFile(ctx, credentials, installationID, pull.Repository.Owner, pull.Repository.Name, "localenv.yaml", pull.HeadSHA)
	if err != nil {
		return Result{}, fmt.Errorf("read head localenv.yaml: %w", err)
	}
	config, err := repository.ParseConfig(headConfig)
	if err != nil {
		return Result{}, fmt.Errorf("parse head localenv.yaml: %w", err)
	}
	result := Result{}
	for _, file := range config.Files {
		headSource, err := reader.ReadFile(ctx, credentials, installationID, pull.Repository.Owner, pull.Repository.Name, file.Schema, pull.HeadSHA)
		if err != nil {
			return Result{}, fmt.Errorf("read head schema %q: %w", file.Schema, err)
		}
		headKeys, err := dotenv.ParseSchema(headSource)
		if err != nil {
			return Result{}, fmt.Errorf("parse head schema %q: %w", file.Schema, err)
		}
		baseSource, err := reader.ReadFile(ctx, credentials, installationID, pull.Repository.Owner, pull.Repository.Name, file.Schema, pull.BaseSHA)
		baseKeys := []string(nil)
		if err != nil {
			if !errors.Is(err, githubapp.ErrNotFound) {
				return Result{}, fmt.Errorf("read base schema %q: %w", file.Schema, err)
			}
		} else if baseKeys, err = dotenv.ParseSchema(baseSource); err != nil {
			return Result{}, fmt.Errorf("parse base schema %q: %w", file.Schema, err)
		}
		fileID := FileID(pull.Repository.GitHubRepoID, file.Schema, file.Target)
		for _, key := range difference(headKeys, baseKeys) {
			result.Requirements = append(result.Requirements, Requirement{FileID: fileID, SchemaPath: file.Schema, TargetPath: file.Target, KeyName: key, State: StateMissing})
		}
		for _, key := range difference(baseKeys, headKeys) {
			result.Requirements = append(result.Requirements, Requirement{FileID: fileID, SchemaPath: file.Schema, TargetPath: file.Target, KeyName: key, State: StateRemoved})
		}
	}
	return result, nil
}

// FileID is stable across config snapshots and PR analysis, while preserving
// only the public repository file mapping.
func FileID(githubRepositoryID int64, schemaPath, targetPath string) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", githubRepositoryID, schemaPath, targetPath)))
	return "file:" + hex.EncodeToString(digest[:16])
}

func difference(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, key := range right {
		rightSet[key] = struct{}{}
	}
	result := make([]string, 0)
	for _, key := range left {
		if _, exists := rightSet[key]; !exists {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}
