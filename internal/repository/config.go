// Package repository implements the local repository contract used by v1.
package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/localenv/localenv/internal/dotenv"
	"gopkg.in/yaml.v3"
)

const configFilename = "localenv.yaml"

// Config is the complete, strict v1 localenv.yaml contract.
type Config struct {
	Version int
	Files   []File
}

// File maps a committed schema file to one developer-local dotenv file.
type File struct {
	Schema string
	Target string
}

// Snapshot contains only public repository contract metadata and schema key
// names. It deliberately cannot carry schema values.
type Snapshot struct {
	Config Config
	Files  []SchemaFile
}

// SchemaFile is one configured schema and its required keys.
type SchemaFile struct {
	Schema string
	Target string
	Keys   []string
}

// ParseConfig parses localenv.yaml, rejecting unknown fields and YAML features
// that obscure the contract (aliases, anchors, duplicate mapping keys).
func ParseConfig(source []byte) (Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	decoder.KnownFields(true)
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Config{}, fmt.Errorf("parse localenv.yaml: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err == nil {
		return Config{}, errors.New("localenv.yaml must contain one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse localenv.yaml: %w", err)
	}
	if containsUnsupportedYAML(&document) {
		return Config{}, errors.New("localenv.yaml must not use YAML aliases or anchors")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return Config{}, errors.New("localenv.yaml must be a mapping")
	}
	root := document.Content[0]
	if err := uniqueMappingKeys(root); err != nil {
		return Config{}, err
	}
	if err := onlyFields(root, "version", "files"); err != nil {
		return Config{}, err
	}
	for index := 1; index < len(root.Content); index += 2 {
		if root.Content[index-1].Value != "files" {
			continue
		}
		files := root.Content[index]
		if files.Kind != yaml.SequenceNode {
			return Config{}, errors.New("localenv.yaml files must be a sequence")
		}
		for _, file := range files.Content {
			if file.Kind != yaml.MappingNode {
				return Config{}, errors.New("localenv.yaml files entries must be mappings")
			}
			if err := onlyFields(file, "schema", "target"); err != nil {
				return Config{}, err
			}
		}
	}
	var raw struct {
		Version int    `yaml:"version"`
		Files   []File `yaml:"files"`
	}
	if err := root.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode localenv.yaml: %w", err)
	}
	if raw.Version != 1 {
		return Config{}, errors.New("localenv.yaml version must be 1")
	}
	if len(raw.Files) == 0 {
		return Config{}, errors.New("localenv.yaml files must not be empty")
	}
	seenSchemas, seenTargets := make(map[string]struct{}), make(map[string]struct{})
	for index, file := range raw.Files {
		if err := validateRelativePath(file.Schema); err != nil {
			return Config{}, fmt.Errorf("files[%d].schema: %w", index, err)
		}
		if err := validateRelativePath(file.Target); err != nil {
			return Config{}, fmt.Errorf("files[%d].target: %w", index, err)
		}
		if _, exists := seenSchemas[file.Schema]; exists {
			return Config{}, fmt.Errorf("duplicate schema path %q", file.Schema)
		}
		if _, exists := seenTargets[file.Target]; exists {
			return Config{}, fmt.Errorf("duplicate target path %q", file.Target)
		}
		seenSchemas[file.Schema], seenTargets[file.Target] = struct{}{}, struct{}{}
	}
	return Config{Version: raw.Version, Files: raw.Files}, nil
}

// LoadSnapshot finds localenv.yaml at repository root and validates every
// configured path against that root before parsing schema key names.
func LoadSnapshot(root string) (Snapshot, error) {
	resolvedRoot, err := resolveRoot(root)
	if err != nil {
		return Snapshot{}, err
	}
	configPath, err := safePath(resolvedRoot, configFilename, true)
	if err != nil {
		return Snapshot{}, fmt.Errorf("localenv.yaml: %w", err)
	}
	source, err := os.ReadFile(configPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read localenv.yaml: %w", err)
	}
	config, err := ParseConfig(source)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Config: config, Files: make([]SchemaFile, 0, len(config.Files))}
	for _, file := range config.Files {
		schemaPath, err := safePath(resolvedRoot, file.Schema, true)
		if err != nil {
			return Snapshot{}, fmt.Errorf("schema %q: %w", file.Schema, err)
		}
		if _, err := safePath(resolvedRoot, file.Target, false); err != nil {
			return Snapshot{}, fmt.Errorf("target %q: %w", file.Target, err)
		}
		schema, err := os.ReadFile(schemaPath)
		if err != nil {
			return Snapshot{}, fmt.Errorf("read schema %q: %w", file.Schema, err)
		}
		keys, err := dotenv.ParseSchema(schema)
		if err != nil {
			return Snapshot{}, fmt.Errorf("schema %q: %w", file.Schema, err)
		}
		snapshot.Files = append(snapshot.Files, SchemaFile{Schema: file.Schema, Target: file.Target, Keys: keys})
	}
	return snapshot, nil
}

func validateRelativePath(path string) error {
	if path == "" || strings.TrimSpace(path) != path {
		return errors.New("must be a non-empty path without surrounding whitespace")
	}
	if filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return errors.New("must be a relative slash-separated path")
	}
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || cleaned != path {
		return errors.New("must stay inside the repository root")
	}
	return nil
}

func resolveRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("repository root must be an existing directory")
	}
	return resolved, nil
}

func safePath(root, relative string, mustExist bool) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	current := root
	for _, component := range strings.Split(relative, "/") {
		candidate := filepath.Join(current, component)
		info, err := os.Lstat(candidate)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				current = candidate
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(candidate)
			if err != nil {
				return "", fmt.Errorf("resolve symlink: %w", err)
			}
			if !withinRoot(root, resolved) {
				return "", errors.New("symlink escapes repository root")
			}
			current = resolved
			continue
		}
		current = candidate
	}
	if !withinRoot(root, current) {
		return "", errors.New("path escapes repository root")
	}
	if mustExist {
		info, err := os.Stat(current)
		if err != nil {
			return "", err
		}
		if info.IsDir() {
			return "", errors.New("must be a file")
		}
	}
	return current, nil
}

func withinRoot(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func containsUnsupportedYAML(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return true
	}
	for _, child := range node.Content {
		if containsUnsupportedYAML(child) {
			return true
		}
	}
	return false
}

func uniqueMappingKeys(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{})
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return errors.New("localenv.yaml mapping keys must be strings")
			}
			if _, exists := seen[key.Value]; exists {
				return fmt.Errorf("duplicate localenv.yaml field %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := uniqueMappingKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func onlyFields(node *yaml.Node, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		allowedSet[field] = struct{}{}
	}
	for index := 0; index < len(node.Content); index += 2 {
		name := node.Content[index].Value
		if _, ok := allowedSet[name]; !ok {
			return fmt.Errorf("unknown localenv.yaml field %q", name)
		}
	}
	return nil
}
