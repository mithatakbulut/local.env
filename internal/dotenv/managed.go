package dotenv

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	ManagedBlockStart = "# >>> local.env managed — do not edit manually"
	ManagedBlockEnd   = "# <<< local.env managed"
)

// ManagedResult is the deterministic replacement and key-level change summary
// for a local.env managed block. Values never leave the calling CLI process.
type ManagedResult struct {
	Content []byte
	Added   []string
	Updated []string
	Removed []string
	Changed bool
}

// UpdateManaged replaces only the local.env managed block. It refuses files
// with malformed markers or a managed key outside the block, preserving all
// developer-owned content verbatim.
func UpdateManaged(source []byte, values map[string][]byte) (ManagedResult, error) {
	for key := range values {
		if !validKey(key) {
			return ManagedResult{}, fmt.Errorf("invalid managed key %q", key)
		}
	}
	start, end, err := managedBlock(source)
	if err != nil {
		return ManagedResult{}, err
	}
	current, err := Values(source[start:end])
	if err != nil {
		return ManagedResult{}, fmt.Errorf("parse managed block: %w", err)
	}
	outside := append(append([]byte(nil), source[:start]...), source[end:]...)
	outsideKeys, err := Keys(outside)
	if err != nil {
		return ManagedResult{}, fmt.Errorf("parse developer-owned content: %w", err)
	}
	for key := range values {
		if _, duplicate := outsideKeys[key]; duplicate {
			return ManagedResult{}, fmt.Errorf("managed key %q also exists outside the local.env managed block", key)
		}
	}
	result := ManagedResult{}
	for key, value := range values {
		previous, exists := current[key]
		if !exists {
			result.Added = append(result.Added, key)
		} else if !bytes.Equal(previous, value) {
			result.Updated = append(result.Updated, key)
		}
	}
	for key := range current {
		if _, exists := values[key]; !exists {
			result.Removed = append(result.Removed, key)
		}
	}
	for _, keys := range [][]string{result.Added, result.Updated, result.Removed} {
		sort.Strings(keys)
	}
	block := renderManagedBlock(values)
	if start == len(source) && end == len(source) && len(source) > 0 && source[len(source)-1] != '\n' {
		block = append([]byte{'\n'}, block...)
	}
	result.Content = append(append(append([]byte(nil), source[:start]...), block...), source[end:]...)
	result.Changed = !bytes.Equal(source, result.Content)
	return result, nil
}

// ManagedValues returns the parsed values currently inside the local.env
// block. A file without a block is valid and returns an empty map.
func ManagedValues(source []byte) (map[string][]byte, error) {
	start, end, err := managedBlock(source)
	if err != nil {
		return nil, err
	}
	if start == len(source) && end == len(source) {
		return map[string][]byte{}, nil
	}
	return Values(source[start:end])
}

// DeveloperKeys returns assignment names outside the local.env managed block.
func DeveloperKeys(source []byte) (map[string]struct{}, error) {
	start, end, err := managedBlock(source)
	if err != nil {
		return nil, err
	}
	outside := append(append([]byte(nil), source[:start]...), source[end:]...)
	return Keys(outside)
}

func managedBlock(source []byte) (int, int, error) {
	startMarker := []byte(ManagedBlockStart)
	endMarker := []byte(ManagedBlockEnd)
	firstStart := bytes.Index(source, startMarker)
	firstEnd := bytes.Index(source, endMarker)
	if firstStart < 0 && firstEnd < 0 {
		if len(source) == 0 {
			return 0, 0, nil
		}
		return len(source), len(source), nil
	}
	if firstStart < 0 || firstEnd < 0 || firstEnd < firstStart || bytes.Index(source[firstStart+len(startMarker):], startMarker) >= 0 || bytes.Index(source[firstEnd+len(endMarker):], endMarker) >= 0 {
		return 0, 0, errors.New("local.env managed block markers are malformed")
	}
	start := firstStart
	end := firstEnd + len(endMarker)
	if end < len(source) && source[end] == '\n' {
		end++
	}
	return start, end, nil
}

func renderManagedBlock(values map[string][]byte) []byte {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var block strings.Builder
	block.WriteString(ManagedBlockStart)
	block.WriteByte('\n')
	for _, key := range keys {
		block.WriteString(key)
		block.WriteByte('=')
		block.WriteString(Quote(values[key]))
		block.WriteByte('\n')
	}
	block.WriteString(ManagedBlockEnd)
	block.WriteByte('\n')
	return []byte(block.String())
}

// Quote deterministically emits a double-quoted dotenv value which Values
// decodes to the exact input bytes.
func Quote(value []byte) string {
	var result strings.Builder
	result.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\\':
			result.WriteString(`\\`)
		case '"':
			result.WriteString(`\"`)
		case '\n':
			result.WriteString(`\n`)
		case '\r':
			result.WriteString(`\r`)
		case '\t':
			result.WriteString(`\t`)
		default:
			result.WriteByte(character)
		}
	}
	result.WriteByte('"')
	return result.String()
}

// Keys returns assignments present in source. It is deliberately strict so a
// malformed developer file cannot be partially rewritten.
func Keys(source []byte) (map[string]struct{}, error) {
	values, err := Values(source)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]struct{}, len(values))
	for key := range values {
		keys[key] = struct{}{}
	}
	return keys, nil
}

// Values parses the dotenv subset emitted by Quote plus conventional
// unquoted and single-quoted assignments. It rejects duplicate assignments.
func Values(source []byte) (map[string][]byte, error) {
	result := make(map[string][]byte)
	for lineNumber, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "export") && len(trimmed) > len("export") && (trimmed[len("export")] == ' ' || trimmed[len("export")] == '\t') {
			trimmed = strings.TrimSpace(trimmed[len("export"):])
		}
		key, raw, found := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		if !found || !validKey(key) {
			return nil, fmt.Errorf("invalid dotenv assignment at line %d", lineNumber+1)
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate dotenv key %q", key)
		}
		value, err := decodeValue(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid dotenv value at line %d: %w", lineNumber+1, err)
		}
		result[key] = value
	}
	return result, nil
}

func decodeValue(raw string) ([]byte, error) {
	if raw == "" {
		return []byte{}, nil
	}
	if raw[0] == '\'' {
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return nil, errors.New("unterminated single quote")
		}
		return []byte(raw[1 : len(raw)-1]), nil
	}
	if raw[0] != '"' {
		return []byte(strings.TrimSpace(raw)), nil
	}
	if len(raw) < 2 || raw[len(raw)-1] != '"' {
		return nil, errors.New("unterminated double quote")
	}
	decoded := make([]byte, 0, len(raw)-2)
	for index := 1; index < len(raw)-1; index++ {
		if raw[index] != '\\' {
			decoded = append(decoded, raw[index])
			continue
		}
		index++
		if index >= len(raw)-1 {
			return nil, errors.New("dangling escape")
		}
		switch raw[index] {
		case '\\', '"':
			decoded = append(decoded, raw[index])
		case 'n':
			decoded = append(decoded, '\n')
		case 'r':
			decoded = append(decoded, '\r')
		case 't':
			decoded = append(decoded, '\t')
		default:
			return nil, errors.New("unsupported escape")
		}
	}
	return decoded, nil
}
