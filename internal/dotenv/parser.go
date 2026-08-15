// Package dotenv parses dotenv files without retaining their values.
package dotenv

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// ParseSchema returns the declared key names in source order. Values are
// intentionally discarded: schema defaults must never become managed secrets.
func ParseSchema(source []byte) ([]string, error) {
	reader := bufio.NewReader(bytes.NewReader(source))
	keys := make([]string, 0)
	seen := make(map[string]struct{})

	for lineNumber := 1; ; lineNumber++ {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read dotenv schema: %w", err)
		}
		if len(line) > 0 {
			key, value, hasAssignment, parseErr := assignment(line)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid dotenv schema line %d: %w", lineNumber, parseErr)
			}
			if hasAssignment {
				if _, duplicate := seen[key]; duplicate {
					return nil, fmt.Errorf("duplicate dotenv schema key %q", key)
				}
				seen[key] = struct{}{}
				keys = append(keys, key)
				if quote := openingQuote(value); quote != 0 && !quoteClosed(value, quote) {
					if err := consumeQuotedValue(reader, quote); err != nil {
						return nil, fmt.Errorf("unterminated quoted dotenv value starting at line %d", lineNumber)
					}
				}
			}
		}
		if err == io.EOF {
			break
		}
	}
	return keys, nil
}

func assignment(line string) (key, value string, hasAssignment bool, err error) {
	trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\n"))
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false, nil
	}
	if strings.HasPrefix(trimmed, "export") && len(trimmed) > len("export") && unicode.IsSpace(rune(trimmed[len("export")])) {
		trimmed = strings.TrimLeftFunc(trimmed[len("export"):], unicode.IsSpace)
	}
	equals := strings.IndexByte(trimmed, '=')
	if equals < 1 {
		return "", "", false, fmt.Errorf("expected KEY=value assignment")
	}
	key = strings.TrimSpace(trimmed[:equals])
	if !validKey(key) {
		return "", "", false, fmt.Errorf("invalid key name")
	}
	return key, strings.TrimLeftFunc(trimmed[equals+1:], unicode.IsSpace), true, nil
}

func validKey(key string) bool {
	if key == "" || !asciiLetterOrUnderscore(key[0]) {
		return false
	}
	for index := 1; index < len(key); index++ {
		if !asciiLetterOrUnderscore(key[index]) && (key[index] < '0' || key[index] > '9') {
			return false
		}
	}
	return true
}

func asciiLetterOrUnderscore(character byte) bool {
	return character == '_' || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
}

func openingQuote(value string) byte {
	if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
		return value[0]
	}
	return 0
}

func quoteClosed(value string, quote byte) bool {
	escaped := false
	for index := 1; index < len(value); index++ {
		if quote == '"' && value[index] == '\\' && !escaped {
			escaped = true
			continue
		}
		if value[index] == quote && !escaped {
			return true
		}
		escaped = false
	}
	return false
}

func consumeQuotedValue(reader *bufio.Reader, quote byte) error {
	for {
		line, err := reader.ReadString('\n')
		if quoteClosed(string(append([]byte{quote}, []byte(line)...)), quote) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
