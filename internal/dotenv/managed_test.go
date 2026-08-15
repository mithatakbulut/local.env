package dotenv

import (
	"bytes"
	"strings"
	"testing"
)

func TestUpdateManagedPreservesDeveloperContentAndRoundTripsValues(t *testing.T) {
	source := []byte("MY_DEBUG_FLAG=true\n\n" + ManagedBlockStart + "\nOLD=\"old\"\n" + ManagedBlockEnd + "\n\nLOCAL_ONLY=1\n")
	value := []byte("https://user:pass@example.test/a?x=1# two $= \\\nquote=\"✓")
	result, err := UpdateManaged(source, map[string][]byte{"DATABASE_URL": value})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || strings.Join(result.Added, ",") != "DATABASE_URL" || strings.Join(result.Removed, ",") != "OLD" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !bytes.HasPrefix(result.Content, []byte("MY_DEBUG_FLAG=true\n\n")) || !bytes.HasSuffix(result.Content, []byte("\nLOCAL_ONLY=1\n")) {
		t.Fatalf("developer content changed: %q", result.Content)
	}
	start := bytes.Index(result.Content, []byte(ManagedBlockStart))
	end := bytes.Index(result.Content, []byte(ManagedBlockEnd))
	values, err := Values(result.Content[start:end])
	if err != nil || !bytes.Equal(values["DATABASE_URL"], value) {
		t.Fatalf("round trip = %q, %v", values["DATABASE_URL"], err)
	}
}

func TestUpdateManagedRefusesDuplicateManagedKeyOutsideBlock(t *testing.T) {
	_, err := UpdateManaged([]byte("TOKEN=developer-owned\n"), map[string][]byte{"TOKEN": []byte("managed")})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("error = %v", err)
	}
}

func TestUpdateManagedRefusesMalformedMarkers(t *testing.T) {
	_, err := UpdateManaged([]byte(ManagedBlockStart+"\n"), map[string][]byte{"TOKEN": []byte("value")})
	if err == nil || !strings.Contains(err.Error(), "markers") {
		t.Fatalf("error = %v", err)
	}
}
