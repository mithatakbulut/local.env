package dotenv

import (
	"reflect"
	"testing"
)

func TestParseSchemaConventionalDotenvWithoutValues(t *testing.T) {
	keys, err := ParseSchema([]byte("\n# comment\nDATABASE_URL=example\nexport REDIS_URL=redis://example\nQUOTED=\"text # remains a value\"\nUNICODE_VALUE='örnek'\nMULTILINE=\"one\ntwo\"\n"))
	if err != nil {
		t.Fatalf("ParseSchema() error = %v", err)
	}
	if want := []string{"DATABASE_URL", "REDIS_URL", "QUOTED", "UNICODE_VALUE", "MULTILINE"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("ParseSchema() = %#v, want %#v", keys, want)
	}
}

func TestParseSchemaRejectsDuplicateAndMalformedKeys(t *testing.T) {
	for name, source := range map[string]string{
		"duplicate":          "ONE=1\nONE=2\n",
		"missing equals":     "ONE\n",
		"invalid key":        "1ONE=value\n",
		"non ASCII key":      "ONEÜ=value\n",
		"unterminated quote": "ONE=\"value\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSchema([]byte(source)); err == nil {
				t.Fatal("ParseSchema() succeeded, want error")
			}
		})
	}
}
