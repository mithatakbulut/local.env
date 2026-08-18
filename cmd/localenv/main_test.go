package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlagPrintsBuildVersionOnly(t *testing.T) {
	version = "v1.1.3"
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "v1.1.3" || errOut.Len() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}
