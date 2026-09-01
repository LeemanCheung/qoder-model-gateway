package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestProtocolFixtureRootSuiteIsStaticReadOnly(t *testing.T) {
	if flag.Lookup("update-protocol-fixtures") != nil {
		t.Fatal("ordinary root tests still register -update-protocol-fixtures")
	}
	paths, err := filepath.Glob("protocol_fixture*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if path == "protocol_fixture_phase9_test.go" {
			continue
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"update-protocol-fixtures",
			"newWasmAuthFromBytes",
			"authWasm",
			"newFixtureBackend",
			"publishFixture",
			"os.CreateTemp",
			"os.Rename",
			"os.WriteFile",
		} {
			if bytes.Contains(encoded, []byte(forbidden)) {
				t.Fatalf("ordinary root fixture suite %s contains forbidden live/update path %q", path, forbidden)
			}
		}
	}
}
