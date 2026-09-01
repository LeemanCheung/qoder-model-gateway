package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func authorizedPaths(t *testing.T) (string, string) {
	t.Helper()
	wasmPath := os.Getenv("QODER2API_WASM_ORACLE")
	fixturePath := os.Getenv("QODER2API_WASM_ORACLE_FIXTURES")
	if wasmPath == "" || fixturePath == "" {
		t.Skip("explicit authorized WASM and fixture paths are required")
	}
	return wasmPath, fixturePath
}

func TestAuthorizedWASMFixtureIntegration(t *testing.T) {
	wasmPath, fixturePath := authorizedPaths(t)
	var output bytes.Buffer
	status := run(context.Background(), []string{"--wasm", wasmPath, "--fixtures", fixturePath, "verify-fixtures"}, &output)
	if status != 0 {
		t.Fatalf("status=%d safe-output=%q", status, output.String())
	}
	wantOperations := []string{`"operation":"credential"`, `"operation":"runtime"`, `"operation":"model-cache"`, `"operation":"infer"`, `"operation":"infer-no-org"`}
	cursor := 0
	for _, operation := range wantOperations {
		index := strings.Index(output.String()[cursor:], operation)
		if index < 0 {
			t.Fatalf("missing ordered operation %s in %q", operation, output.String())
		}
		cursor += index + len(operation)
	}
	for _, forbidden := range []string{"Authorization", "synthetic-access-token", "synthetic-user-0001", "synthetic-org-0001", "Bearer", "Traceback"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("safe output contains %q", forbidden)
		}
	}
}

func TestAuthorizedRecomputedManifestNestedTamperingRejected(t *testing.T) {
	fixturePath := os.Getenv("QODER2API_WASM_ORACLE_FIXTURES")
	if fixturePath == "" {
		t.Skip("explicit frozen fixture path is required")
	}
	tests := []struct {
		name     string
		document string
		category string
		mutate   func(*fixtureDocument)
	}{
		{name: "credential nested extra", document: "credential.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			var plain map[string]any
			_ = json.Unmarshal([]byte(input["plain"].(string)), &plain)
			plain["scope"] = "synthetic-extra"
			encoded, _ := json.Marshal(plain)
			input["plain"] = string(encoded)
			f.Input, _ = json.Marshal(input)
		}},
		{name: "token marker", document: "credential.json", category: "fixture-safety", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			input["plain"] = `{"uid":"synthetic-user-0001","organization_id":"synthetic-org-0001","access_token":"github_pat_sentinel"}`
			f.Input, _ = json.Marshal(input)
		}},
		{name: "prompt substitution", document: "infer-user.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			var body map[string]any
			_ = json.Unmarshal([]byte(input["body_raw"].(string)), &body)
			body["system"] = "synthetic-changed-prompt"
			encoded, _ := json.Marshal(body)
			input["body_raw"] = string(encoded)
			f.Input, _ = json.Marshal(input)
		}},
		{name: "user nested extra", document: "infer-user.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			input["user"].(map[string]any)["access_token"] = "synthetic-token-substitution"
			f.Input, _ = json.Marshal(input)
		}},
		{name: "no-org caller key substitution", document: "infer-user-no-org.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var expected inferFixtureExpectedPolicy
			_ = json.Unmarshal(f.Expected, &expected)
			expected.Header["Cosy-Key"] = []string{"synthetic-substituted-key"}
			f.Expected, _ = json.Marshal(expected)
		}},
		{name: "arbitrary expected", document: "model-cache.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var expected map[string]any
			_ = json.Unmarshal(f.Expected, &expected)
			expected["encrypted"] = "synthetic-arbitrary-expected"
			f.Expected, _ = json.Marshal(expected)
		}},
		{name: "extra transcript read", document: "runtime-fields.json", category: "fixture-transcript-shape", mutate: func(f *fixtureDocument) {
			f.Transcript.EntropyReads = append(f.Transcript.EntropyReads, entropyRead{Length: 1, Bytes: []byte{1}})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := copyFrozenFixtureSet(t, fixturePath)
			policy := pinnedPolicy()
			policy.DocumentHashes = cloneMap(policy.DocumentHashes)
			path := filepath.Join(dir, test.document)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture fixtureDocument
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			test.mutate(&fixture)
			changed := canonicalBytes(t, fixture)
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(changed)
			policy.DocumentHashes[test.document] = hex.EncodeToString(sum[:])
			manifestPath := filepath.Join(dir, "manifest.json")
			manifestData, _ := os.ReadFile(manifestPath)
			var manifest fixtureManifest
			_ = json.Unmarshal(manifestData, &manifest)
			manifest.Documents = cloneMap(policy.DocumentHashes)
			if err := os.WriteFile(manifestPath, canonicalBytes(t, manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := validateFixtureSet(dir, policy); categoryOf(err) != test.category {
				t.Fatalf("category = %q, want %q", categoryOf(err), test.category)
			}
		})
	}
}

func copyFrozenFixtureSet(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range fixtureJSONNames {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAuthorizedWASMFreeAccounting(t *testing.T) {
	wasmPath, fixturePath := authorizedPaths(t)
	source, err := readBoundedRegularFile(wasmPath, pinnedWASMSize, "wasm-read")
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	fixtures, err := validateFixtureSet(fixturePath, pinnedPolicy())
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	accounting, err := verifyFixtures(context.Background(), source, fixtures, &bytes.Buffer{})
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	if accounting != (freeAccounting{ResultStrings: 9, Contexts: 2, RequestResults: 2}) {
		t.Fatalf("free accounting = %#v", accounting)
	}
}
