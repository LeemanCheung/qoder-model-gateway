package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeOnlyTransitionFlagsAreUnknown(t *testing.T) {
	for _, name := range []string{"protocol-mode", "shadow-capabilities"} {
		var output bytes.Buffer
		_, err := parseAppConfig([]string{"-" + name + "=synthetic"}, envLookup(nil), &output)
		if err == nil {
			t.Fatalf("removed flag -%s was accepted", name)
		}
		if !strings.Contains(output.String(), "flag provided but not defined: -"+name) {
			t.Fatalf("removed flag -%s did not fail as an unknown flag", name)
		}
	}
}

func TestNativeOnlyTransitionEnvironmentIsIgnored(t *testing.T) {
	queried := make(map[string]bool)
	lookup := func(key string) (string, bool) {
		queried[key] = true
		switch key {
		case "QODER2API_PROTOCOL_MODE":
			return "shadow", true
		case "QODER2API_SHADOW_CAPABILITIES":
			return "infer", true
		default:
			return "", false
		}
	}
	if _, err := parseAppConfig(nil, lookup, io.Discard); err != nil {
		t.Fatalf("legacy transition environment changed native-only defaults: %v", err)
	}
	for _, key := range []string{"QODER2API_PROTOCOL_MODE", "QODER2API_SHADOW_CAPABILITIES"} {
		if queried[key] {
			t.Fatalf("native-only config still reads %s", key)
		}
	}
}

func TestNativeOnlyStartupOmitsProtocolModeLog(t *testing.T) {
	h := newAppRunHarness(t)
	var logs []string
	always := func(format string, args ...any) {
		logs = append(logs, format)
	}
	if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, always); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	for _, line := range logs {
		if strings.Contains(strings.ToLower(line), "protocol mode") {
			t.Fatalf("native-only startup still logs a protocol mode: %q", line)
		}
	}
}

func TestNativeOnlySourceLayout(t *testing.T) {
	for _, path := range []string{
		"assets/qoder_auth_wasm_bg.wasm",
		"wasm.go",
		"wasm_manifest.go",
		"wasm_protocol.go",
		"wasm_test.go",
		"wasm_stress_test.go",
		"wasm_fixture_test_helpers_test.go",
		"protocol_mode.go",
		"protocol_mode_test.go",
		"protocol_shadow.go",
		"protocol_shadow_test.go",
		"protocol_shadow_reporter.go",
		"protocol_shadow_reporter_test.go",
		"protocol_fallback.go",
		"protocol_fallback_test.go",
	} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("removed transition path still exists: %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect transition path %s: %v", path, err)
		}
	}

	moduleFiles := []string{"go.mod", "go.sum"}
	for _, path := range moduleFiles {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, dependency := range []string{"github.com/tetratelabs/wazero", "golang.org/x/sys"} {
			if bytes.Contains(contents, []byte(dependency)) {
				t.Errorf("root %s still contains %s", path, dependency)
			}
		}
	}

	services, err := os.ReadFile("protocol_services.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(services, []byte("func newProtocolServices(host protocolHostDeps)")) {
		t.Error("newProtocolServices is not a single native-only host constructor")
	}
	for _, forbidden := range []string{
		"protocolServiceConfig",
		"protocolServiceFactories",
		"newWASMProtocolServices",
		"newShadowProtocolServices",
		"newNativeFallbackProtocolServices",
		"type protocolBackend interface",
		"owners []",
	} {
		if bytes.Contains(services, []byte(forbidden)) {
			t.Errorf("protocol_services.go still contains transition construct %q", forbidden)
		}
	}
}

func TestNativeOnlyProductionAndTestsDoNotUseEmbeddedWASM(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := entry.Name()
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, contents, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, group := range parsed.Comments {
			for _, comment := range group.List {
				if strings.HasPrefix(comment.Text, "//go:"+"embed") {
					t.Errorf("root Go source still embeds an asset: %s", path)
				}
			}
		}
		for _, imported := range parsed.Imports {
			if imported.Path != nil && strings.Contains(imported.Path.Value, "tetratelabs/wazero") {
				t.Errorf("root Go source still imports wazero: %s", path)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			switch identifier.Name {
			case "authWasm", "wasmAuth", "newWasmAuth", "newWasmAuthFromBytes", "newWasmAuthWithConfig":
				t.Errorf("root Go source %s still references embedded WASM identifier %s", path, identifier.Name)
			}
			return true
		})
	}
}

func TestNativeOnlyBinaryAudit(t *testing.T) {
	binaryPath := os.Getenv("QODER2API_NATIVE_BINARY_AUDIT")
	oraclePath := os.Getenv("QODER2API_EXTERNAL_WASM_ORACLE")
	if binaryPath == "" || oraclePath == "" {
		t.Skip("set native binary and external oracle paths for binary audit")
	}
	binaryBytes, err := os.ReadFile(filepath.Clean(binaryPath))
	if err != nil {
		t.Fatalf("read native binary: %v", err)
	}
	oracleBytes, err := os.ReadFile(filepath.Clean(oraclePath))
	if err != nil {
		t.Fatalf("read external oracle: %v", err)
	}
	if len(oracleBytes) == 0 {
		t.Fatal("external oracle is empty")
	}
	if bytes.Contains(binaryBytes, oracleBytes) {
		t.Fatal("native production binary contains the complete external oracle byte sequence")
	}
	info, err := buildinfo.ReadFile(filepath.Clean(binaryPath))
	if err != nil {
		t.Fatalf("read native binary build info: %v", err)
	}
	for _, dependency := range info.Deps {
		if dependency != nil && strings.Contains(dependency.Path, "tetratelabs/wazero") {
			t.Fatal("native production binary metadata contains wazero")
		}
	}
}

func TestNativeOnlyRemovedFlagsDoNotPolluteGlobalFlagSet(t *testing.T) {
	for _, name := range []string{"protocol-mode", "shadow-capabilities"} {
		if flag.CommandLine.Lookup(name) != nil {
			t.Fatalf("global flag set contains removed application flag %q", name)
		}
	}
}
