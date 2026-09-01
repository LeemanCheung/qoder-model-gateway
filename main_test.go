package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeModelCacheDecryptor struct {
	calls int
	input string
	uid   string
	data  []byte
	err   error
}

func (f *fakeModelCacheDecryptor) Decrypt(_ context.Context, input, uid string) ([]byte, error) {
	f.calls++
	f.input = input
	f.uid = uid
	return f.data, f.err
}

func modelByKey(catalog []*modelConfig, key string) *modelConfig {
	for _, model := range catalog {
		if model.Key == key {
			return model
		}
	}
	return nil
}

func TestLoadCatalogExplicitFileBypassesDecryptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"chat":[{"key":"explicit","display_name":"Explicit"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	decryptor := &fakeModelCacheDecryptor{err: errors.New("must not be called")}

	catalog := loadCatalog(context.Background(), decryptor, filepath.Join(t.TempDir(), "auth", "user"), "synthetic-user", path, t.Logf)

	if decryptor.calls != 0 {
		t.Fatalf("Decrypt() calls = %d, want 0", decryptor.calls)
	}
	if model := modelByKey(catalog, "explicit"); model == nil || !model.Enable || model.Format != "openai" || model.Source != "system" {
		t.Fatalf("explicit model = %#v, want merged defaults", model)
	}
}

func TestLoadCatalogUsesModelCacheDecryptor(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-user"
	cachePath := filepath.Join(root, ".models", uid, "catalog-v6")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("  encrypted-catalog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decryptor := &fakeModelCacheDecryptor{data: []byte(`{"chat":[{"key":"cached","display_name":"Cached","context_config":{"default":{"token_count":321000}}}]}`)}

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

	if decryptor.calls != 1 || decryptor.input != "encrypted-catalog" || decryptor.uid != uid {
		t.Fatalf("Decrypt() = calls %d, input %q, uid %q", decryptor.calls, decryptor.input, decryptor.uid)
	}
	if model := modelByKey(catalog, "cached"); model == nil || model.MaxInputTokens != 321000 || !model.Enable {
		t.Fatalf("cached model = %#v, want merged cache model", model)
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("merged catalog lost builtin auto model")
	}
}

func TestLoadCatalogFallsBackAfterDecryptError(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-user"
	cachePath := filepath.Join(root, ".models", uid, "catalog-v6")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	decryptor := &fakeModelCacheDecryptor{err: errors.New("synthetic decrypt failure")}

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

	if decryptor.calls != 1 {
		t.Fatalf("Decrypt() calls = %d, want 1", decryptor.calls)
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("fallback catalog is missing builtin auto model")
	}
}

func TestLoadCatalogNilDecryptorFallsBack(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	cachePath := filepath.Join(root, ".models", "synthetic-user", "catalog-v6")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := loadCatalog(context.Background(), nil, authFile, "synthetic-user", "", t.Logf)
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("fallback catalog is missing builtin auto model")
	}
}

func TestLoadCatalogMissingCacheDoesNotDecrypt(t *testing.T) {
	decryptor := &fakeModelCacheDecryptor{}
	catalog := loadCatalog(context.Background(), decryptor, filepath.Join(t.TempDir(), ".auth", "user"), "synthetic-user", "", t.Logf)
	if decryptor.calls != 0 {
		t.Fatalf("Decrypt() calls = %d, want 0", decryptor.calls)
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("catalog is missing builtin auto model")
	}
}

func TestLoadCatalogMergesNativeQMCV1Cache(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-native-catalog-user"
	plain := []byte(`{"chat":[{"key":"native-cached","display_name":"Native Cached","context_config":{"default":{"token_count":654321}}}]}`)
	blob, err := encryptQMCV1ForTest(plain, uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("catalog plaintext length %d: encrypt returned kind %q", len(plain), protocolErrorKindOf(err))
	}
	writeDynamicCatalogCache(t, authFile, uid, blob)

	catalog := loadCatalog(context.Background(), nativeModelCacheDecryptor{}, authFile, uid, "", func(string, ...any) {})

	model := modelByKey(catalog, "native-cached")
	if model == nil || !model.Enable || model.Format != "openai" || model.Source != "system" || model.MaxInputTokens != 654321 {
		t.Fatal("native QMC catalog model was not merged with approved defaults")
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("native QMC merge lost builtin auto model")
	}
}

func TestLoadCatalogNativeQMCV1FailuresRetainBuiltinCatalog(t *testing.T) {
	const uid = "synthetic-fallback-catalog-user"
	validPlain := []byte(`{"chat":[{"key":"must-not-merge","display_name":"Must Not Merge"}]}`)
	valid, err := encryptQMCV1ForTest(validPlain, uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("valid fallback setup length %d: encrypt returned kind %q", len(validPlain), protocolErrorKindOf(err))
	}
	unknownVersion := mutateCatalogQMCBlob(t, valid, len(qmcV1Prefix)-1)
	badTag := mutateCatalogQMCBlob(t, valid, -1)
	wrongUIDBlob, err := encryptQMCV1ForTest(validPlain, "synthetic-other-catalog-user", []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("wrong-UID setup length %d: encrypt returned kind %q", len(validPlain), protocolErrorKindOf(err))
	}
	invalidJSON, err := encryptQMCV1ForTest([]byte("synthetic invalid JSON"), uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("invalid-JSON setup length %d: encrypt returned kind %q", len("synthetic invalid JSON"), protocolErrorKindOf(err))
	}

	tests := []struct {
		name      string
		blob      string
		writeFile bool
		decryptor modelCacheDecryptor
	}{
		{name: "unknown version", blob: unknownVersion, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "bad tag", blob: badTag, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "wrong UID", blob: wrongUIDBlob, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "invalid JSON", blob: invalidJSON, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "missing file", decryptor: nativeModelCacheDecryptor{}},
		{name: "nil decryptor", blob: valid, writeFile: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			authFile := filepath.Join(root, ".auth", "user")
			if tt.writeFile {
				writeDynamicCatalogCache(t, authFile, uid, tt.blob)
			}
			catalog := loadCatalog(context.Background(), tt.decryptor, authFile, uid, "", func(string, ...any) {})
			if modelByKey(catalog, "auto") == nil {
				t.Fatalf("case %s: fallback catalog lacks builtin auto model", tt.name)
			}
			if modelByKey(catalog, "must-not-merge") != nil {
				t.Fatalf("case %s: invalid dynamic catalog was merged", tt.name)
			}
		})
	}
}

func TestCatalogReadErrorDetailOmitsPath(t *testing.T) {
	const path = "/SENTINEL-DYNAMIC-CATALOG-UID/catalog-v6"
	err := &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
	detail := catalogReadErrorDetail(err)
	if !strings.Contains(detail, "open") || !strings.Contains(detail, os.ErrPermission.Error()) {
		t.Fatalf("detail = %q, want operation and errno", detail)
	}
	if strings.Contains(detail, path) || strings.Contains(detail, "SENTINEL-DYNAMIC-CATALOG-UID") {
		t.Fatalf("detail leaked path: %q", detail)
	}
}

func TestCatalogDecryptErrorDetailUsesTypedProtocolCauseButHidesArbitraryText(t *testing.T) {
	typed := newProtocolError(
		protocolBackendIncompatible,
		"model cache data is incompatible",
		errors.New("model cache envelope authentication failed"),
	)
	typedDetail := catalogDecryptErrorDetail(typed)
	if !strings.Contains(typedDetail, string(protocolBackendIncompatible)) ||
		!strings.Contains(typedDetail, "authentication failed") {
		t.Fatalf("typed detail = %q", typedDetail)
	}

	arbitrary := errors.New("SENTINEL-DYNAMIC-CATALOG-ERROR")
	arbitraryDetail := catalogDecryptErrorDetail(arbitrary)
	if strings.Contains(arbitraryDetail, arbitrary.Error()) || arbitraryDetail == "" {
		t.Fatalf("arbitrary detail = %q", arbitraryDetail)
	}

	wrappedCancellation := fmt.Errorf("SENTINEL-CATALOG-CANCELLATION: %w", context.Canceled)
	cancellationDetail := catalogDecryptErrorDetail(wrappedCancellation)
	if cancellationDetail != context.Canceled.Error() {
		t.Fatalf("wrapped cancellation detail = %q, want %q", cancellationDetail, context.Canceled)
	}
}

func TestLoadCatalogDynamicCacheLoggingIsValueFree(t *testing.T) {
	const uid = "SENTINEL-DYNAMIC-CATALOG-UID"
	const blob = "SENTINEL-DYNAMIC-CATALOG-BLOB"
	const plain = "SENTINEL-DYNAMIC-CATALOG-PLAINTEXT"

	t.Run("decrypt failure", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		cachePath := writeDynamicCatalogCache(t, authFile, uid, blob)
		decryptErr := errors.New("SENTINEL-DYNAMIC-CATALOG-ERROR " + uid + " " + blob + " " + plain + " " + cachePath)
		decryptor := &fakeModelCacheDecryptor{err: decryptErr}
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("decrypt failure fallback lacks builtin auto model")
		}
		output := logs.String()
		if !strings.Contains(output, "catalog decrypt failed") {
			t.Fatal("decrypt failure log lacks safe category")
		}
		assertCatalogLogOmits(t, output, uid, blob, plain, cachePath, "SENTINEL-DYNAMIC-CATALOG-ERROR")
	})

	t.Run("typed decrypt failure includes safe detail", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		cachePath := writeDynamicCatalogCache(t, authFile, uid, blob)
		decryptor := &fakeModelCacheDecryptor{err: newProtocolError(
			protocolBackendIncompatible,
			"model cache data is incompatible",
			errors.New("model cache envelope authentication failed"),
		)}
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("typed decrypt failure fallback lacks builtin auto model")
		}
		output := logs.String()
		if !strings.Contains(output, "kind=backend-incompatible") || !strings.Contains(output, "authentication failed") {
			t.Fatalf("typed decrypt failure log lacks safe detail: %q", output)
		}
		assertCatalogLogOmits(t, output, uid, blob, cachePath)
	})

	t.Run("missing cache is silent", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), nativeModelCacheDecryptor{}, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("missing cache fallback lacks builtin auto model")
		}
		if output := logs.String(); output != "" {
			t.Fatalf("missing cache log = %q, want silence", output)
		}
	})

	t.Run("nil decryptor", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		cachePath := writeDynamicCatalogCache(t, authFile, uid, blob)
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), nil, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("nil decryptor fallback lacks builtin auto model")
		}
		output := logs.String()
		if !strings.Contains(output, "catalog decrypt failed") {
			t.Fatal("nil decryptor log lacks safe category")
		}
		assertCatalogLogOmits(t, output, uid, blob, cachePath)
	})
}

func writeDynamicCatalogCache(t *testing.T, authFile, uid, blob string) string {
	t.Helper()
	cachePath := filepath.Clean(filepath.Join(filepath.Dir(authFile), "..", ".models", uid, "catalog-v6"))
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal("create dynamic catalog directory failed")
	}
	if err := os.WriteFile(cachePath, []byte(blob), 0o600); err != nil {
		t.Fatalf("write dynamic catalog blob length %d failed", len(blob))
	}
	return cachePath
}

func mutateCatalogQMCBlob(t *testing.T, blob string, index int) string {
	t.Helper()
	envelope, err := decodeStrictStdBase64(blob)
	if err != nil {
		t.Fatalf("decode mutation setup blob length %d: strict decode failed", len(blob))
	}
	if index < 0 {
		index = len(envelope) - 1
	}
	changed := append([]byte(nil), envelope...)
	changed[index] ^= 1
	return base64.StdEncoding.EncodeToString(changed)
}

func captureCatalogLogs() (*strings.Builder, func(string, ...any)) {
	var logs strings.Builder
	return &logs, func(format string, args ...any) {
		_, _ = fmt.Fprintf(&logs, format, args...)
		logs.WriteByte('\n')
	}
}

func assertCatalogLogOmits(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && strings.Contains(output, value) {
			t.Fatal("dynamic catalog log contains a forbidden content marker")
		}
	}
}

func TestQoderProtocolVersion(t *testing.T) {
	if qoderProtocolVersion != "1.1.34" {
		t.Fatalf("qoderProtocolVersion = %q, want %q", qoderProtocolVersion, "1.1.34")
	}
	if qoderUserAgent() != "qoder/1.1.34" {
		t.Fatalf("qoderUserAgent() = %q, want %q", qoderUserAgent(), "qoder/1.1.34")
	}
}

func TestBusinessInfoUsesQoderProtocolVersion(t *testing.T) {
	got := businessInfo([]upMessage{{Role: "user", Content: "synthetic"}})
	if got["version"] != qoderProtocolVersion {
		t.Fatalf("businessInfo version = %v, want %q", got["version"], qoderProtocolVersion)
	}
}

func TestBuiltinCatalogContainsApprovedStableModels(t *testing.T) {
	models := make(map[string]*modelConfig)
	for _, model := range builtinCatalog() {
		models[model.Key] = model
	}

	cmodel, ok := models["cmodel"]
	if !ok {
		t.Fatal("builtinCatalog is missing cmodel")
	}
	if cmodel.DisplayName != "Cantus" {
		t.Fatalf("cmodel DisplayName = %q, want Cantus", cmodel.DisplayName)
	}

	gmodel, ok := models["gmodel"]
	if !ok {
		t.Fatal("builtinCatalog is missing gmodel")
	}
	if gmodel.DisplayName != "GLM-5.3" {
		t.Fatalf("gmodel DisplayName = %q, want GLM-5.3", gmodel.DisplayName)
	}
	if !gmodel.IsReasoning {
		t.Fatal("gmodel IsReasoning = false, want true")
	}
	if !gmodel.IsVL {
		t.Fatal("gmodel IsVL = false, want true")
	}
	if gmodel.MaxInputTokens != 1_000_000 {
		t.Fatalf("gmodel MaxInputTokens = %d, want 1000000", gmodel.MaxInputTokens)
	}

	if _, ok := models["qwen3.8-v116-dogfood-crit"]; ok {
		t.Fatal("builtinCatalog contains qwen3.8-v116-dogfood-crit")
	}
}
