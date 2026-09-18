package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeLocalExactCatalogue(t *testing.T) {
	t.Setenv("QODER2API_NATIVE_LOCKDOWN", "1")
	file := filepath.Join(t.TempDir(), "models.json")
	_ = os.WriteFile(file, []byte(`{"chat":[{"key":"kmodel_latest","display_name":"Kimi-K3","enable":true},{"key":"disabled","display_name":"Unavailable","enable":false}]}`), 0600)
	catalog := loadCatalog(context.Background(), nil, "", "", file, nil)
	if len(catalog) != 1 {
		t.Fatalf("catalogue should contain one enabled account model, got %d", len(catalog))
	}
	resolver := newModelResolver(catalog, nil, "auto", "ultimate")
	if resolver.resolve("qoder-anthropic/Kimi-K3") == nil {
		t.Fatal("explicit alias did not resolve")
	}
	if resolver.resolve("Missing") != nil {
		t.Fatal("unknown model silently fell back")
	}
	if resolver.resolve("Kimi-K3[1m]") != nil {
		t.Fatal("context suffix switched model")
	}
	if len(loadCatalog(context.Background(), nil, "", "", file+".missing", nil)) != 0 {
		t.Fatal("missing catalogue used invented defaults")
	}
}
func TestNativeLocalSecurityBoundary(t *testing.T) {
	t.Setenv("QODER2API_NATIVE_LOCKDOWN", "1")
	valid := appConfig{addr: "127.0.0.1:18789", sk: strings.Repeat("s", 32), readOnlyAuth: true, inferEndpoint: "https://gateway.qoder.com.cn", openapiEndpoint: "https://openapi.qoder.com.cn", webEndpoint: "https://qoder.cn"}
	if err := validateLocalNativeConfig(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*appConfig){func(c *appConfig) { c.addr = ":18789" }, func(c *appConfig) { c.sk = "" }, func(c *appConfig) { c.readOnlyAuth = false }, func(c *appConfig) { c.inferEndpoint = "https://example.invalid" }, func(c *appConfig) { c.dumpDir = "capture" }} {
		invalid := valid
		mutate(&invalid)
		if validateLocalNativeConfig(invalid) == nil {
			t.Fatal("unsafe native configuration accepted")
		}
	}
	handler := localNativeGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, host := range []string{"evil.example:18789", "localhost.evil:18789"} {
		request := httptest.NewRequest("GET", "http://"+host+"/health", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatal("non-loopback host accepted")
		}
	}
	if strings.Contains(nativePublicError("secret request details"), "secret") {
		t.Fatal("raw upstream error exposed")
	}
}
