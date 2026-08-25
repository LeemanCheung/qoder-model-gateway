package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func resolverTestCatalog() []*modelConfig {
	return []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180000},
		{Key: "ultimate", DisplayName: "Ultimate", MaxInputTokens: 1000000},
		{Key: "efficient", DisplayName: "Efficient", MaxInputTokens: 180000},
		{Key: "qmodel_38max", DisplayName: "Qwen3.8-Max", MaxInputTokens: 1000000},
	}
}

func TestModelResolverAcceptsInternalKeysAndDisplayNames(t *testing.T) {
	r := newModelResolver(resolverTestCatalog(), nil, "", "")

	for _, identifier := range []string{"qmodel_38max", "Qwen3.8-Max"} {
		if got := r.resolve(identifier).Key; got != "qmodel_38max" {
			t.Errorf("resolve(%q).Key = %q, want qmodel_38max", identifier, got)
		}
	}
}

func TestModelResolverPreservesMappingPrecedenceAndAcceptsNameTargets(t *testing.T) {
	r := newModelResolver(resolverTestCatalog(), map[string]string{
		"Qwen3.8-Max": "efficient",
		"mapped":      "Qwen3.8-Max",
		"synthetic":   "unknown-target",
		"*":           "auto",
	}, "", "")

	if got := r.resolve("Qwen3.8-Max").Key; got != "efficient" {
		t.Fatalf("exact mapping over display name resolved to %q, want efficient", got)
	}
	if got := r.resolve("mapped").Key; got != "qmodel_38max" {
		t.Fatalf("display-name mapping target resolved to %q, want qmodel_38max", got)
	}
	if got := r.resolve("synthetic"); got.Key != "unknown-target" || got.Source != "system" {
		t.Fatalf("unknown mapping target resolved to %+v, want synthetic unknown-target", got)
	}

	wildcard := newModelResolver(resolverTestCatalog(), map[string]string{"*": "efficient"}, "", "")
	if got := wildcard.resolve("qmodel_38max").Key; got != "efficient" {
		t.Fatalf("wildcard mapping over internal key resolved to %q, want efficient", got)
	}
}

func TestModelResolverDisplayNameSupportsOneMSuffix(t *testing.T) {
	r := newModelResolver(resolverTestCatalog(), nil, "Auto", "Ultimate")

	if got := r.resolve("Efficient[1m]").Key; got != "ultimate" {
		t.Fatalf("Efficient[1m] resolved to %q, want ultimate", got)
	}
	if got := r.resolve("Qwen3.8-Max[1m]").Key; got != "qmodel_38max" {
		t.Fatalf("Qwen3.8-Max[1m] resolved to %q, want qmodel_38max", got)
	}
	if got := r.resolve("unknown").Key; got != "auto" {
		t.Fatalf("display-name default resolved to %q, want auto", got)
	}
}

func TestModelResolverPublicIDAvoidsReservedOneMSuffix(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180_000},
		{Key: "ultimate", DisplayName: "Ultimate", MaxInputTokens: 1_000_000},
		{Key: "special", DisplayName: "Special[1m]", MaxInputTokens: 180_000},
	}
	r := newModelResolver(catalog, nil, "auto", "ultimate")

	publicID := r.publicID(r.byKey["special"])
	if publicID != "special" {
		t.Fatalf("publicID(special) = %q, want special", publicID)
	}
	if got := r.resolve(publicID).Key; got != "special" {
		t.Errorf("resolve(publicID(special)).Key = %q, want special", got)
	}
}

func TestModelResolverUsesOnlyUnambiguousDisplayNames(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180000},
		{Key: "blank", DisplayName: "   ", MaxInputTokens: 180000},
		{Key: "shared_a", DisplayName: "Shared", MaxInputTokens: 180000},
		{Key: "shared_b", DisplayName: "Shared", MaxInputTokens: 180000},
		{Key: "Alias", DisplayName: "Internal Alias", MaxInputTokens: 180000},
		{Key: "conflict", DisplayName: "Alias", MaxInputTokens: 180000},
		{Key: "qmodel_38max", DisplayName: "Qwen3.8-Max", MaxInputTokens: 1000000},
	}
	r := newModelResolver(catalog, nil, "auto", "ultimate")

	if got := r.resolve("Shared").Key; got != "auto" {
		t.Errorf("ambiguous Shared resolved to %q, want default auto", got)
	}
	if got := r.resolve("Alias").Key; got != "Alias" {
		t.Errorf("internal key Alias resolved to %q, want Alias", got)
	}

	for _, key := range []string{"blank", "shared_a", "shared_b", "conflict"} {
		if got := r.publicID(r.byKey[key]); got != key {
			t.Errorf("publicID(%q) = %q, want key fallback", key, got)
		}
	}
	if got := r.publicID(r.byKey["qmodel_38max"]); got != "Qwen3.8-Max" {
		t.Errorf("publicID(qmodel_38max) = %q, want Qwen3.8-Max", got)
	}
	if got := r.publicID(nil); got != "" {
		t.Errorf("publicID(nil) = %q, want empty string", got)
	}
}

type modelListResponse struct {
	Object string `json:"object"`
	Data   []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		QoderKey    string `json:"qoder_key"`
		MaxTokens   int    `json:"max_tokens"`
	} `json:"data"`
}

func TestHandleModelsReturnsFriendlyStableIDs(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "qmodel_38max", DisplayName: "Qwen3.8-Max", MaxInputTokens: 1_000_000},
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180_000},
		{Key: "gmodel", DisplayName: "GLM-5.3", MaxInputTokens: 200_000},
	}
	s := &server{models: newModelResolver(catalog, nil, "", "")}
	recorder := httptest.NewRecorder()

	s.handleModels(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response modelListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Object != "list" {
		t.Errorf("object = %q, want list", response.Object)
	}
	var ids []string
	for _, item := range response.Data {
		ids = append(ids, item.ID)
		if item.QoderKey == "" {
			t.Errorf("model %q has empty qoder_key", item.ID)
		}
	}
	if want := []string{"Auto", "GLM-5.3", "Qwen3.8-Max"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	qwen := response.Data[2]
	if qwen.Name != "Qwen3.8-Max" || qwen.DisplayName != "Qwen3.8-Max" {
		t.Errorf("Qwen names = (%q, %q), want Qwen3.8-Max", qwen.Name, qwen.DisplayName)
	}
	if qwen.QoderKey != "qmodel_38max" {
		t.Errorf("Qwen qoder_key = %q, want qmodel_38max", qwen.QoderKey)
	}
	if qwen.MaxTokens != 1_000_000 {
		t.Errorf("Qwen max_tokens = %d, want 1000000", qwen.MaxTokens)
	}
}

func TestHandleModelsFallsBackToKeysForAmbiguousOrEmptyNames(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180_000},
		{Key: "alpha", DisplayName: "Shared", MaxInputTokens: 180_000},
		{Key: "beta", DisplayName: "Shared", MaxInputTokens: 180_000},
		{Key: "raw", DisplayName: "   ", MaxInputTokens: 180_000},
		{Key: "special", DisplayName: "Special[1m]", MaxInputTokens: 180_000},
	}
	s := &server{models: newModelResolver(catalog, nil, "", "")}
	recorder := httptest.NewRecorder()

	s.handleModels(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response modelListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var ids []string
	for _, item := range response.Data {
		ids = append(ids, item.ID)
		if item.QoderKey == "" {
			t.Errorf("model %q has empty qoder_key", item.ID)
		}
	}
	if want := []string{"Auto", "alpha", "beta", "raw", "special"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	if response.Data[1].ID != "alpha" || response.Data[2].ID != "beta" {
		t.Errorf("ambiguous IDs = (%q, %q), want (alpha, beta)", response.Data[1].ID, response.Data[2].ID)
	}
	raw := response.Data[3]
	if raw.Name != "raw" || raw.DisplayName != "raw" {
		t.Errorf("raw names = (%q, %q), want (raw, raw)", raw.Name, raw.DisplayName)
	}
	special := response.Data[4]
	if special.ID != "special" || special.QoderKey != "special" {
		t.Errorf("special identifiers = (%q, %q), want (special, special)", special.ID, special.QoderKey)
	}
	if special.Name != "Special[1m]" || special.DisplayName != "Special[1m]" {
		t.Errorf("special names = (%q, %q), want (Special[1m], Special[1m])", special.Name, special.DisplayName)
	}
}
