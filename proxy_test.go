package main

import "testing"

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
