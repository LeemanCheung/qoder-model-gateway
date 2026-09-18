package main

import (
	"encoding/json"
	"testing"
)

func testContextModel() *modelConfig {
	return &modelConfig{
		Key: "qmodel", DisplayName: "Qoder Model", Enable: true, MaxInputTokens: 180000,
		ContextConfig: map[string]contextTier{
			"200K": {TokenCount: 200000, IsDefault: true},
			"400K": {TokenCount: 400000},
			"1M":   {TokenCount: 1000000},
		},
	}
}

func TestModelContextUsesDesktopPreferenceOnlyWhenSupported(t *testing.T) {
	model := testContextModel()
	applyContextPreferences([]*modelConfig{model}, map[string]int{"qmodel": 1000000})
	if model.contextWindow() != 1000000 {
		t.Fatalf("selected context = %d, want 1000000", model.contextWindow())
	}
	if model.MaxInputTokens != 180000 {
		t.Fatalf("model descriptor max_input_tokens changed to %d", model.MaxInputTokens)
	}
	applyContextPreferences([]*modelConfig{model}, map[string]int{"qmodel": 300000})
	if model.contextWindow() != 200000 {
		t.Fatalf("unsupported desktop preference selected context = %d, want catalog default 200000", model.contextWindow())
	}
	if got := model.maximumContextWindow(); got != 1000000 {
		t.Fatalf("maximum context = %d, want 1000000", got)
	}
}

func TestModelContextFallsBackToCatalogDefaultThenDescriptor(t *testing.T) {
	model := testContextModel()
	applyContextPreferences([]*modelConfig{model}, nil)
	if model.contextWindow() != 200000 {
		t.Fatalf("catalog default = %d, want 200000", model.contextWindow())
	}
	fallback := &modelConfig{Key: "auto", MaxInputTokens: 180000}
	applyContextPreferences([]*modelConfig{fallback}, nil)
	if fallback.contextWindow() != 180000 {
		t.Fatalf("descriptor fallback = %d, want 180000", fallback.contextWindow())
	}
}

func TestModelContextFlowsToUpstreamParameters(t *testing.T) {
	model := testContextModel()
	applyContextPreferences([]*modelConfig{model}, map[string]int{"qmodel": 400000})
	request := &anthropicRequest{MaxTokens: 12, Messages: []anthropicMsg{{Role: "user", Content: json.RawMessage(`"test"`)}}}
	body, err := buildUpstreamBody(request, model, "synthetic-session", "synthetic-request")
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Parameters map[string]any `json:"parameters"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := int(decoded.Parameters["context_length"].(float64)); got != 400000 {
		t.Fatalf("upstream context_length = %d, want 400000", got)
	}
}

func TestParseContextPreferencesRejectsUnsafeInput(t *testing.T) {
	preferences, err := parseContextPreferences(`{"gmodel":1000000}`)
	if err != nil || preferences["gmodel"] != 1000000 {
		t.Fatalf("valid preferences = %#v, %v", preferences, err)
	}
	for _, raw := range []string{`[]`, `{"":200000}`, `{"gmodel":0}`, `{"gmodel":2000001}`} {
		if _, err := parseContextPreferences(raw); err == nil {
			t.Fatalf("invalid preferences %s accepted", raw)
		}
	}
}
