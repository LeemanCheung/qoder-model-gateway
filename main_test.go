package main

import "testing"

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
