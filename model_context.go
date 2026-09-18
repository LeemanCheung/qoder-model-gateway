package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// parseContextPreferences accepts the non-secret per-model selection exported
// by the local Qoder Desktop database. Unknown model keys are harmless and are
// ignored later, but malformed values must not silently change a request.
func parseContextPreferences(raw string) (map[string]int, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]int{}, nil
	}
	var values map[string]int
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("invalid context preferences JSON: %w", err)
	}
	for key, window := range values {
		if strings.TrimSpace(key) == "" || window <= 0 || window > 2_000_000 {
			return nil, fmt.Errorf("invalid context preference")
		}
	}
	return values, nil
}

func (mc *modelConfig) supportedContextWindows() []int {
	if mc == nil {
		return nil
	}
	seen := map[int]bool{}
	for _, tier := range mc.ContextConfig {
		if tier.TokenCount > 0 {
			seen[tier.TokenCount] = true
		}
	}
	values := make([]int, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Ints(values)
	return values
}

func (mc *modelConfig) maximumContextWindow() int {
	maximum := 0
	for _, value := range mc.supportedContextWindows() {
		if value > maximum {
			maximum = value
		}
	}
	if mc != nil && mc.MaxInputTokens > maximum {
		maximum = mc.MaxInputTokens
	}
	return maximum
}

func (mc *modelConfig) supportsContextWindow(window int) bool {
	if mc == nil || window <= 0 {
		return false
	}
	values := mc.supportedContextWindows()
	if len(values) == 0 {
		return mc.MaxInputTokens > 0 && window <= mc.MaxInputTokens
	}
	index := sort.SearchInts(values, window)
	return index < len(values) && values[index] == window
}

func (mc *modelConfig) catalogDefaultContextWindow() int {
	if mc == nil {
		return 0
	}
	defaultWindow := 0
	for _, tier := range mc.ContextConfig {
		if tier.IsDefault && tier.TokenCount > 0 && (defaultWindow == 0 || tier.TokenCount < defaultWindow) {
			defaultWindow = tier.TokenCount
		}
	}
	if defaultWindow > 0 {
		return defaultWindow
	}
	if mc.MaxInputTokens > 0 {
		return mc.MaxInputTokens
	}
	values := mc.supportedContextWindows()
	if len(values) > 0 {
		return values[0]
	}
	return 0
}

func (mc *modelConfig) contextWindow() int {
	if mc != nil && mc.EffectiveContextWindow > 0 {
		return mc.EffectiveContextWindow
	}
	return mc.catalogDefaultContextWindow()
}

func applyContextPreferences(catalog []*modelConfig, preferences map[string]int) {
	for _, mc := range catalog {
		if mc == nil {
			continue
		}
		selected := 0
		if preferred := preferences[mc.Key]; mc.supportsContextWindow(preferred) {
			selected = preferred
		}
		if selected == 0 {
			selected = mc.catalogDefaultContextWindow()
		}
		mc.EffectiveContextWindow = selected
	}
}
