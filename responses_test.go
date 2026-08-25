package main

import (
	"encoding/json"
	"testing"
)

func TestRespToUpstreamPreservesInputImage(t *testing.T) {
	input := json.RawMessage(`[
		{
			"type": "message",
			"role": "user",
			"content": [
				{"type": "input_text", "text": "describe this"},
				{"type": "input_image", "image_url": "data:image/png;base64,abc"}
			]
		}
	]`)

	_, msgs, err := respToUpstream("", input)
	if err != nil {
		t.Fatalf("respToUpstream returned error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if len(msgs[0].Contents) != 2 {
		t.Fatalf("got %d upstream content parts, want 2", len(msgs[0].Contents))
	}
	if got := msgs[0].Contents[0].Text; got != "describe this" {
		t.Fatalf("text content = %q, want %q", got, "describe this")
	}
	if got := msgs[0].Contents[1].ImageURL.URL; got != "data:image/png;base64,abc" {
		t.Fatalf("image URL = %q, want data URL", got)
	}
}

func TestRespToUpstreamAcceptsCompactRoleContentItem(t *testing.T) {
	// Hermes sends Responses input in this compact form: it has role/content
	// but omits the optional type:"message" discriminator.
	input := json.RawMessage(`[
		{"role": "user", "content": "只回复四个字：测试成功"}
	]`)

	_, msgs, err := respToUpstream("", input)
	if err != nil {
		t.Fatalf("respToUpstream returned error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if got := msgs[0].Role; got != "user" {
		t.Fatalf("role = %q, want user", got)
	}
	if got := msgs[0].Content; got != "只回复四个字：测试成功" {
		t.Fatalf("content = %q, want compact user text", got)
	}
	if len(msgs[0].Contents) != 1 || msgs[0].Contents[0].Text != "只回复四个字：测试成功" {
		t.Fatalf("upstream contents = %#v, want compact user text", msgs[0].Contents)
	}
}

func TestRespToUpstreamAcceptsCompactContentParts(t *testing.T) {
	input := json.RawMessage(`[
		{
			"role": "user",
			"content": [
				{"type": "input_text", "text": "describe this"},
				{"type": "input_image", "image_url": "data:image/png;base64,abc"}
			]
		}
	]`)

	_, msgs, err := respToUpstream("", input)
	if err != nil {
		t.Fatalf("respToUpstream returned error: %v", err)
	}
	if len(msgs) != 1 || len(msgs[0].Contents) != 2 {
		t.Fatalf("upstream messages = %#v, want compact text and image parts", msgs)
	}
	if got := msgs[0].Contents[1].ImageURL.URL; got != "data:image/png;base64,abc" {
		t.Fatalf("image URL = %q, want data URL", got)
	}
}

func TestRespToUpstreamIgnoresInvalidCompactItems(t *testing.T) {
	tests := []struct {
		name string
		item string
	}{
		{name: "missing role", item: `{"content":"hello"}`},
		{name: "null content", item: `{"role":"user","content":null}`},
		{name: "invalid content shape", item: `{"role":"user","content":{"text":"hello"}}`},
		{name: "empty content parts", item: `{"role":"user","content":[]}`},
		{name: "null content part", item: `{"role":"user","content":[null]}`},
		{name: "missing content part type", item: `{"role":"user","content":[{"text":"hello"}]}`},
		{name: "unknown content part type", item: `{"role":"user","content":[{"type":"unknown","text":"hello"}]}`},
		{name: "missing text", item: `{"role":"user","content":[{"type":"input_text"}]}`},
		{name: "missing image URL", item: `{"role":"user","content":[{"type":"input_image"}]}`},
		{name: "unsupported role", item: `{"role":"tool","content":"result","call_id":"call_1"}`},
		{name: "tool-like item", item: `{"call_id":"call_1","output":"result"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := json.RawMessage("[" + tt.item + "]")
			_, msgs, err := respToUpstream("", input)
			if err != nil {
				t.Fatalf("respToUpstream returned error: %v", err)
			}
			if len(msgs) != 0 {
				t.Fatalf("upstream messages = %#v, want invalid compact item ignored", msgs)
			}
		})
	}
}
