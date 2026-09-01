package main

import (
	"encoding/hex"
	"testing"
)

func TestReverseMaskUUIDFormatsRuntimeASCIIKeyWithoutMutatingInput(t *testing.T) {
	rawBytes, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal("decode synthetic UUID bytes")
	}
	var raw [16]byte
	copy(raw[:], rawBytes)
	before := raw

	got := reverseMaskUUID(raw)
	wantBytes, err := hex.DecodeString("100f0e0d0c0b4a098807060504030201")
	if err != nil {
		t.Fatal("decode expected synthetic UUID bytes")
	}
	var want [16]byte
	copy(want[:], wantBytes)
	if got != want {
		t.Fatal("reversed/masked UUID bytes differ from the deterministic vector")
	}
	if raw != before {
		t.Fatal("reverseMaskUUID mutated its input")
	}
	if formatted := formatLowerUUID(got); formatted != "100f0e0d-0c0b-4a09-8807-060504030201" {
		t.Fatalf("formatted UUID length %d differs from deterministic lowercase form", len(formatted))
	}
	if key := runtimeASCIIKey(got); key != "100f0e0d0c0b4a09" {
		t.Fatalf("runtime ASCII key length %d differs from deterministic value", len(key))
	}
}
