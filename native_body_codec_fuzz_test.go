package main

import (
	"bytes"
	"testing"
)

func FuzzNativeBodyCodec(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"text":"合成🙂"}`))
	f.Add([]byte{0, 1, 2, 255})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		codec := nativeBodyCodec{}
		encoded, err := codec.Encode(raw)
		if err != nil {
			t.Fatalf("raw length %d: Encode returned error kind %q", len(raw), protocolErrorKindOf(err))
		}
		decoded, err := codec.Decode(encoded)
		if err != nil {
			t.Fatalf("encoded length %d: Decode returned error kind %q", len(encoded), protocolErrorKindOf(err))
		}
		if !bytes.Equal(decoded, raw) {
			t.Fatalf("round-trip length mismatch: raw=%d decoded=%d encoded=%d", len(raw), len(decoded), len(encoded))
		}
		bound := qoderBodyBase64.DecodedLen(len(encoded))
		if cap(decoded) > bound {
			t.Fatalf("encoded length %d: decoded capacity %d exceeds bound %d", len(encoded), cap(decoded), bound)
		}
	})
}
