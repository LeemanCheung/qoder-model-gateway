package main

import (
	"bytes"
	"testing"
)

func TestNativeBodyCodecGoldenAndRawRoundTrips(t *testing.T) {
	codec := nativeBodyCodec{}
	tests := []struct {
		name      string
		raw       []byte
		golden    []byte
		hasGolden bool
	}{
		{name: "empty", raw: nil, golden: []byte{}, hasGolden: true},
		{name: "empty object", raw: []byte(`{}`), golden: []byte(`$kwm`), hasGolden: true},
		{name: "unicode", raw: []byte(`{"text":"合成🙂"}`)},
		{name: "binary", raw: []byte{0x00, 0x01, 0xfe, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := codec.Encode(tt.raw)
			if err != nil {
				t.Fatalf("case %s raw length %d: Encode returned error kind %q", tt.name, len(tt.raw), protocolErrorKindOf(err))
			}
			if tt.hasGolden && !bytes.Equal(encoded, tt.golden) {
				t.Fatalf("case %s raw length %d: encoded length = %d, want %d", tt.name, len(tt.raw), len(encoded), len(tt.golden))
			}
			decoded, err := codec.Decode(encoded)
			if err != nil {
				t.Fatalf("case %s encoded length %d: Decode returned error kind %q", tt.name, len(encoded), protocolErrorKindOf(err))
			}
			if !bytes.Equal(decoded, tt.raw) {
				t.Fatalf("case %s: round-trip lengths decoded=%d raw=%d", tt.name, len(decoded), len(tt.raw))
			}
		})
	}
}

func TestNativeBodyCodecPreservesCallerBytesExactly(t *testing.T) {
	codec := nativeBodyCodec{}
	compact := []byte(`{}`)
	spaced := []byte(`{ }`)

	compactEncoded, err := codec.Encode(compact)
	if err != nil {
		t.Fatalf("compact raw length %d: Encode returned error kind %q", len(compact), protocolErrorKindOf(err))
	}
	spacedEncoded, err := codec.Encode(spaced)
	if err != nil {
		t.Fatalf("spaced raw length %d: Encode returned error kind %q", len(spaced), protocolErrorKindOf(err))
	}
	if bytes.Equal(compactEncoded, spacedEncoded) {
		t.Fatalf("distinct raw lengths %d and %d produced identical encodings of length %d", len(compact), len(spaced), len(compactEncoded))
	}
	decoded, err := codec.Decode(spacedEncoded)
	if err != nil {
		t.Fatalf("spaced encoded length %d: Decode returned error kind %q", len(spacedEncoded), protocolErrorKindOf(err))
	}
	if !bytes.Equal(decoded, spaced) {
		t.Fatalf("spaced round-trip lengths decoded=%d raw=%d", len(decoded), len(spaced))
	}
}

func TestNativeBodyCodecMatchesPinnedInferFixture(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "infer-user.json")
	var input inferFixtureInput
	var expected inferFixtureExpected
	decodeExactJSON(t, fixture.Input, &input)
	decodeExactJSON(t, fixture.Expected, &expected)

	got, err := (nativeBodyCodec{}).Encode([]byte(input.BodyRaw))
	if err != nil {
		t.Fatalf("fixture raw length %d: Encode returned error kind %q", len(input.BodyRaw), protocolErrorKindOf(err))
	}
	if !bytes.Equal(got, expected.BodyBytes) {
		t.Fatalf("fixture body mismatch: native length %d, pinned length %d", len(got), len(expected.BodyBytes))
	}
}

func TestNativeBodyCodecRejectsMalformedInputWithoutPanic(t *testing.T) {
	codec := nativeBodyCodec{}
	tests := []struct {
		name    string
		encoded []byte
	}{
		{name: "length 1", encoded: []byte("a")},
		{name: "length 2", encoded: []byte("ab")},
		{name: "length 3", encoded: []byte("abc")},
		{name: "invalid alphabet", encoded: []byte("????")},
		{name: "misplaced padding", encoded: []byte("_$__")},
		{name: "missing padding", encoded: []byte("kwm")},
		{name: "extra padding", encoded: []byte("$kwm$")},
		{name: "carriage return", encoded: []byte("$k\rwm")},
		{name: "line feed", encoded: []byte("$k\nwm")},
		{name: "trailing garbage", encoded: []byte("$kwm?")},
		{name: "non-canonical trailing bits", encoded: []byte("$d$_")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Fatalf("case %s encoded length %d panicked", tt.name, len(tt.encoded))
				}
			}()
			decoded, err := codec.Decode(tt.encoded)
			if err == nil {
				t.Fatalf("case %s encoded length %d: Decode succeeded with decoded length %d", tt.name, len(tt.encoded), len(decoded))
			}
			if len(decoded) != 0 {
				t.Fatalf("case %s encoded length %d: malformed decode returned %d bytes", tt.name, len(tt.encoded), len(decoded))
			}
			if got := protocolErrorKindOf(err); got != protocolInvalidInput {
				t.Fatalf("case %s encoded length %d: error kind = %q, want %q", tt.name, len(tt.encoded), got, protocolInvalidInput)
			}
			if got, want := err.Error(), "protocol body is invalid"; got != want {
				t.Fatalf("case %s encoded length %d: public error length = %d, want %d", tt.name, len(tt.encoded), len(got), len(want))
			}
		})
	}
}

func TestNativeBodyCodecDecodedCapacityUsesEncodedLengthBound(t *testing.T) {
	codec := nativeBodyCodec{}
	for _, rawLen := range []int{0, 1, 2, 3, 4, 255} {
		rawLen := rawLen
		t.Run(bodyLengthCaseName(rawLen), func(t *testing.T) {
			raw := bytes.Repeat([]byte{0x5a}, rawLen)
			encoded, err := codec.Encode(raw)
			if err != nil {
				t.Fatalf("raw length %d: Encode returned error kind %q", rawLen, protocolErrorKindOf(err))
			}
			decoded, err := codec.Decode(encoded)
			if err != nil {
				t.Fatalf("encoded length %d: Decode returned error kind %q", len(encoded), protocolErrorKindOf(err))
			}
			bound := qoderBodyBase64.DecodedLen(len(encoded))
			if cap(decoded) > bound {
				t.Fatalf("encoded length %d: decoded capacity %d exceeds bound %d", len(encoded), cap(decoded), bound)
			}
			if len(decoded) != rawLen {
				t.Fatalf("raw length %d: decoded length %d", rawLen, len(decoded))
			}
		})
	}
}

func TestNativeBodyCodecDoesNotMutateInputs(t *testing.T) {
	codec := nativeBodyCodec{}
	raw := []byte(`{"synthetic":"value"}`)
	rawBefore := append([]byte(nil), raw...)
	encoded, err := codec.Encode(raw)
	if err != nil {
		t.Fatalf("raw length %d: Encode returned error kind %q", len(raw), protocolErrorKindOf(err))
	}
	if !bytes.Equal(raw, rawBefore) {
		t.Fatalf("Encode mutated raw input of length %d", len(raw))
	}
	encodedBefore := append([]byte(nil), encoded...)
	if _, err := codec.Decode(encoded); err != nil {
		t.Fatalf("encoded length %d: Decode returned error kind %q", len(encoded), protocolErrorKindOf(err))
	}
	if !bytes.Equal(encoded, encodedBefore) {
		t.Fatalf("Decode mutated encoded input of length %d", len(encoded))
	}
}

func TestNativeBodyCodecSwapOuterThirdsIsSelfInverseAndNonMutating(t *testing.T) {
	for length := 0; length <= 10; length++ {
		src := make([]byte, length)
		for i := range src {
			src[i] = byte(i + 1)
		}
		before := append([]byte(nil), src...)
		swapped := swapOuterThirds(src)
		if !bytes.Equal(src, before) {
			t.Fatalf("source length %d mutated during swap", length)
		}
		if len(swapped) != len(src) {
			t.Fatalf("source length %d produced swapped length %d", length, len(swapped))
		}
		restored := swapOuterThirds(swapped)
		if !bytes.Equal(restored, src) {
			t.Fatalf("source length %d restored length %d differs", length, len(restored))
		}
	}
}

func bodyLengthCaseName(length int) string {
	const digits = "0123456789"
	if length == 0 {
		return "length-0"
	}
	var reversed [20]byte
	index := len(reversed)
	for length > 0 {
		index--
		reversed[index] = digits[length%10]
		length /= 10
	}
	return "length-" + string(reversed[index:])
}
