package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

func FuzzCredentialEnvelope(f *testing.F) {
	encoded, err := os.ReadFile(filepath.Join(protocolFixtureDir(), "credential.json"))
	if err != nil {
		f.Fatalf("read official credential fixture: %v", err)
	}
	var fixture protocolFixture
	if err := decodeStrictJSON(encoded, &fixture); err != nil {
		f.Fatal("decode official credential fixture")
	}
	var expected credentialFixtureExpected
	if err := decodeStrictJSON(fixture.Expected, &expected); err != nil {
		f.Fatal("decode official credential fixture expected value")
	}
	officialBytes, err := decodeStrictStdBase64(expected.Encrypted)
	if err != nil || len(officialBytes) < 32 {
		f.Fatalf("official credential ciphertext length %d is unsuitable for fuzz seeds", len(officialBytes))
	}
	malformedPaddingBytes := append([]byte(nil), officialBytes...)
	malformedPaddingBytes[len(malformedPaddingBytes)-17] ^= 1
	truncatedBytes := append([]byte(nil), officialBytes[:len(officialBytes)-1]...)

	f.Add(expected.Encrypted)
	f.Add("")
	f.Add(base64.StdEncoding.EncodeToString(malformedPaddingBytes))
	f.Add("-_8=")
	f.Add(base64.StdEncoding.EncodeToString(truncatedBytes))

	const maxBlobLen = 1 << 20
	const key = protocolFixtureMachineKey
	codec := nativeCredentialCodec{}
	f.Fuzz(func(t *testing.T, blob string) {
		if len(blob) > maxBlobLen {
			return
		}
		plain, err := codec.Decrypt(context.Background(), blob, key)
		if err != nil {
			if protocolErrorKindOf(err) != protocolBackendIncompatible || err.Error() != "credential data is incompatible" {
				t.Fatalf("blob length %d: decrypt returned unsafe error category", len(blob))
			}
			return
		}
		if !utf8.ValidString(plain) {
			t.Fatalf("blob length %d: successful decrypt returned invalid UTF-8 of length %d", len(blob), len(plain))
		}

		canonical, err := codec.Encrypt(context.Background(), plain, key)
		if err != nil {
			t.Fatalf("blob length %d plaintext length %d: re-encrypt returned kind %q", len(blob), len(plain), protocolErrorKindOf(err))
		}
		decoded, err := decodeStrictStdBase64(canonical)
		if err != nil || len(decoded) == 0 || len(decoded)%16 != 0 {
			t.Fatalf("blob length %d plaintext length %d canonical length %d: re-encrypt was not canonical", len(blob), len(plain), len(canonical))
		}
		roundTrip, err := codec.Decrypt(context.Background(), canonical, key)
		if err != nil {
			t.Fatalf("blob length %d plaintext length %d canonical length %d: canonical decrypt returned kind %q", len(blob), len(plain), len(canonical), protocolErrorKindOf(err))
		}
		if roundTrip != plain {
			t.Fatalf("blob length %d: round-trip plaintext lengths first=%d second=%d", len(blob), len(plain), len(roundTrip))
		}
	})
}
