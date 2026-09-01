package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzModelCacheEnvelope(f *testing.F) {
	encoded, err := os.ReadFile(filepath.Join(protocolFixtureDir(), "model-cache.json"))
	if err != nil {
		f.Fatalf("read model-cache fixture: %v", err)
	}
	var fixture protocolFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		f.Fatalf("decode model-cache fixture: %v", err)
	}
	var expected modelCacheFixtureExpected
	if err := json.Unmarshal(fixture.Expected, &expected); err != nil {
		f.Fatalf("decode model-cache expected fixture: %v", err)
	}
	officialEnvelope, err := decodeStrictStdBase64(expected.Encrypted)
	if err != nil {
		f.Fatalf("official encrypted length %d: strict decode failed", len(expected.Encrypted))
	}

	wrongVersion := append([]byte(nil), officialEnvelope...)
	wrongVersion[len(qmcV1Prefix)-1]++
	corruptTag := append([]byte(nil), officialEnvelope...)
	corruptTag[len(corruptTag)-1] ^= 1
	truncatedNonce := append([]byte(qmcV1Prefix), make([]byte, qmcNonceSize-1)...)
	truncatedTag := append([]byte(qmcV1Prefix), make([]byte, qmcNonceSize+qmcTagSize-1)...)
	missingPadding := strings.TrimRight(expected.Encrypted, "=")
	if missingPadding == expected.Encrypted {
		f.Fatal("official encrypted fixture unexpectedly lacks padding")
	}

	for _, seed := range []string{
		expected.Encrypted,
		"",
		base64.StdEncoding.EncodeToString([]byte("QMC")),
		base64.StdEncoding.EncodeToString(wrongVersion),
		base64.StdEncoding.EncodeToString(truncatedNonce),
		base64.StdEncoding.EncodeToString(truncatedTag),
		base64.StdEncoding.EncodeToString(corruptTag),
		missingPadding,
		expected.Encrypted + "\r",
		expected.Encrypted + "\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, blob string) {
		if len(blob) > 1<<20 {
			return
		}
		plain, err := (nativeModelCacheDecryptor{}).Decrypt(t.Context(), blob, protocolFixtureUID)
		if err != nil {
			return
		}
		reencrypted, err := encryptQMCV1ForTest(plain, protocolFixtureUID, []byte("fuzz-nonce12"))
		if err != nil {
			t.Fatalf("successful decrypt plaintext length %d: re-encrypt returned kind %q", len(plain), protocolErrorKindOf(err))
		}
		roundTrip, err := (nativeModelCacheDecryptor{}).Decrypt(t.Context(), reencrypted, protocolFixtureUID)
		if err != nil {
			t.Fatalf("re-encrypted length %d: decrypt returned kind %q", len(reencrypted), protocolErrorKindOf(err))
		}
		if !bytes.Equal(roundTrip, plain) {
			t.Fatalf("round-trip plaintext lengths got=%d want=%d", len(roundTrip), len(plain))
		}
	})
}
