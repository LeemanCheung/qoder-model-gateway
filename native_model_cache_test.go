package main

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNativeModelCacheDerives32ByteKey(t *testing.T) {
	const oracleUID = "synthetic-user-0001"
	got, err := deriveModelCacheKey(oracleUID)
	if err != nil {
		t.Fatalf("oracle synthetic UID: derive returned error kind %q", protocolErrorKindOf(err))
	}
	want, err := hkdf.Key(sha256.New, []byte(oracleUID), []byte("qoder-model-cache-enc"), "model-cache-v1", 32)
	if err != nil {
		t.Fatal("independent HKDF-SHA256 oracle returned an error")
	}
	if !bytes.Equal(got, want) {
		t.Fatal("derived key differs from independent HKDF-SHA256 oracle")
	}

	first, err := deriveModelCacheKey("synthetic-user-a")
	if err != nil {
		t.Fatalf("first synthetic UID: derive returned error kind %q", protocolErrorKindOf(err))
	}
	second, err := deriveModelCacheKey("synthetic-user-a")
	if err != nil {
		t.Fatalf("second synthetic UID: derive returned error kind %q", protocolErrorKindOf(err))
	}
	different, err := deriveModelCacheKey("synthetic-user-b")
	if err != nil {
		t.Fatalf("different synthetic UID: derive returned error kind %q", protocolErrorKindOf(err))
	}
	if len(first) != 32 || len(second) != 32 || len(different) != 32 {
		t.Fatalf("derived key lengths = %d/%d/%d, want 32 each", len(first), len(second), len(different))
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same synthetic UID produced different derived keys")
	}
	if bytes.Equal(first, different) {
		t.Fatal("different synthetic UIDs produced the same derived key")
	}
	first[0] ^= 1
	if bytes.Equal(first, second) {
		t.Fatal("derived key calls returned aliased storage")
	}
}

func TestNativeModelCacheMatchesOfficialFixture(t *testing.T) {
	input, expected, nonce := loadNativeModelCacheFixture(t)

	encrypted, err := encryptQMCV1ForTest([]byte(input.Plain), input.UID, nonce)
	if err != nil {
		t.Fatalf("fixture plaintext length %d nonce length %d: native encrypt returned kind %q", len(input.Plain), len(nonce), protocolErrorKindOf(err))
	}
	if encrypted != expected.Encrypted {
		t.Fatalf("fixture encryption mismatch: native length %d official length %d", len(encrypted), len(expected.Encrypted))
	}
	decrypted, err := (nativeModelCacheDecryptor{}).Decrypt(context.Background(), expected.Encrypted, input.UID)
	if err != nil {
		t.Fatalf("fixture encrypted length %d: native decrypt returned kind %q", len(expected.Encrypted), protocolErrorKindOf(err))
	}
	if string(decrypted) != expected.Decrypted {
		t.Fatalf("fixture decryption mismatch: native length %d official length %d", len(decrypted), len(expected.Decrypted))
	}
}

func TestNativeModelCacheOfficialFixtureMutationsFailClosed(t *testing.T) {
	input, expected, _ := loadNativeModelCacheFixture(t)
	envelope, err := decodeStrictStdBase64(expected.Encrypted)
	if err != nil {
		t.Fatalf("fixture encrypted length %d: strict decode failed", len(expected.Encrypted))
	}
	indices := []int{0, len(qmcV1Prefix) - 1, len(qmcV1Prefix), len(qmcV1Prefix) + qmcNonceSize, len(envelope) - 1}
	for mutation, index := range indices {
		changed := append([]byte(nil), envelope...)
		changed[index] ^= 1
		blob := base64.StdEncoding.EncodeToString(changed)
		plain, err := (nativeModelCacheDecryptor{}).Decrypt(context.Background(), blob, input.UID)
		if err == nil || protocolErrorKindOf(err) != protocolBackendIncompatible {
			t.Fatalf("mutation %d at envelope offset %d: fail-closed category differs", mutation, index)
		}
		if plain != nil {
			t.Fatalf("mutation %d at envelope offset %d: returned plaintext length %d", mutation, index, len(plain))
		}
	}
	plain, err := (nativeModelCacheDecryptor{}).Decrypt(context.Background(), expected.Encrypted, "synthetic-wrong-fixture-user")
	if err == nil || protocolErrorKindOf(err) != protocolBackendIncompatible {
		t.Fatal("wrong synthetic fixture UID did not fail closed")
	}
	if plain != nil {
		t.Fatalf("wrong synthetic fixture UID returned plaintext length %d", len(plain))
	}
}

func loadNativeModelCacheFixture(t *testing.T) (modelCacheFixtureInput, modelCacheFixtureExpected, []byte) {
	t.Helper()
	_, fixture := loadProtocolFixture(t, "model-cache.json")
	var input modelCacheFixtureInput
	var expected modelCacheFixtureExpected
	decodeExactJSON(t, fixture.Input, &input)
	decodeExactJSON(t, fixture.Expected, &expected)
	if len(fixture.Transcript.EntropyReads) != 1 {
		t.Fatalf("fixture entropy read count = %d, want 1", len(fixture.Transcript.EntropyReads))
	}
	nonce := append([]byte(nil), fixture.Transcript.EntropyReads[0].Bytes...)
	if fixture.Transcript.EntropyReads[0].Length != qmcNonceSize || len(nonce) != qmcNonceSize {
		t.Fatalf("fixture nonce declared/decoded lengths = %d/%d, want %d", fixture.Transcript.EntropyReads[0].Length, len(nonce), qmcNonceSize)
	}
	return input, expected, nonce
}

func TestDecryptQMCV1RoundTripReturnsFreshPlaintext(t *testing.T) {
	plain := []byte("synthetic model cache plaintext")
	blob, err := encryptQMCV1ForTest(plain, "synthetic-user", []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("setup plaintext length %d: encrypt returned kind %q", len(plain), protocolErrorKindOf(err))
	}

	first, err := decryptQMCV1(blob, "synthetic-user")
	if err != nil {
		t.Fatalf("ciphertext length %d: decrypt returned kind %q", len(blob), protocolErrorKindOf(err))
	}
	if !bytes.Equal(first, plain) {
		t.Fatalf("round-trip lengths plaintext=%d decrypted=%d", len(plain), len(first))
	}
	first[0] ^= 1
	second, err := decryptQMCV1(blob, "synthetic-user")
	if err != nil {
		t.Fatalf("second ciphertext length %d: decrypt returned kind %q", len(blob), protocolErrorKindOf(err))
	}
	if !bytes.Equal(second, plain) {
		t.Fatalf("second round-trip lengths plaintext=%d decrypted=%d", len(plain), len(second))
	}
}

func TestNativeModelCacheDecryptorHonorsCanceledContextBeforeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plain, err := (nativeModelCacheDecryptor{}).Decrypt(ctx, "not-base64", "synthetic-user")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error category = %T, want context cancellation", err)
	}
	if plain != nil {
		t.Fatalf("canceled decrypt returned plaintext length %d", len(plain))
	}
}

func TestNativeModelCacheRejectsMalformedEnvelopesSafely(t *testing.T) {
	const uid = "SENTINEL-MODEL-CACHE-UID"
	plain := []byte("SENTINEL-MODEL-CACHE-PLAINTEXT")
	valid, err := encryptQMCV1ForTest(plain, uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("setup plaintext length %d: encrypt returned kind %q", len(plain), protocolErrorKindOf(err))
	}
	validEnvelope, err := decodeStrictStdBase64(valid)
	if err != nil {
		t.Fatalf("setup encrypted length %d: strict decode failed", len(valid))
	}
	emptyValid, err := encryptQMCV1ForTest(nil, uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("setup empty plaintext: encrypt returned kind %q", protocolErrorKindOf(err))
	}
	emptyEnvelope, err := decodeStrictStdBase64(emptyValid)
	if err != nil {
		t.Fatalf("setup empty encrypted length %d: strict decode failed", len(emptyValid))
	}

	encode := base64.StdEncoding.EncodeToString
	wrongMagic := append([]byte(nil), validEnvelope...)
	wrongMagic[0] ^= 1
	wrongVersion := append([]byte(nil), validEnvelope...)
	wrongVersion[len(qmcV1Prefix)-1]++
	corruptCiphertext := append([]byte(nil), validEnvelope...)
	corruptCiphertext[len(qmcV1Prefix)+qmcNonceSize] ^= 1
	corruptTag := append([]byte(nil), validEnvelope...)
	corruptTag[len(corruptTag)-1] ^= 1
	missingPadding := strings.TrimRight(valid, "=")
	if missingPadding == valid {
		t.Fatal("setup encrypted envelope unexpectedly lacks padding")
	}

	tests := []struct {
		name     string
		blob     string
		uid      string
		internal string
	}{
		{name: "empty Base64", blob: "", uid: uid, internal: "model cache envelope is too short"},
		{name: "carriage return", blob: valid + "\r", uid: uid, internal: "model cache envelope encoding is invalid"},
		{name: "line feed", blob: valid + "\n", uid: uid, internal: "model cache envelope encoding is invalid"},
		{name: "URL-safe Base64", blob: "-_8=", uid: uid, internal: "model cache envelope encoding is invalid"},
		{name: "missing padding", blob: missingPadding, uid: uid, internal: "model cache envelope encoding is invalid"},
		{name: "trailing garbage", blob: valid + "garbage", uid: uid, internal: "model cache envelope encoding is invalid"},
		{name: "wrong magic", blob: encode(wrongMagic), uid: uid, internal: "model cache envelope magic or version is unsupported"},
		{name: "wrong version", blob: encode(wrongVersion), uid: uid, internal: "model cache envelope magic or version is unsupported"},
		{name: "truncated nonce", blob: encode(append([]byte(qmcV1Prefix), make([]byte, qmcNonceSize-1+qmcTagSize)...)), uid: uid, internal: "model cache envelope is too short"},
		{name: "truncated tag", blob: encode(emptyEnvelope[:len(emptyEnvelope)-1]), uid: uid, internal: "model cache envelope is too short"},
		{name: "corrupt ciphertext", blob: encode(corruptCiphertext), uid: uid, internal: "model cache envelope authentication failed"},
		{name: "corrupt tag", blob: encode(corruptTag), uid: uid, internal: "model cache envelope authentication failed"},
		{name: "wrong UID", blob: valid, uid: "SENTINEL-WRONG-MODEL-CACHE-UID", internal: "model cache envelope authentication failed"},
	}
	for decodedLen := 1; decodedLen < len(qmcV1Prefix)+qmcNonceSize+qmcTagSize; decodedLen++ {
		tests = append(tests, struct {
			name     string
			blob     string
			uid      string
			internal string
		}{
			name:     fmt.Sprintf("decoded length %d", decodedLen),
			blob:     encode(make([]byte, decodedLen)),
			uid:      uid,
			internal: "model cache envelope is too short",
		})
	}

	decryptor := nativeModelCacheDecryptor{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decryptor.Decrypt(context.Background(), tt.blob, tt.uid)
			if err == nil {
				t.Fatalf("case %s blob length %d: decrypt succeeded with plaintext length %d", tt.name, len(tt.blob), len(got))
			}
			if got != nil {
				t.Fatalf("case %s blob length %d: rejected decrypt returned plaintext length %d", tt.name, len(tt.blob), len(got))
			}
			if kind := protocolErrorKindOf(err); kind != protocolBackendIncompatible {
				t.Fatalf("case %s blob length %d: error kind %q, want %q", tt.name, len(tt.blob), kind, protocolBackendIncompatible)
			}
			if err.Error() != "model cache data is incompatible" {
				t.Fatalf("case %s blob length %d: public error category is unsafe", tt.name, len(tt.blob))
			}
			internal := protocolInternalError(err)
			if internal == nil || internal.Error() != tt.internal {
				t.Fatalf("case %s blob length %d: internal error category differs", tt.name, len(tt.blob))
			}
			for _, forbidden := range []string{uid, tt.uid, string(plain), tt.blob} {
				if forbidden != "" && (strings.Contains(err.Error(), forbidden) || strings.Contains(internal.Error(), forbidden)) {
					t.Fatalf("case %s blob length %d: error leaked a forbidden content marker", tt.name, len(tt.blob))
				}
			}
		})
	}
}

func TestEncryptQMCV1ForTestRejectsInvalidNonce(t *testing.T) {
	for _, nonceLen := range []int{0, qmcNonceSize - 1, qmcNonceSize + 1} {
		_, err := encryptQMCV1ForTest([]byte("synthetic payload"), "synthetic-user", make([]byte, nonceLen))
		if err == nil {
			t.Fatalf("nonce length %d: encrypt returned nil error", nonceLen)
		}
		if got := protocolErrorKindOf(err); got != protocolInvalidInput {
			t.Fatalf("nonce length %d: error kind %q, want %q", nonceLen, got, protocolInvalidInput)
		}
		if err.Error() != "model cache input is invalid" {
			t.Fatalf("nonce length %d: public error category is unsafe", nonceLen)
		}
	}
}

func TestEncryptQMCV1ForTestUsesV1Layout(t *testing.T) {
	plain := []byte("synthetic model cache payload")
	nonce := []byte("nonce-12byte")
	plainBefore := append([]byte(nil), plain...)
	nonceBefore := append([]byte(nil), nonce...)

	blob, err := encryptQMCV1ForTest(plain, "synthetic-user", nonce)
	if err != nil {
		t.Fatalf("plaintext length %d nonce length %d: encrypt returned kind %q", len(plain), len(nonce), protocolErrorKindOf(err))
	}
	envelope, err := decodeStrictStdBase64(blob)
	if err != nil {
		t.Fatalf("encrypted length %d: strict decode failed", len(blob))
	}
	wantLen := len(qmcV1Prefix) + qmcNonceSize + len(plain) + qmcTagSize
	if len(envelope) != wantLen {
		t.Fatalf("envelope length = %d, want %d", len(envelope), wantLen)
	}
	if !bytes.Equal(envelope[:len(qmcV1Prefix)], []byte(qmcV1Prefix)) {
		t.Fatal("envelope prefix differs from QMC v1")
	}
	if !bytes.Equal(envelope[len(qmcV1Prefix):len(qmcV1Prefix)+qmcNonceSize], nonce) {
		t.Fatal("envelope nonce differs from caller nonce")
	}
	if !bytes.Equal(plain, plainBefore) || !bytes.Equal(nonce, nonceBefore) {
		t.Fatal("test encrypt mutated caller input")
	}
}
