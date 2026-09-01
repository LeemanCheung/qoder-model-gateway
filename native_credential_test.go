package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNativeCredentialMatchesOfficialFixture(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "credential.json")
	var input credentialFixtureInput
	var expected credentialFixtureExpected
	decodeExactJSON(t, fixture.Input, &input)
	decodeExactJSON(t, fixture.Expected, &expected)

	codec := nativeCredentialCodec{}
	encrypted, err := codec.Encrypt(context.Background(), input.Plain, input.MachineKey)
	if err != nil {
		t.Fatalf("fixture plaintext length %d key byte length %d: native Encrypt returned kind %q", len(input.Plain), len([]byte(input.MachineKey)), protocolErrorKindOf(err))
	}
	if encrypted != expected.Encrypted {
		t.Fatalf("fixture encryption mismatch: native length %d official length %d", len(encrypted), len(expected.Encrypted))
	}

	decrypted, err := codec.Decrypt(context.Background(), expected.Encrypted, input.MachineKey)
	if err != nil {
		t.Fatalf("fixture ciphertext length %d key byte length %d: native Decrypt returned kind %q", len(expected.Encrypted), len([]byte(input.MachineKey)), protocolErrorKindOf(err))
	}
	if decrypted != expected.Decrypted {
		t.Fatalf("fixture decryption mismatch: native length %d official length %d", len(decrypted), len(expected.Decrypted))
	}
}

func TestNativeCredentialDecryptRejectsInvalidUTF8(t *testing.T) {
	const key = "0123456789abcdef"
	invalidPlain := []byte{0xff}
	ciphertext, err := aesCBCEncryptPKCS7(invalidPlain, []byte(key), []byte(key))
	if err != nil {
		t.Fatalf("invalid UTF-8 setup plaintext length %d: AES helper returned error", len(invalidPlain))
	}
	blob := base64.StdEncoding.EncodeToString(ciphertext)

	plain, err := (nativeCredentialCodec{}).Decrypt(context.Background(), blob, key)
	if err == nil {
		t.Fatalf("native invalid UTF-8 ciphertext length %d: Decrypt succeeded with plaintext length %d", len(blob), len(plain))
	}
	if plain != "" {
		t.Fatalf("native invalid UTF-8 ciphertext length %d: rejected Decrypt returned plaintext length %d", len(blob), len(plain))
	}
	if got := protocolErrorKindOf(err); got != protocolBackendIncompatible {
		t.Fatalf("native invalid UTF-8 ciphertext length %d: error kind %q, want %q", len(blob), got, protocolBackendIncompatible)
	}
	if err.Error() != "credential data is incompatible" {
		t.Fatalf("native invalid UTF-8 ciphertext length %d: public error category is unsafe", len(blob))
	}
}

func TestNativeCredentialRoundTripVectors(t *testing.T) {
	codec := nativeCredentialCodec{}
	for _, test := range []struct {
		name  string
		plain string
		key   string
	}{
		{name: "empty plaintext", plain: "", key: "0123456789abcdef"},
		{name: "unicode plaintext", plain: "合成🙂凭据", key: "密钥1234567890"},
		{name: "embedded NUL", plain: "synthetic\x00credential", key: "0123456789abcdef"},
		{name: "length 15", plain: strings.Repeat("a", 15), key: "密钥1234567890"},
		{name: "length 16", plain: strings.Repeat("b", 16), key: "0123456789abcdef"},
		{name: "length 17", plain: strings.Repeat("c", 17), key: "密钥1234567890"},
		{name: "4 KiB", plain: strings.Repeat("x", 4<<10), key: "0123456789abcdef"},
	} {
		t.Run(test.name, func(t *testing.T) {
			first, err := codec.Encrypt(context.Background(), test.plain, test.key)
			if err != nil {
				t.Fatalf("Encrypt() returned kind %q", protocolErrorKindOf(err))
			}
			second, err := codec.Encrypt(context.Background(), test.plain, test.key)
			if err != nil {
				t.Fatalf("second Encrypt() returned kind %q", protocolErrorKindOf(err))
			}
			if first != second {
				t.Fatal("deterministic credential encryption produced different envelopes")
			}
			plain, err := codec.Decrypt(context.Background(), first, test.key)
			if err != nil {
				t.Fatalf("Decrypt() returned kind %q", protocolErrorKindOf(err))
			}
			if plain != test.plain {
				t.Fatalf("round-trip plaintext lengths got/want = %d/%d", len([]byte(plain)), len([]byte(test.plain)))
			}
		})
	}
}

func TestNativeCredentialRejectsInvalidMachineKeyByteLengths(t *testing.T) {
	codec := nativeCredentialCodec{}
	tests := []struct {
		name string
		key  string
	}{
		{name: "empty", key: ""},
		{name: "15 ASCII bytes", key: strings.Repeat("k", 15)},
		{name: "17 ASCII bytes", key: strings.Repeat("k", 17)},
		{name: "five multibyte runes", key: strings.Repeat("密", 5)},
		{name: "six multibyte runes", key: strings.Repeat("密", 6)},
		{name: "16 multibyte runes", key: strings.Repeat("密", 16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyLen := len([]byte(tt.key))
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{name: "encrypt", run: func() error {
					_, err := codec.Encrypt(context.Background(), "SENTINEL-CREDENTIAL-PLAINTEXT", tt.key)
					return err
				}},
				{name: "decrypt", run: func() error {
					_, err := codec.Decrypt(context.Background(), "QUFBQUFBQUFBQUFBQUFBQQ==", tt.key)
					return err
				}},
			} {
				err := operation.run()
				if protocolErrorKindOf(err) != protocolInvalidInput {
					t.Fatalf("case %s operation %s key byte length %d: error kind %q, want %q", tt.name, operation.name, keyLen, protocolErrorKindOf(err), protocolInvalidInput)
				}
				if err == nil || err.Error() != "credential input is invalid" {
					t.Fatalf("case %s operation %s key byte length %d: public error category is unsafe", tt.name, operation.name, keyLen)
				}
				if tt.key != "" && strings.Contains(err.Error(), tt.key) {
					t.Fatalf("case %s operation %s key byte length %d: public error leaked key", tt.name, operation.name, keyLen)
				}
			}
		})
	}
}

func TestNativeCredentialRejectsMalformedEnvelopesSafely(t *testing.T) {
	const key = "0123456789abcdef"
	const sentinelPlain = "SENTINEL-CREDENTIAL-PLAINTEXT"
	codec := nativeCredentialCodec{}
	valid, err := codec.Encrypt(context.Background(), sentinelPlain, key)
	if err != nil {
		t.Fatalf("setup plaintext length %d: Encrypt returned kind %q", len(sentinelPlain), protocolErrorKindOf(err))
	}
	emptyPlainCiphertext, err := codec.Encrypt(context.Background(), "", key)
	if err != nil {
		t.Fatalf("setup empty plaintext: Encrypt returned kind %q", protocolErrorKindOf(err))
	}
	missingPadding := strings.TrimRight(emptyPlainCiphertext, "=")

	aligned, err := codec.Encrypt(context.Background(), strings.Repeat("p", 16), key)
	if err != nil {
		t.Fatalf("setup aligned plaintext length 16: Encrypt returned kind %q", protocolErrorKindOf(err))
	}
	corruptedBytes, err := decodeStrictStdBase64(aligned)
	if err != nil || len(corruptedBytes) != 32 {
		t.Fatalf("setup aligned ciphertext length %d: strict decode error presence %t decoded length %d", len(aligned), err != nil, len(corruptedBytes))
	}
	corruptedBytes[15] ^= 1
	corruptedPadding := base64.StdEncoding.EncodeToString(corruptedBytes)

	tests := []struct {
		name string
		blob string
	}{
		{name: "empty blob", blob: ""},
		{name: "URL-safe Base64", blob: "-_8="},
		{name: "missing padding", blob: missingPadding},
		{name: "carriage return", blob: valid + "\r"},
		{name: "line feed", blob: valid + "\n"},
		{name: "space", blob: valid + " "},
		{name: "trailing garbage", blob: valid + "garbage"},
		{name: "corrupted final padding", blob: corruptedPadding},
	}
	for decodedLen := 1; decodedLen <= 15; decodedLen++ {
		tests = append(tests, struct {
			name string
			blob string
		}{name: fmt.Sprintf("decoded length %d", decodedLen), blob: base64.StdEncoding.EncodeToString(bytesOfLength(decodedLen))})
	}
	for _, decodedLen := range []int{17, 31} {
		tests = append(tests, struct {
			name string
			blob string
		}{name: fmt.Sprintf("block misalignment %d", decodedLen), blob: base64.StdEncoding.EncodeToString(bytesOfLength(decodedLen))})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plain, err := codec.Decrypt(context.Background(), tt.blob, key)
			if err == nil {
				t.Fatalf("case %s blob length %d: Decrypt succeeded with plaintext length %d", tt.name, len(tt.blob), len(plain))
			}
			if plain != "" {
				t.Fatalf("case %s blob length %d: rejected Decrypt returned plaintext length %d", tt.name, len(tt.blob), len(plain))
			}
			if got := protocolErrorKindOf(err); got != protocolBackendIncompatible {
				t.Fatalf("case %s blob length %d: error kind %q, want %q", tt.name, len(tt.blob), got, protocolBackendIncompatible)
			}
			if err.Error() != "credential data is incompatible" {
				t.Fatalf("case %s blob length %d: public error category is unsafe", tt.name, len(tt.blob))
			}
			if strings.Contains(err.Error(), sentinelPlain) || (tt.blob != "" && strings.Contains(err.Error(), tt.blob)) {
				t.Fatalf("case %s blob length %d: public error leaked credential content", tt.name, len(tt.blob))
			}
		})
	}
}

func TestNativeCredentialHonorsCanceledContextBeforeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	codec := nativeCredentialCodec{}
	if _, err := codec.Encrypt(ctx, "SENTINEL-CREDENTIAL-PLAINTEXT", "short"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Encrypt cancellation error category = %T, want context cancellation", err)
	}
	if _, err := codec.Decrypt(ctx, "SENTINEL-CREDENTIAL-CIPHERTEXT", "short"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Decrypt cancellation error category = %T, want context cancellation", err)
	}
}

func bytesOfLength(length int) []byte {
	value := make([]byte, length)
	for i := range value {
		value[i] = byte(i + 1)
	}
	return value
}
