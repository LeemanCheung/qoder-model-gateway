package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimePublicKeyMatchesPinnedSPKI(t *testing.T) {
	block, rest := pem.Decode([]byte(runtimePublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		t.Fatal("runtime public key PEM is not one exact PUBLIC KEY block")
	}
	if len(block.Bytes) != 162 {
		t.Fatalf("runtime public key SPKI DER length = %d, want 162", len(block.Bytes))
	}
	sum := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(sum[:]); got != "a6a4aa468d90c618966e38122abfb06e566c18c9b21090d61f3e9b796b33e569" {
		t.Fatal("runtime public key SPKI SHA-256 differs from the pinned digest")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal("parse pinned runtime SPKI")
	}
	independent, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("runtime SPKI key type = %T, want RSA", parsed)
	}
	if independent.Size() != 128 || independent.E != 65537 {
		t.Fatalf("runtime RSA size/exponent = %d/%d, want 128/65537", independent.Size(), independent.E)
	}

	got, err := runtimePublicKey()
	if err != nil {
		t.Fatalf("runtimePublicKey returned error kind %q", protocolErrorKindOf(err))
	}
	if got.Size() != independent.Size() || got.E != independent.E || got.N.Cmp(independent.N) != 0 {
		t.Fatal("runtimePublicKey differs from independent SPKI parsing")
	}
}

func TestRuntimePKCS1PaddingUsesBulkReadAndLeftToRightZeroRedraws(t *testing.T) {
	publicKey, err := runtimePublicKey()
	if err != nil {
		t.Fatalf("load runtime public key returned kind %q", protocolErrorKindOf(err))
	}
	message := []byte("0123456789abcdef")
	initialPS := bytes.Repeat([]byte{0x5a}, 109)
	initialPS[0] = 0
	initialPS[len(initialPS)-1] = 0
	entropy := &fixedProtocolEntropy{reads: [][]byte{
		initialPS,
		{0x00},
		{0x7f},
		{0x80},
	}}
	recorder := newTranscriptRecorder(protocolHostDeps{Entropy: entropy})

	ciphertext, err := rsaEncryptPKCS1v15Exact(publicKey, message, recorder)
	if err != nil {
		t.Fatalf("manual runtime RSA returned error kind %q", protocolErrorKindOf(err))
	}
	if len(ciphertext) != 128 {
		t.Fatalf("manual runtime RSA ciphertext length = %d, want 128", len(ciphertext))
	}
	transcript := recorder.Transcript()
	gotReads := entropyReadLengths(transcript)
	if wantReads := []int{109, 1, 1, 1}; !reflect.DeepEqual(gotReads, wantReads) {
		t.Fatalf("manual runtime RSA entropy read shape = %v, want %v", gotReads, wantReads)
	}

	finalPS := append([]byte(nil), initialPS...)
	finalPS[0] = 0x7f
	finalPS[len(finalPS)-1] = 0x80
	for i, value := range finalPS {
		if value == 0 {
			t.Fatalf("manual runtime RSA final PS byte %d is zero", i)
		}
	}
	em := make([]byte, publicKey.Size())
	em[1] = 2
	copy(em[2:], finalPS)
	copy(em[2+len(finalPS)+1:], message)
	m := new(big.Int).SetBytes(em)
	wantInt := new(big.Int).Exp(m, big.NewInt(int64(publicKey.E)), publicKey.N)
	want := make([]byte, publicKey.Size())
	wantInt.FillBytes(want)
	if !bytes.Equal(ciphertext, want) {
		t.Fatal("manual runtime RSA ciphertext differs from independently exponentiated encoded message")
	}
}

func TestRuntimePKCS1RejectsOversizedMessageBeforeEntropy(t *testing.T) {
	publicKey, err := runtimePublicKey()
	if err != nil {
		t.Fatalf("load runtime public key returned kind %q", protocolErrorKindOf(err))
	}
	entropy := &fixedProtocolEntropy{reads: [][]byte{{1}}}
	ciphertext, err := rsaEncryptPKCS1v15Exact(publicKey, bytes.Repeat([]byte{0x41}, publicKey.Size()-10), entropy)
	if err == nil || protocolErrorKindOf(err) != protocolInvalidInput {
		t.Fatalf("oversized RSA message error kind = %q, want %q", protocolErrorKindOf(err), protocolInvalidInput)
	}
	if len(ciphertext) != 0 || entropy.next != 0 {
		t.Fatalf("oversized RSA message returned length %d after %d entropy reads", len(ciphertext), entropy.next)
	}
}

func TestNativeRuntimeFieldsMatchesOfficialFixture(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "runtime-fields.json")
	var input runtimeFixtureInput
	var expected runtimeFixtureExpected
	decodeExactJSON(t, fixture.Input, &input)
	decodeExactJSON(t, fixture.Expected, &expected)
	replay := newTranscriptReplay(fixture.Transcript)
	ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: replay, Entropy: replay})
	rawInput := []byte(input.Raw)
	before := append([]byte(nil), rawInput...)

	got, err := generateNativeRuntimeFieldsRaw(ctx, protocolHostDeps{Clock: fixtureClock{}, Entropy: repeatedByteEntropy(0x33)}, rawInput)
	if err != nil {
		t.Fatalf("fixture raw input length %d: native generation returned kind %q", len(rawInput), protocolErrorKindOf(err))
	}
	if !bytes.Equal(rawInput, before) {
		t.Fatalf("fixture raw input length %d: native generation mutated input", len(rawInput))
	}
	if string(got) != expected.Raw {
		t.Fatalf("fixture native/official output lengths = %d/%d", len(got), len(expected.Raw))
	}
	fields, err := decodeRuntimeFieldOutputJSON(got)
	if err != nil {
		t.Fatalf("fixture native output length %d: strict decode returned kind %q", len(got), protocolErrorKindOf(err))
	}
	if fields.EncryptUserInfo != expected.EncryptUserInfo || fields.Key != expected.Key {
		t.Fatalf("fixture native field lengths encrypt/key = %d/%d, want %d/%d", len(fields.EncryptUserInfo), len(fields.Key), len(expected.EncryptUserInfo), len(expected.Key))
	}
	encryptedUserInfo, err := decodeStrictStdBase64(fields.EncryptUserInfo)
	if err != nil || len(encryptedUserInfo) == 0 || len(encryptedUserInfo)%16 != 0 {
		t.Fatalf("fixture encrypted-user field length %d did not decode to aligned standard Base64", len(fields.EncryptUserInfo))
	}
	encryptedKey, err := decodeStrictStdBase64(fields.Key)
	if err != nil || len(encryptedKey) != 128 {
		t.Fatalf("fixture key field length %d decoded RSA length %d, want 128", len(fields.Key), len(encryptedKey))
	}
	if len(fixture.Transcript.EntropyReads) == 0 || len(fixture.Transcript.EntropyReads[0].Bytes) != 16 {
		t.Fatal("fixture UUID entropy is unavailable")
	}
	var fixtureRandom [16]byte
	copy(fixtureRandom[:], fixture.Transcript.EntropyReads[0].Bytes)
	key := []byte(runtimeASCIIKey(reverseMaskUUID(fixtureRandom)))
	decryptedRaw, err := aesCBCDecryptPKCS7(encryptedUserInfo, key, key)
	if err != nil {
		t.Fatalf("fixture encrypted-user decoded length %d: AES recovery failed", len(encryptedUserInfo))
	}
	if !bytes.Equal(decryptedRaw, rawInput) {
		t.Fatalf("fixture AES recovery lengths plain/raw = %d/%d", len(decryptedRaw), len(rawInput))
	}
	if gotShape := entropyReadLengths(fixture.Transcript); !reflect.DeepEqual(gotShape, []int{16, 109}) {
		t.Fatalf("fixture entropy read shape = %v, want [16 109]", gotShape)
	}
	if len(fixture.Transcript.UnixMilli) != 0 {
		t.Fatalf("fixture clock read count = %d, want 0", len(fixture.Transcript.UnixMilli))
	}
	assertReplayExhausted(t, replay)
}

func entropyReadLengths(transcript protocolTranscript) []int {
	lengths := make([]int, len(transcript.EntropyReads))
	for i, read := range transcript.EntropyReads {
		lengths[i] = read.Length
	}
	return lengths
}

type runtimeScriptEntropy struct {
	fill    byte
	failAt  int
	err     error
	lengths []int
}

func (e *runtimeScriptEntropy) Read(dst []byte) error {
	call := len(e.lengths)
	e.lengths = append(e.lengths, len(dst))
	if call == e.failAt {
		return e.err
	}
	for i := range dst {
		dst[i] = e.fill
	}
	return nil
}

type runtimeEntropyStep struct {
	bytes []byte
	err   error
}

type runtimeSteppedEntropy struct {
	steps   []runtimeEntropyStep
	next    int
	lengths []int
}

func (e *runtimeSteppedEntropy) Read(dst []byte) error {
	e.lengths = append(e.lengths, len(dst))
	if e.next >= len(e.steps) {
		return errors.New("synthetic runtime entropy steps exhausted")
	}
	step := e.steps[e.next]
	e.next++
	if step.err != nil {
		return step.err
	}
	if len(step.bytes) != len(dst) {
		return errors.New("synthetic runtime entropy step length mismatch")
	}
	copy(dst, step.bytes)
	return nil
}

func TestNativeRuntimeFieldsClassifiesZeroRedrawEntropyFailure(t *testing.T) {
	sentinel := errors.New("synthetic runtime redraw entropy unavailable")
	initialPadding := bytes.Repeat([]byte{0x5a}, 109)
	initialPadding[0] = 0
	entropy := &runtimeSteppedEntropy{steps: []runtimeEntropyStep{
		{bytes: bytes.Repeat([]byte{0x11}, 16)},
		{bytes: initialPadding},
		{err: sentinel},
	}}
	generator := &nativeRuntimeFieldGenerator{host: protocolHostDeps{Clock: fixtureClock{}, Entropy: entropy}}
	got, err := generator.Generate(context.Background(), runtimeFieldInput{UID: "synthetic-redraw-user"})
	if err == nil || protocolErrorKindOf(err) != protocolEntropyFailure {
		t.Fatalf("zero-redraw entropy read shape %v: error kind = %q, want %q", entropy.lengths, protocolErrorKindOf(err), protocolEntropyFailure)
	}
	if got != (runtimeFieldOutput{}) {
		t.Fatalf("zero-redraw entropy read shape %v returned nonzero fields", entropy.lengths)
	}
	if err.Error() != "Secure protocol randomness is unavailable" || !errors.Is(protocolInternalError(err), sentinel) {
		t.Fatalf("zero-redraw entropy read shape %v: safe category or cause differs", entropy.lengths)
	}
	if !reflect.DeepEqual(entropy.lengths, []int{16, 109, 1}) {
		t.Fatalf("zero-redraw entropy read shape = %v, want [16 109 1]", entropy.lengths)
	}
}

func TestNativeRuntimeFieldsTypedGeneratorUsesContextOverrideAndFallback(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "runtime-fields.json")
	var fixtureInput runtimeFixtureInput
	var expected runtimeFixtureExpected
	decodeExactJSON(t, fixture.Input, &fixtureInput)
	decodeExactJSON(t, fixture.Expected, &expected)
	var input runtimeFieldInput
	decodeExactJSON(t, []byte(fixtureInput.Raw), &input)
	beforeTags := append([]string(nil), input.OrganizationTags...)

	t.Run("context override wins", func(t *testing.T) {
		fallbackEntropy := &runtimeScriptEntropy{fill: 0x33, failAt: -1}
		replay := newTranscriptReplay(fixture.Transcript)
		ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: replay, Entropy: replay})
		generator := &nativeRuntimeFieldGenerator{host: protocolHostDeps{Clock: fixtureClock{}, Entropy: fallbackEntropy}}
		got, err := generator.Generate(ctx, input)
		if err != nil {
			t.Fatalf("typed fixture input tags %d: Generate returned kind %q", len(input.OrganizationTags), protocolErrorKindOf(err))
		}
		if got.EncryptUserInfo != expected.EncryptUserInfo || got.Key != expected.Key {
			t.Fatalf("typed context-override field lengths encrypt/key = %d/%d, want %d/%d", len(got.EncryptUserInfo), len(got.Key), len(expected.EncryptUserInfo), len(expected.Key))
		}
		if len(fallbackEntropy.lengths) != 0 {
			t.Fatalf("typed context override used fallback entropy %d times", len(fallbackEntropy.lengths))
		}
		assertReplayExhausted(t, replay)
	})

	t.Run("struct fallback is used", func(t *testing.T) {
		replay := newTranscriptReplay(fixture.Transcript)
		generator := &nativeRuntimeFieldGenerator{host: protocolHostDeps{Clock: replay, Entropy: replay}}
		got, err := generator.Generate(context.Background(), input)
		if err != nil {
			t.Fatalf("typed fallback input tags %d: Generate returned kind %q", len(input.OrganizationTags), protocolErrorKindOf(err))
		}
		if got.EncryptUserInfo != expected.EncryptUserInfo || got.Key != expected.Key {
			t.Fatalf("typed fallback field lengths encrypt/key = %d/%d, want %d/%d", len(got.EncryptUserInfo), len(got.Key), len(expected.EncryptUserInfo), len(expected.Key))
		}
		assertReplayExhausted(t, replay)
	})
	if !reflect.DeepEqual(input.OrganizationTags, beforeTags) {
		t.Fatalf("typed generation mutated %d organization tags", len(beforeTags))
	}
}

func TestNativeRuntimeFieldsRejectsCanceledInvalidAndMissingHostInputsBeforeEntropy(t *testing.T) {
	t.Run("canceled context", func(t *testing.T) {
		entropy := &runtimeScriptEntropy{fill: 0x5a, failAt: -1}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := generateNativeRuntimeFieldsRaw(ctx, protocolHostDeps{Entropy: entropy}, append([]byte("SENTINEL-RUNTIME-RAW"), 0xff))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled raw generation error category = %T, want context cancellation", err)
		}
		if len(got) != 0 || len(entropy.lengths) != 0 {
			t.Fatalf("canceled raw generation output length/entropy calls = %d/%d", len(got), len(entropy.lengths))
		}
	})

	t.Run("invalid UTF-8", func(t *testing.T) {
		const sentinel = "SENTINEL-RUNTIME-RAW"
		entropy := &runtimeScriptEntropy{fill: 0x5a, failAt: -1}
		got, err := generateNativeRuntimeFieldsRaw(context.Background(), protocolHostDeps{Entropy: entropy}, append([]byte(sentinel), 0xff))
		if err == nil || protocolErrorKindOf(err) != protocolInvalidInput {
			t.Fatalf("invalid UTF-8 raw generation error kind = %q, want %q", protocolErrorKindOf(err), protocolInvalidInput)
		}
		if len(got) != 0 || len(entropy.lengths) != 0 {
			t.Fatalf("invalid UTF-8 raw generation output length/entropy calls = %d/%d", len(got), len(entropy.lengths))
		}
		if strings.Contains(err.Error()+" "+fmt.Sprint(protocolInternalError(err)), sentinel) {
			t.Fatal("invalid UTF-8 raw generation error leaked input content")
		}
	})

	t.Run("missing entropy", func(t *testing.T) {
		got, err := generateNativeRuntimeFieldsRaw(context.Background(), protocolHostDeps{Clock: fixtureClock{}}, []byte(`{}`))
		if err == nil || protocolErrorKindOf(err) != protocolBackendIncompatible {
			t.Fatalf("missing entropy error kind = %q, want %q", protocolErrorKindOf(err), protocolBackendIncompatible)
		}
		if len(got) != 0 {
			t.Fatalf("missing entropy returned output length %d", len(got))
		}
	})
}

func TestNativeRuntimeFieldsClassifiesEntropyFailuresThroughTypedGenerator(t *testing.T) {
	sentinel := errors.New("synthetic runtime entropy unavailable")
	for _, tt := range []struct {
		name      string
		failAt    int
		wantShape []int
	}{
		{name: "UUID read", failAt: 0, wantShape: []int{16}},
		{name: "RSA padding read", failAt: 1, wantShape: []int{16, 109}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entropy := &runtimeScriptEntropy{fill: 0x5a, failAt: tt.failAt, err: sentinel}
			generator := &nativeRuntimeFieldGenerator{host: protocolHostDeps{Clock: fixtureClock{}, Entropy: entropy}}
			got, err := generator.Generate(context.Background(), runtimeFieldInput{
				UID: "synthetic-runtime-user", OrganizationID: "synthetic-runtime-org",
				OrganizationTags: []string{"synthetic-tag"}, DataPolicyAgreed: true,
			})
			if err == nil || protocolErrorKindOf(err) != protocolEntropyFailure {
				t.Fatalf("case %s read shape %v: error kind = %q, want %q", tt.name, entropy.lengths, protocolErrorKindOf(err), protocolEntropyFailure)
			}
			if got != (runtimeFieldOutput{}) {
				t.Fatalf("case %s read shape %v: entropy failure returned nonzero fields", tt.name, entropy.lengths)
			}
			if err.Error() != "Secure protocol randomness is unavailable" || !errors.Is(protocolInternalError(err), sentinel) {
				t.Fatalf("case %s read shape %v: entropy failure category or cause differs", tt.name, entropy.lengths)
			}
			if !reflect.DeepEqual(entropy.lengths, tt.wantShape) {
				t.Fatalf("case %s entropy read shape = %v, want %v", tt.name, entropy.lengths, tt.wantShape)
			}
		})
	}
}

func deterministicRuntimeTranscript(zeroRedraw bool) protocolTranscript {
	uuidBytes := make([]byte, 16)
	for i := range uuidBytes {
		uuidBytes[i] = byte(i + 1)
	}
	padding := make([]byte, 109)
	for i := range padding {
		padding[i] = byte(i + 17)
	}
	reads := []entropyRead{
		{Length: len(uuidBytes), Bytes: uuidBytes},
		{Length: len(padding), Bytes: padding},
	}
	if zeroRedraw {
		padding[0] = 0
		padding[len(padding)-1] = 0
		reads = append(reads,
			entropyRead{Length: 1, Bytes: []byte{0x00}},
			entropyRead{Length: 1, Bytes: []byte{0x7f}},
			entropyRead{Length: 1, Bytes: []byte{0x80}},
		)
	}
	return protocolTranscript{EntropyReads: reads}
}

func TestNativeRuntimeFieldsOutputParserAcceptsOneExactObject(t *testing.T) {
	raw := []byte("{\"encrypt_user_info\":\"synthetic-encrypted\",\"key\":\"synthetic-key\"}\n\t")
	got, err := decodeRuntimeFieldOutputJSON(raw)
	if err != nil {
		t.Fatalf("strict runtime output length %d returned kind %q", len(raw), protocolErrorKindOf(err))
	}
	want := runtimeFieldOutput{EncryptUserInfo: "synthetic-encrypted", Key: "synthetic-key"}
	if got != want {
		t.Fatal("strict runtime output fields differ from the synthetic object")
	}
	canonical, err := json.Marshal(got)
	if err != nil {
		t.Fatal("marshal parsed synthetic runtime output")
	}
	if string(canonical) != `{"encrypt_user_info":"synthetic-encrypted","key":"synthetic-key"}` {
		t.Fatalf("canonical runtime output length = %d, want ordered compact object", len(canonical))
	}
}

func TestNativeRuntimeFieldsOutputParserRejectsInvalidEnvelopesSafely(t *testing.T) {
	const sentinel = "SENTINEL-RUNTIME-OUTPUT-VALUE"
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "top-level array", raw: []byte(`[]`)},
		{name: "missing encrypt field", raw: []byte(`{"key":"synthetic-key"}`)},
		{name: "missing key field", raw: []byte(`{"encrypt_user_info":"synthetic-encrypted"}`)},
		{name: "empty encrypt field", raw: []byte(`{"encrypt_user_info":"","key":"synthetic-key"}`)},
		{name: "empty key field", raw: []byte(`{"encrypt_user_info":"synthetic-encrypted","key":""}`)},
		{name: "duplicate encrypt field", raw: []byte(`{"encrypt_user_info":"synthetic-a","encrypt_user_info":"synthetic-b","key":"synthetic-key"}`)},
		{name: "duplicate key field", raw: []byte(`{"encrypt_user_info":"synthetic-encrypted","key":"synthetic-a","key":"synthetic-b"}`)},
		{name: "unknown field", raw: []byte(`{"encrypt_user_info":"synthetic-encrypted","key":"synthetic-key","` + sentinel + `":"` + sentinel + `"}`)},
		{name: "wrong encrypt type", raw: []byte(`{"encrypt_user_info":1,"key":"synthetic-key"}`)},
		{name: "wrong key type", raw: []byte(`{"encrypt_user_info":"synthetic-encrypted","key":null}`)},
		{name: "trailing object", raw: []byte(`{"encrypt_user_info":"synthetic-encrypted","key":"synthetic-key"}{}`)},
		{name: "trailing token", raw: []byte(`{"encrypt_user_info":"synthetic-encrypted","key":"synthetic-key"}x`)},
		{name: "malformed", raw: []byte(`{"encrypt_user_info":`)},
		{name: "invalid UTF-8", raw: []byte{0xff, 0xfe}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRuntimeFieldOutputJSON(tt.raw)
			if err == nil || protocolErrorKindOf(err) != protocolBackendFailure {
				t.Fatalf("case %s length %d: error kind = %q, want %q", tt.name, len(tt.raw), protocolErrorKindOf(err), protocolBackendFailure)
			}
			if got != (runtimeFieldOutput{}) {
				t.Fatalf("case %s length %d: rejected output was nonzero", tt.name, len(tt.raw))
			}
			if err.Error() != "Qoder protocol operation failed" {
				t.Fatalf("case %s length %d: public error category differs", tt.name, len(tt.raw))
			}
			combined := err.Error() + " " + fmt.Sprint(protocolInternalError(err))
			if strings.Contains(combined, sentinel) || strings.Contains(combined, "synthetic-encrypted") || strings.Contains(combined, "synthetic-key") {
				t.Fatalf("case %s length %d: error leaked a runtime output value", tt.name, len(tt.raw))
			}
		})
	}
}
