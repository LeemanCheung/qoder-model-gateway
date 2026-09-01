package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureOracle struct {
	Version string `json:"version"`
	Size    int    `json:"size"`
	SHA256  string `json:"sha256"`
}

type fixtureManifest struct {
	Version   string            `json:"version"`
	Size      int               `json:"size"`
	SHA256    string            `json:"sha256"`
	Documents map[string]string `json:"documents"`
}

type protocolFixture struct {
	Oracle     fixtureOracle      `json:"oracle"`
	Input      json.RawMessage    `json:"input"`
	Transcript protocolTranscript `json:"transcript"`
	Expected   json.RawMessage    `json:"expected"`
}

const (
	protocolFixtureUnixMilli       = int64(1_781_000_123_456)
	protocolFixtureMachineID       = "00000000-1111-4222-8333-444444444444"
	protocolFixtureMachineKey      = "00000000-1111-42"
	protocolFixtureUID             = "synthetic-user-0001"
	protocolFixtureOrg             = "synthetic-org-0001"
	protocolFixtureEndpoint        = "https://example.invalid/base"
	protocolFixtureSessionID       = "synthetic-session-0001"
	protocolFixtureRequestID       = "synthetic-request-0001"
	protocolFixtureBusinessID      = "synthetic-business-0001"
	protocolFixtureBusinessMillis  = int64(1_781_000_123_456)
	protocolFixtureCredentialPlain = `{"uid":"synthetic-user-0001","organization_id":"synthetic-org-0001","access_token":"synthetic-access-token-0001"}`
	protocolFixtureModelCachePlain = `{"models":[{"id":"synthetic-model-0001"}]}`
	protocolFixtureRuntimeInput    = `{"uid":"synthetic-user-0001","organization_id":"synthetic-org-0001","organization_tags":["synthetic-a","b"],"data_policy_agreed":true}`
	protocolFixtureOracleSize      = 297238
	protocolFixtureOracleSHA256    = "b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4"
)

var (
	protocolFixtureTags     = []string{"synthetic-a", "b"}
	protocolFixtureIdentity = fixtureOracle{Version: "1.1.34", Size: protocolFixtureOracleSize, SHA256: protocolFixtureOracleSHA256}
	protocolFixtureNames    = []string{"runtime-fields.json", "credential.json", "model-cache.json", "infer-user.json"}
)

type fixtureClock struct{}

func (fixtureClock) Now() (time.Time, error) { return time.UnixMilli(protocolFixtureUnixMilli), nil }

type fixtureEntropy struct{ next byte }

func (e *fixtureEntropy) Read(dst []byte) error {
	for i := range dst {
		e.next++
		if e.next == 0 {
			e.next = 1
		}
		dst[i] = e.next
	}
	return nil
}

type runtimeFixtureInput struct {
	Raw string `json:"raw"`
}
type runtimeFixtureExpected struct {
	Raw             string `json:"raw"`
	EncryptUserInfo string `json:"encrypt_user_info"`
	Key             string `json:"key"`
}
type credentialFixtureInput struct {
	MachineKey string `json:"machine_key"`
	Plain      string `json:"plain"`
}
type credentialFixtureExpected struct {
	Decrypted string `json:"decrypted"`
	Encrypted string `json:"encrypted"`
}
type modelCacheFixtureInput struct {
	Plain string `json:"plain"`
	UID   string `json:"uid"`
}
type modelCacheFixtureExpected struct {
	Decrypted string `json:"decrypted"`
	Encrypted string `json:"encrypted"`
}
type inferFixtureInput struct {
	MachineID   string           `json:"machine_id"`
	Version     string           `json:"version"`
	User        protocolUserInfo `json:"user"`
	Scene       protocolScene    `json:"scene"`
	Endpoint    string           `json:"endpoint"`
	BodyRaw     string           `json:"body_raw"`
	ModelKey    string           `json:"model_key"`
	ModelSource string           `json:"model_source"`
}
type inferFixtureExpected struct {
	URL        string      `json:"url"`
	Header     http.Header `json:"header"`
	BodyString string      `json:"body_string"`
	BodyBytes  []byte      `json:"body_bytes"`
}

type cosyAuthorizationPayloadForTest struct {
	Version     string `json:"version"`
	RequestID   string `json:"requestId"`
	Info        string `json:"info"`
	CosyVersion string `json:"cosyVersion"`
	IDEVersion  string `json:"ideVersion"`
}

func TestProtocolCharacterizationFixtures(t *testing.T) {
	if err := validateFixtureDirectoryInventory(protocolFixtureDir()); err != nil {
		t.Fatalf("protocol fixture directory inventory is invalid: %v", err)
	}
	manifestBytes, manifest := loadProtocolFixtureManifest(t)
	assertCanonicalFixtureJSON(t, filepath.Join(protocolFixtureDir(), "manifest.json"), manifestBytes, manifest)

	documents := make(map[string][]byte, len(protocolFixtureNames))
	fixtures := make(map[string]protocolFixture, len(protocolFixtureNames))
	for _, name := range protocolFixtureNames {
		documents[name], fixtures[name] = loadProtocolFixture(t, name)
		assertCanonicalFixtureJSON(t, filepath.Join(protocolFixtureDir(), name), documents[name], fixtures[name])
	}
	if err := verifyFixtureDocumentHashes(manifest, documents); err != nil {
		t.Fatalf("protocol fixture set integrity check failed: %v", err)
	}
	for _, name := range protocolFixtureNames {
		name := name
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			validateProtocolFixture(t, name, fixtures[name])
			replayNativeProtocolFixture(t, name, fixtures[name])
		})
	}
}

func replayNativeProtocolFixture(t *testing.T, name string, fixture protocolFixture) {
	t.Helper()
	switch name {
	case "credential.json":
		var input credentialFixtureInput
		var expected credentialFixtureExpected
		decodeExactJSON(t, fixture.Input, &input)
		decodeExactJSON(t, fixture.Expected, &expected)
		replay := newTranscriptReplay(fixture.Transcript)
		ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: replay, Entropy: replay})
		codec := nativeCredentialCodec{}
		encrypted, err := codec.Encrypt(ctx, input.Plain, input.MachineKey)
		if err != nil || encrypted != expected.Encrypted {
			t.Fatalf("native credential fixture encrypt mismatch: error kind %q", protocolErrorKindOf(err))
		}
		decrypted, err := codec.Decrypt(ctx, encrypted, input.MachineKey)
		if err != nil || decrypted != expected.Decrypted {
			t.Fatalf("native credential fixture decrypt mismatch: error kind %q", protocolErrorKindOf(err))
		}
		assertReplayExhausted(t, replay)
	case "runtime-fields.json":
		var input runtimeFixtureInput
		var expected runtimeFixtureExpected
		decodeExactJSON(t, fixture.Input, &input)
		decodeExactJSON(t, fixture.Expected, &expected)
		replay := newTranscriptReplay(fixture.Transcript)
		ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: replay, Entropy: replay})
		raw, err := generateNativeRuntimeFieldsRaw(ctx, protocolHostDeps{}, []byte(input.Raw))
		if err != nil || string(raw) != expected.Raw {
			t.Fatalf("native runtime fixture mismatch: output length %d want %d error kind %q", len(raw), len(expected.Raw), protocolErrorKindOf(err))
		}
		assertReplayExhausted(t, replay)
	case "model-cache.json":
		var input modelCacheFixtureInput
		var expected modelCacheFixtureExpected
		decodeExactJSON(t, fixture.Input, &input)
		decodeExactJSON(t, fixture.Expected, &expected)
		replay := newTranscriptReplay(fixture.Transcript)
		nonce := make([]byte, qmcNonceSize)
		if err := replay.Read(nonce); err != nil {
			t.Fatalf("native model-cache fixture nonce replay returned kind %q", protocolErrorKindOf(err))
		}
		encrypted, err := encryptQMCV1ForTest([]byte(input.Plain), input.UID, nonce)
		if err != nil || encrypted != expected.Encrypted {
			t.Fatalf("native model-cache fixture encrypt mismatch: error kind %q", protocolErrorKindOf(err))
		}
		decrypted, err := (nativeModelCacheDecryptor{}).Decrypt(context.Background(), encrypted, input.UID)
		if err != nil || string(decrypted) != expected.Decrypted {
			t.Fatalf("native model-cache fixture decrypt mismatch: error kind %q", protocolErrorKindOf(err))
		}
		assertReplayExhausted(t, replay)
	case "infer-user.json":
		replayNativeInferFixture(t, fixture)
	default:
		t.Fatalf("unknown protocol fixture %q", name)
	}
}

type fixtureHostCallKind string

const (
	fixtureHostClock   fixtureHostCallKind = "clock"
	fixtureHostEntropy fixtureHostCallKind = "entropy"
)

type fixtureHostCall struct {
	kind   fixtureHostCallKind
	length int
}

type fixtureOrderedReplay struct {
	mu       sync.Mutex
	replay   *transcriptReplay
	expected []fixtureHostCall
	observed []fixtureHostCall
	cursor   int
}

func newFixtureOrderedReplay(transcript protocolTranscript, expected []fixtureHostCall) *fixtureOrderedReplay {
	return &fixtureOrderedReplay{replay: newTranscriptReplay(transcript), expected: append([]fixtureHostCall(nil), expected...)}
}

func (r *fixtureOrderedReplay) expect(call fixtureHostCall) error {
	if r.cursor >= len(r.expected) {
		return transcriptReplayError(fmt.Errorf("fixture host call sequence exhausted at %d", r.cursor))
	}
	if want := r.expected[r.cursor]; want != call {
		return transcriptReplayError(fmt.Errorf("fixture host call %d has unexpected kind or length", r.cursor))
	}
	r.cursor++
	r.observed = append(r.observed, call)
	return nil
}

func (r *fixtureOrderedReplay) Now() (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.expect(fixtureHostCall{kind: fixtureHostClock}); err != nil {
		return time.Time{}, err
	}
	return r.replay.Now()
}

func (r *fixtureOrderedReplay) Read(dst []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.expect(fixtureHostCall{kind: fixtureHostEntropy, length: len(dst)}); err != nil {
		return err
	}
	return r.replay.Read(dst)
}

func (r *fixtureOrderedReplay) Exhausted() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cursor != len(r.expected) || !reflect.DeepEqual(r.observed, r.expected) {
		return transcriptReplayError(fmt.Errorf("fixture host call sequence consumed %d/%d", r.cursor, len(r.expected)))
	}
	return r.replay.Exhausted()
}

func fixtureEntropyCalls(transcript protocolTranscript) []fixtureHostCall {
	calls := make([]fixtureHostCall, len(transcript.EntropyReads))
	for i, read := range transcript.EntropyReads {
		calls[i] = fixtureHostCall{kind: fixtureHostEntropy, length: read.Length}
	}
	return calls
}

func replayNativeInferFixture(t *testing.T, fixture protocolFixture) {
	t.Helper()
	var input inferFixtureInput
	var expected inferFixtureExpected
	decodeExactJSON(t, fixture.Input, &input)
	decodeExactJSON(t, fixture.Expected, &expected)
	if len(fixture.Transcript.EntropyReads) != 3 || len(fixture.Transcript.UnixMilli) != 1 {
		t.Fatalf("combined infer fixture transcript shape = entropy %d clock %d", len(fixture.Transcript.EntropyReads), len(fixture.Transcript.UnixMilli))
	}
	combined := cloneProtocolTranscript(fixture.Transcript)
	newTranscript := protocolTranscript{EntropyReads: append([]entropyRead(nil), combined.EntropyReads[:2]...)}
	prepareTranscript := protocolTranscript{UnixMilli: append([]int64(nil), combined.UnixMilli...), EntropyReads: append([]entropyRead(nil), combined.EntropyReads[2:]...)}
	assertEntropyShape(t, newTranscript, 16, 109)
	assertEntropyShape(t, prepareTranscript, 16)

	newReplay := newFixtureOrderedReplay(newTranscript, fixtureEntropyCalls(newTranscript))
	factory := &nativeContextFactory{host: protocolHostDeps{Clock: fixtureClock{}, Entropy: &fixtureEntropy{}}}
	newCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: newReplay, Entropy: newReplay})
	protocolCtx, err := factory.New(newCtx, protocolContextConfig{MachineID: input.MachineID, Version: input.Version, User: input.User, Scene: input.Scene})
	if err != nil {
		t.Fatalf("native fixture context New returned kind %q", protocolErrorKindOf(err))
	}
	defer func() {
		if closeErr := protocolCtx.Close(); closeErr != nil {
			t.Errorf("native fixture context close returned kind %q", protocolErrorKindOf(closeErr))
		}
	}()
	assertReplayExhausted(t, newReplay)

	prepareCalls := append([]fixtureHostCall{{kind: fixtureHostClock}}, fixtureEntropyCalls(prepareTranscript)...)
	prepareReplay := newFixtureOrderedReplay(prepareTranscript, prepareCalls)
	prepareCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: prepareReplay, Entropy: prepareReplay})
	got, err := protocolCtx.PrepareInferRequest(prepareCtx, inferRequestInput{Endpoint: input.Endpoint, Body: []byte(input.BodyRaw), ModelKey: input.ModelKey, ModelSource: input.ModelSource})
	if err != nil {
		t.Fatalf("native fixture PrepareInferRequest returned kind %q", protocolErrorKindOf(err))
	}
	assertReplayExhausted(t, prepareReplay)
	if expected.BodyString != string(expected.BodyBytes) {
		t.Fatal("native fixture expected body representations differ")
	}
	want := &preparedRequest{URL: expected.URL, Header: expected.Header, Body: expected.BodyBytes}
	assertNativeInferPreparedExact(t, got, want)
}

func TestProtocolFixtureOrderedReplayRejectsEntropyBeforeClock(t *testing.T) {
	replay := newFixtureOrderedReplay(protocolTranscript{UnixMilli: []int64{protocolFixtureUnixMilli}, EntropyReads: []entropyRead{{Length: 1, Bytes: []byte{1}}}}, []fixtureHostCall{{kind: fixtureHostClock}, {kind: fixtureHostEntropy, length: 1}})
	if err := replay.Read(make([]byte, 1)); err == nil {
		t.Fatal("native fixture ordered replay accepted entropy before clock")
	}
}

func TestNativeInferOfficialFixtureReplay(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "infer-user.json")
	replayNativeInferFixture(t, fixture)
}

func deterministicFixtureRemoteChatAskBody(t *testing.T) string {
	t.Helper()
	system := "synthetic-system-prompt-0001"
	messages := []upMessage{{Role: "user", Content: "synthetic-user-message-0001", Contents: []upPart{{Type: "text", Text: "synthetic-user-message-0001"}}}}
	tools := []map[string]any{{
		"type": "function",
		"function": map[string]any{
			"name": "synthetic_tool_0001", "description": "synthetic tool description",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string"}}, "required": []string{"value"}},
		},
	}}
	parameters := map[string]any{"temperature": 0.25, "top_p": 0.75, "max_tokens": 321}
	model := &modelConfig{Key: "synthetic-model-0001", Format: "openai", Source: "system", Enable: true, DisplayName: "Synthetic Model", IsReasoning: false, IsVL: false, MaxInputTokens: 4096}
	encoded, err := remoteChatAskBodyWithSources(system, messages, tools, parameters, model, protocolFixtureSessionID, protocolFixtureRequestID, func() string { return protocolFixtureBusinessID }, func() int64 { return protocolFixtureBusinessMillis })
	if err != nil {
		t.Fatalf("build deterministic fixture RemoteChatAsk body: %v", err)
	}
	return string(encoded)
}

func validateProtocolFixture(t *testing.T, name string, fixture protocolFixture) {
	t.Helper()
	if !reflect.DeepEqual(fixture.Oracle, protocolFixtureIdentity) {
		t.Fatalf("fixture %s oracle identity mismatch", name)
	}
	switch name {
	case "runtime-fields.json":
		var input runtimeFixtureInput
		var raw runtimeFieldInput
		decodeExactJSON(t, fixture.Input, &input)
		decodeExactJSON(t, []byte(input.Raw), &raw)
		want := runtimeFieldInput{UID: protocolFixtureUID, OrganizationID: protocolFixtureOrg, OrganizationTags: protocolFixtureTags, DataPolicyAgreed: true}
		if input.Raw != protocolFixtureRuntimeInput || !reflect.DeepEqual(raw, want) {
			t.Fatal("runtime fixture input is outside the synthetic allowlist")
		}
		var expected runtimeFixtureExpected
		decodeExactJSON(t, fixture.Expected, &expected)
		if expected.Raw != `{"encrypt_user_info":"`+expected.EncryptUserInfo+`","key":"`+expected.Key+`"}` || expected.EncryptUserInfo == "" || expected.Key == "" {
			t.Fatal("runtime expected fields are incomplete or reordered")
		}
		assertEntropyShape(t, fixture.Transcript, 16, 109)
		if len(fixture.Transcript.UnixMilli) != 0 {
			t.Fatal("runtime fixture unexpectedly consumes clock")
		}
	case "credential.json":
		var input credentialFixtureInput
		decodeExactJSON(t, fixture.Input, &input)
		if input.MachineKey != protocolFixtureMachineKey || input.Plain != protocolFixtureCredentialPlain {
			t.Fatal("credential fixture input is outside the synthetic allowlist")
		}
		var expected credentialFixtureExpected
		decodeExactJSON(t, fixture.Expected, &expected)
		if expected.Decrypted != protocolFixtureCredentialPlain || expected.Encrypted == "" {
			t.Fatal("credential expected value is incomplete")
		}
		assertEntropyShape(t, fixture.Transcript)
		if len(fixture.Transcript.UnixMilli) != 0 {
			t.Fatal("credential fixture unexpectedly consumes clock")
		}
	case "model-cache.json":
		var input modelCacheFixtureInput
		decodeExactJSON(t, fixture.Input, &input)
		if input.UID != protocolFixtureUID || input.Plain != protocolFixtureModelCachePlain {
			t.Fatal("model-cache fixture input is outside the synthetic allowlist")
		}
		var expected modelCacheFixtureExpected
		decodeExactJSON(t, fixture.Expected, &expected)
		if expected.Decrypted != protocolFixtureModelCachePlain || expected.Encrypted == "" {
			t.Fatal("model-cache expected value is incomplete")
		}
		assertEntropyShape(t, fixture.Transcript, 12)
		if len(fixture.Transcript.UnixMilli) != 0 {
			t.Fatal("model-cache fixture unexpectedly consumes clock")
		}
	case "infer-user.json":
		var input inferFixtureInput
		decodeExactJSON(t, fixture.Input, &input)
		wantUser := protocolUserInfo{UID: protocolFixtureUID, EncryptUserInfo: input.User.EncryptUserInfo, Key: input.User.Key, OrganizationID: protocolFixtureOrg, OrganizationTags: protocolFixtureTags, DataPolicyAgreed: true}
		if input.MachineID != protocolFixtureMachineID || input.Version != qoderProtocolVersion || !reflect.DeepEqual(input.User, wantUser) || input.User.EncryptUserInfo == "" || input.User.Key == "" || !reflect.DeepEqual(input.Scene, defaultProtocolScene()) || input.Endpoint != protocolFixtureEndpoint || input.BodyRaw != deterministicFixtureRemoteChatAskBody(t) || input.ModelKey != "auto" || input.ModelSource != "system" {
			t.Fatal("infer fixture input is outside the synthetic allowlist")
		}
		var expected inferFixtureExpected
		decodeExactJSON(t, fixture.Expected, &expected)
		if expected.URL == "" || len(expected.Header) == 0 || expected.BodyString != string(expected.BodyBytes) {
			t.Fatal("infer expected output is incomplete")
		}
		assertEntropyShape(t, fixture.Transcript, 16, 109, 16)
		if !reflect.DeepEqual(fixture.Transcript.UnixMilli, []int64{protocolFixtureUnixMilli}) {
			t.Fatal("infer fixture clock transcript mismatch")
		}
	default:
		t.Fatalf("unknown fixture %q", name)
	}
}

func assertEntropyShape(t *testing.T, transcript protocolTranscript, lengths ...int) {
	t.Helper()
	got := make([]int, len(transcript.EntropyReads))
	for i, read := range transcript.EntropyReads {
		got[i] = read.Length
		if len(read.Bytes) != read.Length {
			t.Fatalf("entropy read %d byte count = %d want %d", i, len(read.Bytes), read.Length)
		}
	}
	if !reflect.DeepEqual(got, lengths) && !(len(got) == 0 && len(lengths) == 0) {
		t.Fatalf("entropy shape = %v, want %v", got, lengths)
	}
}

func assertReplayExhausted(t *testing.T, replay interface{ Exhausted() error }) {
	t.Helper()
	if err := replay.Exhausted(); err != nil {
		t.Fatalf("fixture replay not exhausted: %v (internal: %v)", err, protocolInternalError(err))
	}
}

func stableFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal canonical fixture JSON: %v", err)
	}
	return append(encoded, '\n')
}

func assertCanonicalFixtureJSON(t *testing.T, path string, encoded []byte, value any) {
	t.Helper()
	if canonical := stableFixtureJSON(t, value); !bytes.Equal(encoded, canonical) {
		t.Fatalf("fixture %s is not canonical indented JSON with one trailing LF", path)
	}
}

func decodeExactJSON(t *testing.T, encoded []byte, dst any) {
	t.Helper()
	if err := decodeStrictJSON(encoded, dst); err != nil {
		t.Fatalf("decode exact JSON: %v", err)
	}
}

func decodeStrictJSON(encoded []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func protocolFixtureDir() string {
	return filepath.Join("testdata", "protocol", protocolFixtureIdentity.Version)
}

func expectedProtocolFixtureJSONNames() map[string]struct{} {
	expected := make(map[string]struct{}, len(protocolFixtureNames)+1)
	expected["manifest.json"] = struct{}{}
	for _, name := range protocolFixtureNames {
		expected[name] = struct{}{}
	}
	return expected
}

func validateFixtureDirectoryInventory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read protocol fixture directory: %w", err)
	}
	expected := expectedProtocolFixtureJSONNames()
	present := make(map[string]struct{}, len(expected))
	var inventoryErr error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := entry.Name()
		present[name] = struct{}{}
		encoded, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil {
			inventoryErr = errors.Join(inventoryErr, fmt.Errorf("read protocol fixture %s: %w", name, readErr))
		} else if safeErr := validateFixtureEncodedSafety(name, encoded); safeErr != nil {
			inventoryErr = errors.Join(inventoryErr, safeErr)
		}
		if _, ok := expected[name]; !ok {
			inventoryErr = errors.Join(inventoryErr, fmt.Errorf("unexpected protocol fixture JSON %s", name))
		}
	}
	for name := range expected {
		if _, ok := present[name]; !ok {
			inventoryErr = errors.Join(inventoryErr, fmt.Errorf("missing expected protocol fixture JSON %s", name))
		}
	}
	return inventoryErr
}

func loadProtocolFixtureManifest(t *testing.T) ([]byte, fixtureManifest) {
	t.Helper()
	path := filepath.Join(protocolFixtureDir(), "manifest.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen protocol fixture manifest: %v", err)
	}
	if err := validateFixtureEncodedSafety(path, encoded); err != nil {
		t.Fatal(err)
	}
	assertSingleTrailingLF(t, path, encoded)
	var manifest fixtureManifest
	decodeExactJSON(t, encoded, &manifest)
	if manifest.Version != protocolFixtureIdentity.Version || manifest.Size != protocolFixtureIdentity.Size || manifest.SHA256 != protocolFixtureIdentity.SHA256 {
		t.Fatal("frozen fixture manifest oracle identity mismatch")
	}
	if len(manifest.Documents) != len(protocolFixtureNames) {
		t.Fatalf("manifest document hash count = %d, want %d", len(manifest.Documents), len(protocolFixtureNames))
	}
	return encoded, manifest
}

func verifyFixtureDocumentHashes(manifest fixtureManifest, documents map[string][]byte) error {
	if len(manifest.Documents) != len(protocolFixtureNames) {
		return fmt.Errorf("manifest document hash count = %d, want %d", len(manifest.Documents), len(protocolFixtureNames))
	}
	for _, name := range protocolFixtureNames {
		want, ok := manifest.Documents[name]
		if !ok {
			return fmt.Errorf("manifest lacks SHA-256 for %s", name)
		}
		sum := sha256.Sum256(documents[name])
		if got := hex.EncodeToString(sum[:]); got != want {
			return fmt.Errorf("%s SHA-256 mismatch", name)
		}
	}
	return nil
}

func loadProtocolFixture(t *testing.T, name string) ([]byte, protocolFixture) {
	t.Helper()
	path := filepath.Join(protocolFixtureDir(), name)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen protocol fixture %s: %v", name, err)
	}
	if err := validateFixtureEncodedSafety(name, encoded); err != nil {
		t.Fatal(err)
	}
	assertSingleTrailingLF(t, path, encoded)
	var fixture protocolFixture
	decodeExactJSON(t, encoded, &fixture)
	return encoded, fixture
}

func validateFixtureEncodedSafety(path string, encoded []byte) error {
	for _, forbidden := range []string{
		"/home/", "/Users/", "/root/", "\\Users\\", `C:\\Users\\`, ".qoder", "re/secrets", "SENTINEL-PROTOCOL-SECRET",
		"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "AKIA", "github_pat_", "ghp_", "xoxb-",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			return fmt.Errorf("fixture %s contains a forbidden marker", path)
		}
	}
	return nil
}

func assertSingleTrailingLF(t *testing.T, path string, encoded []byte) {
	t.Helper()
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' || (len(encoded) > 1 && encoded[len(encoded)-2] == '\n') || bytes.Contains(encoded, []byte("\r\n")) {
		t.Fatalf("fixture %s must use LF and end in exactly one LF", path)
	}
}

func TestProtocolFixtureSecurityScan(t *testing.T) {
	if err := validateFixtureDirectoryInventory(protocolFixtureDir()); err != nil {
		t.Fatalf("protocol fixture directory inventory/security scan failed: %v", err)
	}
	_, manifest := loadProtocolFixtureManifest(t)
	documents := make(map[string][]byte, len(protocolFixtureNames))
	for _, name := range protocolFixtureNames {
		encoded, fixture := loadProtocolFixture(t, name)
		documents[name] = encoded
		validateProtocolFixture(t, name, fixture)
	}
	if err := verifyFixtureDocumentHashes(manifest, documents); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolFixtureSafetyRejectsCrossPlatformPathsAndSecretMarkers(t *testing.T) {
	bad := []string{`{"path":"/Users/alice/.config"}`, `{"path":"/root/key"}`, `{"path":"C:\\Users\\alice"}`, `{"key":"-----BEGIN PRIVATE KEY-----"}`, `{"token":"github_pat_real"}`}
	for index, encoded := range bad {
		if err := validateFixtureEncodedSafety("synthetic.json", []byte(encoded)); err == nil {
			t.Fatalf("unsafe synthetic marker case %d was accepted", index)
		}
	}
}

func TestProtocolFixtureManifestDetectsMixedSet(t *testing.T) {
	_, manifest := loadProtocolFixtureManifest(t)
	documents := make(map[string][]byte, len(protocolFixtureNames))
	for _, name := range protocolFixtureNames {
		documents[name], _ = loadProtocolFixture(t, name)
	}
	changed := append([]byte(nil), documents["credential.json"]...)
	changed[len(changed)-2] ^= 1
	documents["credential.json"] = changed
	if err := verifyFixtureDocumentHashes(manifest, documents); err == nil || !strings.Contains(err.Error(), "credential.json") {
		t.Fatalf("mixed frozen fixture set was not detected: %v", err)
	}
}

func TestProtocolFixtureGitAttributes(t *testing.T) {
	encoded, err := os.ReadFile(".gitattributes")
	if err != nil {
		t.Fatalf("read .gitattributes: %v", err)
	}
	if !bytes.Contains(encoded, []byte("testdata/protocol/**/*.json text eol=lf")) {
		t.Fatal(".gitattributes lacks protocol fixture LF rule")
	}
}

func TestProtocolInferFixtureUsesDeterministicRemoteChatAskBuilder(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "infer-user.json")
	var input inferFixtureInput
	decodeExactJSON(t, fixture.Input, &input)
	if input.BodyRaw != deterministicFixtureRemoteChatAskBody(t) {
		t.Fatal("infer fixture raw body differs from deterministic builder")
	}
	var body map[string]json.RawMessage
	decodeExactJSON(t, []byte(input.BodyRaw), &body)
	for _, key := range []string{"business", "session_type", "messages", "system", "tools", "parameters", "model_config"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("infer fixture RemoteChatAsk body lacks %q", key)
		}
	}
}

func TestProtocolFixtureConstantsAreSynthetic(t *testing.T) {
	if protocolFixtureUID != "synthetic-user-0001" || protocolFixtureOrg != "synthetic-org-0001" || !reflect.DeepEqual(protocolFixtureTags, []string{"synthetic-a", "b"}) {
		t.Fatal("fixture identity/tags differ from synthetic allowlist")
	}
	if protocolFixtureMachineID != "00000000-1111-4222-8333-444444444444" || protocolFixtureMachineKey != protocolFixtureMachineID[:16] {
		t.Fatal("fixture machine identity/key mismatch")
	}
	if protocolFixtureEndpoint != "https://example.invalid/base" || protocolFixtureIdentity.Version != qoderProtocolVersion {
		t.Fatal("fixture endpoint/version mismatch")
	}
	if !json.Valid([]byte(deterministicFixtureRemoteChatAskBody(t))) {
		t.Fatal("fixture RemoteChatAsk body is invalid raw JSON")
	}
}
