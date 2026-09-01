package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"sync"
	"testing"
)

const (
	comparisonWASMEnv     = "QODER2API_BENCH_WASM"
	comparisonFixturesEnv = "QODER2API_BENCH_FIXTURES"
)

type comparisonRuntimeSemanticInput struct {
	UID              string   `json:"uid"`
	OrganizationID   string   `json:"organization_id"`
	OrganizationTags []string `json:"organization_tags"`
	DataPolicyAgreed bool     `json:"data_policy_agreed"`
}

type comparisonRuntimeSemanticOutput struct {
	EncryptUserInfo string `json:"encrypt_user_info"`
	Key             string `json:"key"`
}

type comparisonProtocolUser struct {
	UID              string   `json:"uid"`
	EncryptUserInfo  string   `json:"encrypt_user_info"`
	Key              string   `json:"key"`
	OrganizationID   string   `json:"organization_id"`
	OrganizationTags []string `json:"organization_tags"`
	DataPolicyAgreed bool     `json:"data_policy_agreed"`
}

type comparisonProtocolScene struct {
	ClientType      string `json:"client_type"`
	BusinessProduct string `json:"business_product"`
	BusinessType    string `json:"business_type"`
	Scene           string `json:"scene"`
}

type wasmComparisonFixture struct {
	source            []byte
	credential        credentialInput
	runtimeInput      comparisonRuntimeSemanticInput
	runtimeTranscript transcript
	model             modelInput
	modelExpected     modelExpected
	infer             inferInput
	user              comparisonProtocolUser
	scene             comparisonProtocolScene
	newTranscript     transcript
	newCalls          []hostCall
	prepareTranscript transcript
	prepareCalls      []hostCall
}

func splitComparisonInferTranscript(value transcript) (transcript, []hostCall, transcript, []hostCall, error) {
	if len(value.UnixMilli) != 1 ||
		len(value.EntropyReads) != 3 ||
		value.EntropyReads[0].Length != 16 ||
		value.EntropyReads[1].Length != 109 ||
		value.EntropyReads[2].Length != 16 {
		return transcript{}, nil, transcript{}, nil, fail("infer-transcript-shape")
	}
	newTranscript := transcript{
		EntropyReads: []entropyRead{
			{Length: 16, Bytes: append([]byte(nil), value.EntropyReads[0].Bytes...)},
			{Length: 109, Bytes: append([]byte(nil), value.EntropyReads[1].Bytes...)},
		},
	}
	newCalls := []hostCall{
		{Kind: hostEntropy, Length: 16},
		{Kind: hostEntropy, Length: 109},
	}
	prepareTranscript := transcript{
		UnixMilli: append([]int64(nil), value.UnixMilli...),
		EntropyReads: []entropyRead{
			{Length: 16, Bytes: append([]byte(nil), value.EntropyReads[2].Bytes...)},
		},
	}
	prepareCalls := []hostCall{
		{Kind: hostClock},
		{Kind: hostEntropy, Length: 16},
	}
	return newTranscript, newCalls, prepareTranscript, prepareCalls, nil
}

func resetComparisonReplay(replay *orderedReplay) {
	replay.orderCursor = 0
	replay.timeCursor = 0
	replay.entropyCursor = 0
}

func TestComparisonInferTranscriptsSplitNewAndPrepare(t *testing.T) {
	input := transcript{
		UnixMilli: []int64{1234},
		EntropyReads: []entropyRead{
			{Length: 16, Bytes: make([]byte, 16)},
			{Length: 109, Bytes: make([]byte, 109)},
			{Length: 16, Bytes: make([]byte, 16)},
		},
	}
	newTranscript, newCalls, prepareTranscript, prepareCalls, err := splitComparisonInferTranscript(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(newTranscript.EntropyReads) != 2 || len(newCalls) != 2 {
		t.Fatal("new transcript shape mismatch")
	}
	if len(prepareTranscript.UnixMilli) != 1 || len(prepareTranscript.EntropyReads) != 1 || len(prepareCalls) != 2 {
		t.Fatal("prepare transcript shape mismatch")
	}
}

func BenchmarkCompareWASM(b *testing.B) {
	fixture := loadWASMComparisonFixture(b)
	b.Run("ColdStart", benchmarkWASMComparisonColdStart(fixture))

	ctx := context.Background()
	backend, err := newWASMBackend(ctx, fixture.source)
	if err != nil {
		b.Fatal("comparison WASM construction failed")
	}
	defer func() {
		if err := backend.Close(ctx); err != nil {
			b.Error("comparison WASM cleanup failed")
		}
	}()

	b.Run("CredentialRoundTrip", benchmarkWASMComparisonCredential(fixture, backend))
	b.Run("RuntimeFields", benchmarkWASMComparisonRuntime(fixture, backend))
	b.Run("ModelCacheDecrypt", benchmarkWASMComparisonModelCache(fixture, backend))
	b.Run("ContextNew", benchmarkWASMComparisonContextNew(fixture, backend))

	inferContext := newWASMComparisonInferContext(b, fixture, backend)
	defer func() {
		if err := backend.freeContext(ctx, inferContext); err != nil {
			b.Error("comparison infer context cleanup failed")
		}
	}()
	b.Run("InferHot", benchmarkWASMComparisonInfer(fixture, backend, inferContext))
}

func loadWASMComparisonFixture(b *testing.B) wasmComparisonFixture {
	b.Helper()
	wasmPath := os.Getenv(comparisonWASMEnv)
	fixturePath := os.Getenv(comparisonFixturesEnv)
	if wasmPath == "" || fixturePath == "" {
		b.Fatal("comparison benchmark inputs are unavailable")
	}
	source, err := readBoundedRegularFile(wasmPath, pinnedWASMSize, "wasm-read")
	if err == nil {
		err = validateWASM(source)
	}
	if err != nil {
		b.Fatal("comparison WASM identity is invalid")
	}
	fixtures, err := validateFixtureSet(fixturePath, pinnedPolicy())
	if err != nil {
		b.Fatal("comparison fixture set is invalid")
	}
	credential, err := mustDecode[credentialInput](fixtures["credential.json"].Input)
	if err != nil {
		b.Fatal("comparison credential fixture is invalid")
	}
	runtimeWire, err := mustDecode[runtimeInput](fixtures["runtime-fields.json"].Input)
	if err != nil {
		b.Fatal("comparison runtime fixture is invalid")
	}
	var runtimeInput comparisonRuntimeSemanticInput
	if err := json.Unmarshal([]byte(runtimeWire.Raw), &runtimeInput); err != nil {
		b.Fatal("comparison runtime semantic input is invalid")
	}
	model, err := mustDecode[modelInput](fixtures["model-cache.json"].Input)
	if err != nil {
		b.Fatal("comparison model-cache fixture is invalid")
	}
	modelExpected, err := mustDecode[modelExpected](fixtures["model-cache.json"].Expected)
	if err != nil {
		b.Fatal("comparison model-cache output is invalid")
	}
	infer, err := mustDecode[inferInput](fixtures["infer-user.json"].Input)
	if err != nil {
		b.Fatal("comparison infer fixture is invalid")
	}
	var user comparisonProtocolUser
	if err := json.Unmarshal(infer.User, &user); err != nil {
		b.Fatal("comparison infer user is invalid")
	}
	var scene comparisonProtocolScene
	if err := json.Unmarshal(infer.Scene, &scene); err != nil {
		b.Fatal("comparison infer scene is invalid")
	}
	newTranscript, newCalls, prepareTranscript, prepareCalls, err := splitComparisonInferTranscript(fixtures["infer-user.json"].Transcript)
	if err != nil {
		b.Fatal("comparison infer transcript is invalid")
	}
	return wasmComparisonFixture{
		source:            source,
		credential:        credential,
		runtimeInput:      runtimeInput,
		runtimeTranscript: fixtures["runtime-fields.json"].Transcript,
		model:             model,
		modelExpected:     modelExpected,
		infer:             infer,
		user:              user,
		scene:             scene,
		newTranscript:     newTranscript,
		newCalls:          newCalls,
		prepareTranscript: prepareTranscript,
		prepareCalls:      prepareCalls,
	}
}

func benchmarkWASMComparisonColdStart(fixture wasmComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			backend, err := newWASMBackend(ctx, fixture.source)
			if err != nil {
				b.Fatal("WASM cold-start construction failed")
			}
			if err := backend.Close(ctx); err != nil {
				b.Fatal("WASM cold-start cleanup failed")
			}
			runtime.KeepAlive(backend)
		}
	}
}

func benchmarkWASMComparisonCredential(fixture wasmComparisonFixture, backend *wasmBackend) func(*testing.B) {
	return func(b *testing.B) {
		ctx := context.Background()
		var operationMu sync.Mutex
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			operationMu.Lock()
			encrypted, err := backend.callString(ctx, "credential_storage_encrypt", fixture.credential.Plain, fixture.credential.MachineKey)
			if err == nil {
				var decrypted string
				decrypted, err = backend.callString(ctx, "credential_storage_decrypt", encrypted, fixture.credential.MachineKey)
				if err == nil && decrypted != fixture.credential.Plain {
					err = fail("credential-output")
				}
				runtime.KeepAlive(decrypted)
			}
			operationMu.Unlock()
			if err != nil {
				b.Fatal("WASM credential round trip failed")
			}
		}
	}
}

func benchmarkWASMComparisonRuntime(fixture wasmComparisonFixture, backend *wasmBackend) func(*testing.B) {
	return func(b *testing.B) {
		ctx := context.Background()
		replay := newOrderedReplay(fixture.runtimeTranscript, entropyCalls(fixture.runtimeTranscript))
		var operationMu sync.Mutex
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			raw, err := json.Marshal(fixture.runtimeInput)
			if err != nil {
				b.Fatal("WASM runtime input encoding failed")
			}
			operationMu.Lock()
			resetComparisonReplay(replay)
			backend.setReplay(replay)
			outputRaw, err := backend.callString(ctx, "generate_runtime_auth_fields", string(raw))
			operationMu.Unlock()
			if err != nil {
				b.Fatal("WASM runtime-fields generation failed")
			}
			var output comparisonRuntimeSemanticOutput
			if err := json.Unmarshal([]byte(outputRaw), &output); err != nil || output.EncryptUserInfo == "" || output.Key == "" {
				b.Fatal("WASM runtime-fields output is invalid")
			}
			runtime.KeepAlive(output)
		}
	}
}

func benchmarkWASMComparisonModelCache(fixture wasmComparisonFixture, backend *wasmBackend) func(*testing.B) {
	return func(b *testing.B) {
		ctx := context.Background()
		var operationMu sync.Mutex
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			operationMu.Lock()
			decrypted, err := backend.callString(ctx, "model_cache_decrypt", fixture.modelExpected.Encrypted, fixture.model.UID)
			operationMu.Unlock()
			if err != nil || decrypted != fixture.modelExpected.Decrypted {
				b.Fatal("WASM model-cache decrypt failed")
			}
			plain := append([]byte(nil), decrypted...)
			runtime.KeepAlive(plain)
		}
	}
}

func benchmarkWASMComparisonContextNew(fixture wasmComparisonFixture, backend *wasmBackend) func(*testing.B) {
	return func(b *testing.B) {
		ctx := context.Background()
		replay := newOrderedReplay(fixture.newTranscript, fixture.newCalls)
		var operationMu sync.Mutex
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userJSON, err := json.Marshal(fixture.user)
			if err != nil {
				b.Fatal("WASM context user encoding failed")
			}
			sceneJSON, err := json.Marshal(fixture.scene)
			if err != nil {
				b.Fatal("WASM context scene encoding failed")
			}
			operationMu.Lock()
			resetComparisonReplay(replay)
			backend.setReplay(replay)
			ptr, err := backend.newContext(ctx, fixture.infer.MachineID, fixture.infer.Version, string(userJSON), string(sceneJSON))
			if err == nil {
				err = backend.freeContext(ctx, ptr)
			}
			operationMu.Unlock()
			if err != nil {
				b.Fatal("WASM context construction failed")
			}
			runtime.KeepAlive(ptr)
		}
	}
}

func newWASMComparisonInferContext(b *testing.B, fixture wasmComparisonFixture, backend *wasmBackend) uint32 {
	b.Helper()
	userJSON, err := json.Marshal(fixture.user)
	if err != nil {
		b.Fatal("WASM infer user encoding failed")
	}
	sceneJSON, err := json.Marshal(fixture.scene)
	if err != nil {
		b.Fatal("WASM infer scene encoding failed")
	}
	newReplay := newOrderedReplay(fixture.newTranscript, fixture.newCalls)
	backend.setReplay(newReplay)
	ptr, err := backend.newContext(context.Background(), fixture.infer.MachineID, fixture.infer.Version, string(userJSON), string(sceneJSON))
	if err != nil {
		b.Fatal("WASM infer context construction failed")
	}
	return ptr
}

func benchmarkWASMComparisonInfer(fixture wasmComparisonFixture, backend *wasmBackend, ptr uint32) func(*testing.B) {
	return func(b *testing.B) {
		ctx := context.Background()
		body := []byte(fixture.infer.BodyRaw)
		prepareReplay := newOrderedReplay(fixture.prepareTranscript, fixture.prepareCalls)
		var operationMu sync.Mutex
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			operationMu.Lock()
			resetComparisonReplay(prepareReplay)
			backend.setReplay(prepareReplay)
			output, err := backend.prepareInfer(ctx, ptr, fixture.infer.Endpoint, string(body), fixture.infer.ModelKey, fixture.infer.ModelSource)
			operationMu.Unlock()
			if err != nil {
				b.Fatal("WASM infer preparation failed")
			}
			header := make(http.Header, len(output.Headers))
			for key, value := range output.Headers {
				header.Set(key, value)
			}
			prepared := struct {
				URL    string
				Header http.Header
				Body   []byte
			}{
				URL:    output.URL,
				Header: header,
				Body:   append([]byte(nil), output.Body...),
			}
			if prepared.URL == "" || len(prepared.Header) == 0 || len(prepared.Body) == 0 {
				b.Fatal("WASM infer output is invalid")
			}
			runtime.KeepAlive(prepared)
		}
	}
}
