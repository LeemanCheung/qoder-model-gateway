package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	nativeStressOperations             = 10_000
	nativeStressShortRuntimeOperations = 32
	nativeStressShortPrepareOperations = 256
	nativeStressShortCloseOperations   = 128
)

type nativeStressClock struct {
	now time.Time
}

func (c nativeStressClock) Now() (time.Time, error) {
	return c.now, nil
}

type nativeStressPrepareCategory uint8

const (
	nativeStressPrepareComplete nativeStressPrepareCategory = iota
	nativeStressPrepareOperationError
	nativeStressPrepareNilRequest
	nativeStressPrepareURL
	nativeStressPrepareBody
	nativeStressPrepareHeaderCount
	nativeStressPrepareHeaderValues
	nativeStressPrepareHostShape
	nativeStressPrepareAuthorizationEnvelope
	nativeStressPrepareRequestIDMismatch
	nativeStressPrepareDuplicateRequestID
	nativeStressPrepareCategoryCount
)

type nativeStressPrepareResult struct {
	category  nativeStressPrepareCategory
	requestID string
}

type nativeStressEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *nativeStressEventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *nativeStressEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type nativeStressOrderedContext struct {
	name   string
	inner  protocolContext
	events *nativeStressEventLog
}

func (c *nativeStressOrderedContext) PrepareInferRequest(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	return c.inner.PrepareInferRequest(ctx, input)
}

func (c *nativeStressOrderedContext) Close() error {
	c.events.add(c.name + "-close")
	return c.inner.Close()
}

func TestNativeRuntimeFieldsStress(t *testing.T) {
	runNativeRuntimeFieldsStress(t)
}

func TestNativePrepareStress(t *testing.T) {
	runNativePrepareStress(t)
}

func TestNativeContextRebuildStress(t *testing.T) {
	runNativeContextRebuildStress(t)
}

func TestNativeRepeatedCloseStress(t *testing.T) {
	runNativeRepeatedCloseStress(t)
}

func TestNativeStressRequestIDExtraction(t *testing.T) {
	entropy := nativeStressInferEntropy(7)
	want, err := nativeInferRequestID(entropy)
	if err != nil {
		t.Fatal("native stress request-ID setup failed")
	}
	_, payload, err := nativeInferPayload(want, "synthetic-info", qoderProtocolVersion)
	if err != nil {
		t.Fatal("native stress authorization setup failed")
	}
	got, ok := nativeStressAuthorizationRequestID("Bearer COSY." + payload + ".synthetic-signature")
	if !ok || got != want {
		t.Fatal("native stress request-ID extraction failed")
	}
	if _, ok := nativeStressAuthorizationRequestID("synthetic-invalid"); ok {
		t.Fatal("native stress request-ID extraction accepted malformed authorization")
	}
}

func runNativeRuntimeFieldsStress(t *testing.T) {
	operations := nativeStressOperations
	if testing.Short() {
		operations = nativeStressShortRuntimeOperations
	}
	generator := &nativeRuntimeFieldGenerator{host: nativeStressStableHost()}
	input := runtimeFieldInput{
		UID:              "synthetic-native-stress-user",
		OrganizationID:   "synthetic-native-stress-org",
		OrganizationTags: []string{"synthetic-native-stress-tag"},
		DataPolicyAgreed: true,
	}
	operationErrors := 0
	incompleteOutputs := 0
	shapeErrors := 0
	nondeterministicOutputs := 0
	duplicateOutputs := 0
	outputs := make(map[string]struct{}, operations)
	for operation := 0; operation < operations; operation++ {
		firstEntropy := &fixedProtocolEntropy{reads: nativeStressRuntimeEntropyReads(operation)}
		firstClock := &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)}
		firstCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: firstClock, Entropy: firstEntropy})
		first, firstErr := generator.Generate(firstCtx, input)

		secondEntropy := &fixedProtocolEntropy{reads: nativeStressRuntimeEntropyReads(operation)}
		secondClock := &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)}
		secondCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: secondClock, Entropy: secondEntropy})
		second, secondErr := generator.Generate(secondCtx, input)
		if firstErr != nil || secondErr != nil {
			operationErrors++
			continue
		}
		if first.EncryptUserInfo == "" || first.Key == "" || second.EncryptUserInfo == "" || second.Key == "" {
			incompleteOutputs++
		}
		firstClockCalls, _ := firstClock.counts()
		secondClockCalls, _ := secondClock.counts()
		if firstEntropy.next != 2 || secondEntropy.next != 2 || firstClockCalls != 0 || secondClockCalls != 0 {
			shapeErrors++
		}
		if first != second {
			nondeterministicOutputs++
			continue
		}
		identity := first.EncryptUserInfo + "\x00" + first.Key
		if _, duplicate := outputs[identity]; duplicate {
			duplicateOutputs++
			continue
		}
		outputs[identity] = struct{}{}
	}
	if operationErrors != 0 || incompleteOutputs != 0 || shapeErrors != 0 || nondeterministicOutputs != 0 || duplicateOutputs != 0 || len(outputs) != operations {
		t.Fatalf(
			"native runtime stress categories operation_error=%d incomplete=%d host_shape=%d nondeterministic=%d duplicate=%d complete=%d total=%d",
			operationErrors,
			incompleteOutputs,
			shapeErrors,
			nondeterministicOutputs,
			duplicateOutputs,
			len(outputs),
			operations,
		)
	}
}

func nativeStressRuntimeEntropyReads(operation int) [][]byte {
	uuidEntropy := make([]byte, 16)
	for index := range uuidEntropy {
		uuidEntropy[index] = byte((operation+index)%255 + 1)
	}
	binary.BigEndian.PutUint64(uuidEntropy[8:], uint64(operation+1))
	paddingEntropy := make([]byte, 109)
	for index := range paddingEntropy {
		paddingEntropy[index] = byte((operation+index)%255 + 1)
	}
	return [][]byte{uuidEntropy, paddingEntropy}
}

func runNativePrepareStress(t *testing.T) {
	operations := nativeStressOperations
	if testing.Short() {
		operations = nativeStressShortPrepareOperations
	}
	nativeCtx := newNativeStressContext(t, nil)
	defer func() {
		if err := nativeCtx.Close(); err != nil {
			t.Errorf("native prepare stress cleanup failed: category=context-close")
		}
	}()
	input := inferRequestInput{
		Endpoint:    "https://example.invalid/native-stress",
		Body:        []byte(`{"synthetic":"native-stress"}`),
		ModelKey:    "synthetic-native-stress-model",
		ModelSource: "synthetic-native-stress-source",
	}
	expectedBody, err := (nativeBodyCodec{}).Encode(input.Body)
	if err != nil {
		t.Fatal("native prepare stress setup failed: category=body-encode")
	}
	expectedURL := nativeInferURL(input.Endpoint)
	results := make([]nativeStressPrepareResult, operations)
	start := make(chan struct{})
	var ready sync.WaitGroup
	var workers sync.WaitGroup
	ready.Add(operations)
	workers.Add(operations)
	for operation := 0; operation < operations; operation++ {
		operation := operation
		go func() {
			defer workers.Done()
			ready.Done()
			<-start
			results[operation] = runNativeStressPrepareOperation(nativeCtx, input, expectedURL, expectedBody, operation)
		}()
	}
	ready.Wait()
	close(start)
	workers.Wait()

	var categories [nativeStressPrepareCategoryCount]int
	requestIDs := make(map[string]struct{}, operations)
	for _, result := range results {
		if result.category != nativeStressPrepareComplete {
			categories[result.category]++
			continue
		}
		if _, duplicate := requestIDs[result.requestID]; duplicate {
			categories[nativeStressPrepareDuplicateRequestID]++
			continue
		}
		requestIDs[result.requestID] = struct{}{}
		categories[nativeStressPrepareComplete]++
	}
	if categories[nativeStressPrepareComplete] != operations {
		t.Fatalf(
			"native prepare stress categories complete=%d operation_error=%d nil=%d url=%d body=%d header_count=%d header_values=%d host_shape=%d authorization_envelope=%d request_id_mismatch=%d duplicate_request_id=%d total=%d",
			categories[nativeStressPrepareComplete],
			categories[nativeStressPrepareOperationError],
			categories[nativeStressPrepareNilRequest],
			categories[nativeStressPrepareURL],
			categories[nativeStressPrepareBody],
			categories[nativeStressPrepareHeaderCount],
			categories[nativeStressPrepareHeaderValues],
			categories[nativeStressPrepareHostShape],
			categories[nativeStressPrepareAuthorizationEnvelope],
			categories[nativeStressPrepareRequestIDMismatch],
			categories[nativeStressPrepareDuplicateRequestID],
			operations,
		)
	}
}

func runNativeStressPrepareOperation(nativeCtx *nativeProtocolContext, input inferRequestInput, expectedURL string, expectedBody []byte, operation int) nativeStressPrepareResult {
	entropy := nativeStressInferEntropy(operation)
	now := time.Unix(protocolFixtureUnixMilli/1000, 0)
	host := &nativeInferOrderedHost{now: now, entropy: entropy}
	ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: host, Entropy: host})
	prepared, err := nativeCtx.PrepareInferRequest(ctx, input)
	if err != nil {
		return nativeStressPrepareResult{category: nativeStressPrepareOperationError}
	}
	if prepared == nil {
		return nativeStressPrepareResult{category: nativeStressPrepareNilRequest}
	}
	if prepared.URL != expectedURL {
		return nativeStressPrepareResult{category: nativeStressPrepareURL}
	}
	if len(prepared.Body) == 0 || !bytes.Equal(prepared.Body, expectedBody) {
		return nativeStressPrepareResult{category: nativeStressPrepareBody}
	}
	if len(prepared.Header) != 22 {
		return nativeStressPrepareResult{category: nativeStressPrepareHeaderCount}
	}
	authorization := prepared.Header.Get("Authorization")
	if !stringsHasPrefixBearerCOSY(authorization) ||
		prepared.Header.Get("Cosy-Date") != strconv.FormatInt(now.Unix(), 10) ||
		prepared.Header.Get("X-Model-Key") != input.ModelKey ||
		prepared.Header.Get("X-Model-Source") != input.ModelSource {
		return nativeStressPrepareResult{category: nativeStressPrepareHeaderValues}
	}
	events, readLengths := host.transcriptShape()
	if !slices.Equal(events, []string{"clock", "entropy"}) || !slices.Equal(readLengths, []int{16}) {
		return nativeStressPrepareResult{category: nativeStressPrepareHostShape}
	}
	requestID, ok := nativeStressAuthorizationRequestID(authorization)
	if !ok {
		return nativeStressPrepareResult{category: nativeStressPrepareAuthorizationEnvelope}
	}
	expectedRequestID, err := nativeInferRequestID(entropy)
	if err != nil || requestID != expectedRequestID {
		return nativeStressPrepareResult{category: nativeStressPrepareRequestIDMismatch}
	}
	return nativeStressPrepareResult{category: nativeStressPrepareComplete, requestID: requestID}
}

func stringsHasPrefixBearerCOSY(value string) bool {
	const prefix = "Bearer COSY."
	return len(value) > len(prefix) && value[:len(prefix)] == prefix
}

func nativeStressAuthorizationRequestID(authorization string) (string, bool) {
	const prefix = "Bearer COSY."
	if !strings.HasPrefix(authorization, prefix) {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(authorization, prefix), ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var payload nativeInferAuthorizationPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.RequestID == "" {
		return "", false
	}
	return payload.RequestID, true
}

func nativeStressInferEntropy(operation int) []byte {
	entropy := make([]byte, 16)
	copy(entropy, []byte("NSTRESS!"))
	binary.BigEndian.PutUint64(entropy[8:], uint64(operation+1))
	return entropy
}

func runNativeContextRebuildStress(t *testing.T) {
	events := &nativeStressEventLog{}
	oldStarted := make(chan struct{})
	oldRelease := make(chan struct{})
	newStarted := make(chan struct{})
	newRelease := make(chan struct{})
	var oldStartOnce sync.Once
	var oldReleaseOnce sync.Once
	var newStartOnce sync.Once
	var newReleaseOnce sync.Once
	releaseOld := func() { oldReleaseOnce.Do(func() { close(oldRelease) }) }
	releaseNew := func() { newReleaseOnce.Do(func() { close(newRelease) }) }
	defer releaseOld()
	defer releaseNew()

	oldNative := newNativeStressContext(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
		events.add("old-prepare-start")
		oldStartOnce.Do(func() { close(oldStarted) })
		<-oldRelease
		events.add("old-prepare-finish")
		return &preparedRequest{URL: "https://example.invalid/old", Header: make(http.Header), Body: []byte("synthetic-old")}, nil
	})
	newNative := newNativeStressContext(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
		events.add("new-prepare-start")
		newStartOnce.Do(func() { close(newStarted) })
		<-newRelease
		events.add("new-prepare-finish")
		return &preparedRequest{URL: "https://example.invalid/new", Header: make(http.Header), Body: []byte("synthetic-new")}, nil
	})
	manager := &authManager{
		protoCtx: &nativeStressOrderedContext{name: "old", inner: oldNative, events: events},
		logf:     func(string, ...any) {},
	}
	replacement := &nativeStressOrderedContext{name: "new", inner: newNative, events: events}

	prepareDone := make(chan error, 1)
	go func() {
		_, err := manager.prepareWithCurrentContext(context.Background(), inferRequestInput{})
		prepareDone <- err
	}()
	<-oldStarted

	replaceDone := make(chan error, 1)
	go func() {
		replaceDone <- manager.replaceContext(replacement)
	}()
	waitForAuthContextWriter(t, manager)
	select {
	case <-replaceDone:
		t.Fatal("native context rebuild ordering failed: category=replaced-during-prepare")
	default:
	}
	releaseOld()
	if err := <-prepareDone; err != nil {
		t.Fatal("native context rebuild ordering failed: category=old-prepare")
	}
	if err := <-replaceDone; err != nil {
		t.Fatal("native context rebuild ordering failed: category=replace")
	}
	newPrepareDone := make(chan error, 1)
	go func() {
		_, err := manager.prepareWithCurrentContext(context.Background(), inferRequestInput{})
		newPrepareDone <- err
	}()
	<-newStarted

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- manager.Close()
	}()
	waitForAuthContextWriter(t, manager)
	select {
	case <-closeDone:
		t.Fatal("native context rebuild ordering failed: category=closed-during-prepare")
	default:
	}
	releaseNew()
	if err := <-newPrepareDone; err != nil {
		t.Fatal("native context rebuild ordering failed: category=new-prepare")
	}
	if err := <-closeDone; err != nil {
		t.Fatal("native context rebuild ordering failed: category=manager-close")
	}
	if _, err := manager.prepareWithCurrentContext(context.Background(), inferRequestInput{}); protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatal("native context rebuild ordering failed: category=prepare-after-close")
	}
	want := []string{"old-prepare-start", "old-prepare-finish", "old-close", "new-prepare-start", "new-prepare-finish", "new-close"}
	if !slices.Equal(events.snapshot(), want) {
		t.Fatal("native context rebuild ordering failed: category=event-order")
	}
}

func runNativeRepeatedCloseStress(t *testing.T) {
	operations := nativeStressOperations
	if testing.Short() {
		operations = nativeStressShortCloseOperations
	}
	services, err := newNativeProtocolServices(nativeStressStableHost())
	if err != nil || services == nil {
		t.Fatal("native repeated close stress setup failed: category=services")
	}
	contextOne, err := services.contextFactory.New(context.Background(), validNativeContextConfig([]string{"synthetic-close-one"}))
	if err != nil || contextOne == nil {
		t.Fatal("native repeated close stress setup failed: category=context-one")
	}
	for operation := 0; operation < operations; operation++ {
		if err := contextOne.Close(); err != nil {
			t.Fatal("native repeated close stress failed: category=context-close")
		}
	}
	contextTwo, err := services.contextFactory.New(context.Background(), validNativeContextConfig([]string{"synthetic-close-two"}))
	if err != nil || contextTwo == nil {
		t.Fatal("native repeated close stress setup failed: category=context-two")
	}
	manager := &authManager{protoCtx: contextTwo, logf: func(string, ...any) {}}
	for operation := 0; operation < operations; operation++ {
		if err := manager.Close(); err != nil {
			t.Fatal("native repeated close stress failed: category=auth-close")
		}
	}
	for operation := 0; operation < operations; operation++ {
		if err := services.Close(context.Background()); err != nil {
			t.Fatal("native repeated close stress failed: category=services-close")
		}
	}
	if _, err := contextOne.PrepareInferRequest(context.Background(), inferRequestInput{}); protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatal("native repeated close stress failed: category=context-not-closed")
	}
	if _, err := manager.prepareWithCurrentContext(context.Background(), inferRequestInput{}); protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatal("native repeated close stress failed: category=auth-not-closed")
	}
}

func nativeStressStableHost() protocolHostDeps {
	return protocolHostDeps{
		Clock:   nativeStressClock{now: time.UnixMilli(protocolFixtureUnixMilli)},
		Entropy: repeatedByteEntropy(0x5a),
	}
}

func newNativeStressContext(tb testing.TB, prepare nativePrepareFunc) *nativeProtocolContext {
	tb.Helper()
	factory := &nativeContextFactory{host: nativeStressStableHost(), prepare: prepare}
	created, err := factory.New(context.Background(), validNativeContextConfig([]string{"synthetic-native-stress-tag"}))
	if err != nil || created == nil {
		tb.Fatal("native stress context setup failed: category=context-construction")
	}
	nativeCtx, ok := created.(*nativeProtocolContext)
	if !ok {
		tb.Fatal("native stress context setup failed: category=context-type")
	}
	return nativeCtx
}

func BenchmarkNativeBody(b *testing.B) {
	benchmarkNativeBody(b)
}

func BenchmarkNativeCredential(b *testing.B) {
	benchmarkNativeCredential(b)
}

func BenchmarkNativeRuntime(b *testing.B) {
	benchmarkNativeRuntime(b)
}

func BenchmarkNativeModelCache(b *testing.B) {
	benchmarkNativeModelCache(b)
}

func BenchmarkNativeInfer(b *testing.B) {
	benchmarkNativeInfer(b)
}

func benchmarkNativeBody(b *testing.B) {
	codec := nativeBodyCodec{}
	raw := bytes.Repeat([]byte("synthetic-native-body-"), 64)
	b.ReportAllocs()
	b.ResetTimer()
	for operation := 0; operation < b.N; operation++ {
		encoded, err := codec.Encode(raw)
		if err != nil {
			b.Fatal("native body benchmark failed: category=encode")
		}
		decoded, err := codec.Decode(encoded)
		if err != nil || !bytes.Equal(decoded, raw) {
			b.Fatal("native body benchmark failed: category=round-trip")
		}
		runtime.KeepAlive(decoded)
	}
}

func benchmarkNativeCredential(b *testing.B) {
	codec := nativeCredentialCodec{}
	ctx := context.Background()
	plain := `{"uid":"synthetic-native-benchmark-user","token":"synthetic-native-benchmark-token"}`
	const machineKey = "0123456789abcdef"
	b.ReportAllocs()
	b.ResetTimer()
	for operation := 0; operation < b.N; operation++ {
		encrypted, err := codec.Encrypt(ctx, plain, machineKey)
		if err != nil {
			b.Fatal("native credential benchmark failed: category=encrypt")
		}
		decrypted, err := codec.Decrypt(ctx, encrypted, machineKey)
		if err != nil || decrypted != plain {
			b.Fatal("native credential benchmark failed: category=round-trip")
		}
		runtime.KeepAlive(decrypted)
	}
}

func benchmarkNativeRuntime(b *testing.B) {
	generator := &nativeRuntimeFieldGenerator{host: nativeStressStableHost()}
	input := runtimeFieldInput{
		UID:              "synthetic-native-benchmark-user",
		OrganizationID:   "synthetic-native-benchmark-org",
		OrganizationTags: []string{"synthetic-native-benchmark-tag"},
		DataPolicyAgreed: true,
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for operation := 0; operation < b.N; operation++ {
		output, err := generator.Generate(ctx, input)
		if err != nil || output.EncryptUserInfo == "" || output.Key == "" {
			b.Fatal("native runtime benchmark failed: category=generate")
		}
		runtime.KeepAlive(output)
	}
}

func benchmarkNativeModelCache(b *testing.B) {
	plain := []byte(`{"chat":[{"key":"synthetic-native-benchmark-model"}]}`)
	const uid = "synthetic-native-benchmark-user"
	nonce := bytes.Repeat([]byte{0x5a}, qmcNonceSize)
	blob, err := encryptQMCV1ForTest(plain, uid, nonce)
	if err != nil {
		b.Fatal("native model-cache benchmark setup failed: category=encrypt")
	}
	decryptor := nativeModelCacheDecryptor{}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for operation := 0; operation < b.N; operation++ {
		decrypted, err := decryptor.Decrypt(ctx, blob, uid)
		if err != nil || !bytes.Equal(decrypted, plain) {
			b.Fatal("native model-cache benchmark failed: category=decrypt")
		}
		runtime.KeepAlive(decrypted)
	}
}

func benchmarkNativeInfer(b *testing.B) {
	snapshot := nativeContextSnapshot{
		host:      nativeStressStableHost(),
		bodyCodec: nativeBodyCodec{},
		machineID: "00000000-1111-4222-8333-444444444444",
		version:   qoderProtocolVersion,
		user: protocolUserInfo{
			UID:              "synthetic-native-benchmark-user",
			EncryptUserInfo:  "synthetic-native-benchmark-info",
			Key:              "synthetic-native-benchmark-key",
			OrganizationID:   "synthetic-native-benchmark-org",
			OrganizationTags: []string{"synthetic-native-benchmark-tag"},
			DataPolicyAgreed: true,
		},
		scene: defaultProtocolScene(),
	}
	input := inferRequestInput{
		Endpoint:    "https://example.invalid/native-benchmark",
		Body:        []byte(`{"synthetic":"native-benchmark"}`),
		ModelKey:    "synthetic-native-benchmark-model",
		ModelSource: "synthetic-native-benchmark-source",
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for operation := 0; operation < b.N; operation++ {
		prepared, err := prepareNativeInferRequest(ctx, snapshot, input)
		if err != nil || prepared == nil || prepared.URL == "" || len(prepared.Header) == 0 || len(prepared.Body) == 0 {
			b.Fatal("native infer benchmark failed: category=prepare")
		}
		runtime.KeepAlive(prepared)
	}
}
