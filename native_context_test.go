package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	_ protocolContextFactory = (*nativeContextFactory)(nil)
	_ protocolContext        = (*nativeProtocolContext)(nil)
)

type nativeContextHostProbe struct {
	mu           sync.Mutex
	now          time.Time
	fill         byte
	clockCalls   int
	entropyReads []int
	clockErr     error
	entropyErr   error
}

func (p *nativeContextHostProbe) Now() (time.Time, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clockCalls++
	if p.clockErr != nil {
		return time.Time{}, p.clockErr
	}
	return p.now, nil
}

func (p *nativeContextHostProbe) Read(dst []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entropyReads = append(p.entropyReads, len(dst))
	if p.entropyErr != nil {
		return p.entropyErr
	}
	for i := range dst {
		dst[i] = p.fill
	}
	return nil
}

func (p *nativeContextHostProbe) counts() (int, []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clockCalls, append([]int(nil), p.entropyReads...)
}

type nativeContextRuntimeGeneratorFake struct {
	mu      sync.Mutex
	calls   int
	inputs  []runtimeFieldInput
	output  runtimeFieldOutput
	err     error
	consume bool
}

func (g *nativeContextRuntimeGeneratorFake) Generate(ctx context.Context, input runtimeFieldInput) (runtimeFieldOutput, error) {
	input.OrganizationTags = slices.Clone(input.OrganizationTags)
	g.mu.Lock()
	g.calls++
	g.inputs = append(g.inputs, input)
	consume := g.consume
	output := g.output
	err := g.err
	g.mu.Unlock()
	if consume {
		deps := protocolHostDepsFor(ctx, protocolHostDeps{})
		if deps.Entropy == nil {
			return runtimeFieldOutput{}, errors.New("synthetic generator entropy dependency missing")
		}
		if readErr := deps.Entropy.Read(make([]byte, 16)); readErr != nil {
			return runtimeFieldOutput{}, readErr
		}
		if readErr := deps.Entropy.Read(make([]byte, 109)); readErr != nil {
			return runtimeFieldOutput{}, readErr
		}
	}
	return output, err
}

func (g *nativeContextRuntimeGeneratorFake) state() (int, []runtimeFieldInput) {
	g.mu.Lock()
	defer g.mu.Unlock()
	inputs := make([]runtimeFieldInput, len(g.inputs))
	for i, input := range g.inputs {
		input.OrganizationTags = slices.Clone(input.OrganizationTags)
		inputs[i] = input
	}
	return g.calls, inputs
}

func validNativeContextConfig(tags []string) protocolContextConfig {
	return protocolContextConfig{
		MachineID: "00000000-1111-4222-8333-444444444444",
		Version:   qoderProtocolVersion,
		User: protocolUserInfo{
			UID:              "synthetic-native-context-user",
			EncryptUserInfo:  "Y2FsbGVyLWVuY3J5cHRlZC11c2Vy",
			Key:              "Y2FsbGVyLXJ1bnRpbWUta2V5",
			OrganizationID:   "synthetic-native-context-org",
			OrganizationTags: tags,
			DataPolicyAgreed: true,
		},
		Scene: defaultProtocolScene(),
	}
}

func validNativeContextHost() protocolHostDeps {
	return protocolHostDeps{
		Clock:   &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)},
		Entropy: &nativeContextHostProbe{fill: 0x5a},
	}
}

func TestNativeContextFactoryRejectsInvalidFallbackDependenciesAndConfig(t *testing.T) {
	generator := &nativeContextRuntimeGeneratorFake{}
	base := validNativeContextConfig([]string{"synthetic-tag"})
	tests := []struct {
		name   string
		host   protocolHostDeps
		kind   protocolErrorKind
		mutate func(*protocolContextConfig)
	}{
		{name: "missing fallback clock", host: protocolHostDeps{Entropy: &nativeContextHostProbe{fill: 0x5a}}},
		{name: "missing fallback entropy", host: protocolHostDeps{Clock: &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)}}},
		{name: "nil organization tags", host: validNativeContextHost(), kind: protocolBackendFailure, mutate: func(config *protocolContextConfig) { config.User.OrganizationTags = nil }},
		{name: "empty machine ID", host: validNativeContextHost(), mutate: func(config *protocolContextConfig) { config.MachineID = "" }},
		{name: "empty version", host: validNativeContextHost(), mutate: func(config *protocolContextConfig) { config.Version = "" }},
		{name: "empty UID", host: validNativeContextHost(), mutate: func(config *protocolContextConfig) { config.User.UID = "" }},
		{name: "empty scene client type", host: validNativeContextHost(), mutate: func(config *protocolContextConfig) { config.Scene.ClientType = "" }},
		{name: "empty scene business product", host: validNativeContextHost(), mutate: func(config *protocolContextConfig) { config.Scene.BusinessProduct = "" }},
		{name: "empty scene business type", host: validNativeContextHost(), mutate: func(config *protocolContextConfig) { config.Scene.BusinessType = "" }},
		{name: "empty scene", host: validNativeContextHost(), mutate: func(config *protocolContextConfig) { config.Scene.Scene = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := base
			config.User.OrganizationTags = slices.Clone(base.User.OrganizationTags)
			if tt.mutate != nil {
				tt.mutate(&config)
			}
			factory := &nativeContextFactory{host: tt.host, runtimeFields: generator}
			got, err := factory.New(context.Background(), config)
			if got != nil {
				_ = got.Close()
				t.Fatal("invalid native context input returned a context")
			}
			wantKind := tt.kind
			if wantKind == "" {
				wantKind = protocolInvalidInput
			}
			if err == nil || protocolErrorKindOf(err) != wantKind {
				t.Fatalf("invalid native context error kind = %q, want %q", protocolErrorKindOf(err), wantKind)
			}
			for _, forbidden := range []string{base.MachineID, base.User.UID, base.User.OrganizationID, base.User.EncryptUserInfo, base.User.Key} {
				if forbidden != "" && strings.Contains(err.Error(), forbidden) {
					t.Fatal("native context validation error exposed an input value")
				}
			}
		})
	}
	if calls, _ := generator.state(); calls != 0 {
		t.Fatalf("runtime generator calls after validation failures = %d, want 0", calls)
	}
}

func TestNativeContextFactoryRejectsCancellationBeforeRuntimeOrEntropy(t *testing.T) {
	clock := &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)}
	entropy := &nativeContextHostProbe{fill: 0x5a}
	generator := &nativeContextRuntimeGeneratorFake{consume: true}
	factory := &nativeContextFactory{
		host:          protocolHostDeps{Clock: clock, Entropy: entropy},
		runtimeFields: generator,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := factory.New(ctx, validNativeContextConfig([]string{"synthetic-tag"}))
	if got != nil {
		_ = got.Close()
		t.Fatal("canceled native context factory returned a context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled native context factory error type = %T, want context cancellation", err)
	}
	if calls, _ := generator.state(); calls != 0 {
		t.Fatalf("runtime generator calls after cancellation = %d, want 0", calls)
	}
	clockCalls, _ := clock.counts()
	_, entropyReads := entropy.counts()
	if clockCalls != 0 || len(entropyReads) != 0 {
		t.Fatalf("host calls after cancellation = clock %d entropy %v, want none", clockCalls, entropyReads)
	}
}

func TestNativeContextFactoryUsesOverrideWASMNewTranscriptAndPreservesCallerFields(t *testing.T) {
	config := validNativeContextConfig([]string{"synthetic-a", "synthetic-b"})
	transcript := deterministicRuntimeTranscript(false)

	expectedReplay := newTranscriptReplay(transcript)
	expectedCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: expectedReplay, Entropy: expectedReplay})
	expectedGenerated, err := (&nativeRuntimeFieldGenerator{}).Generate(expectedCtx, runtimeFieldInput{
		UID:              config.User.UID,
		OrganizationID:   config.User.OrganizationID,
		OrganizationTags: slices.Clone(config.User.OrganizationTags),
		DataPolicyAgreed: config.User.DataPolicyAgreed,
	})
	if err != nil {
		t.Fatalf("independent native runtime generation returned kind %q", protocolErrorKindOf(err))
	}
	assertReplayExhausted(t, expectedReplay)
	if expectedGenerated.EncryptUserInfo == config.User.EncryptUserInfo || expectedGenerated.Key == config.User.Key {
		t.Fatal("native context test setup did not distinguish generated and caller fields")
	}

	fallbackClock := &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)}
	fallbackEntropy := &nativeContextHostProbe{fill: 0x7a}
	factory := &nativeContextFactory{host: protocolHostDeps{Clock: fallbackClock, Entropy: fallbackEntropy}}
	replay := newTranscriptReplay(transcript)
	ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: replay, Entropy: replay})

	created, err := factory.New(ctx, config)
	if err != nil {
		t.Fatalf("native context factory returned kind %q", protocolErrorKindOf(err))
	}
	defer func() {
		if closeErr := created.Close(); closeErr != nil {
			t.Errorf("native context close returned kind %q", protocolErrorKindOf(closeErr))
		}
	}()
	assertReplayExhausted(t, replay)
	clockCalls, _ := fallbackClock.counts()
	_, entropyReads := fallbackEntropy.counts()
	if clockCalls != 0 || len(entropyReads) != 0 {
		t.Fatalf("factory fallback host calls = clock %d entropy %v, want override only", clockCalls, entropyReads)
	}

	nativeCtx, ok := created.(*nativeProtocolContext)
	if !ok {
		t.Fatalf("native context concrete type = %T", created)
	}
	nativeCtx.mu.RLock()
	effective := cloneNativeProtocolUserInfo(nativeCtx.user)
	nativeCtx.mu.RUnlock()
	if effective.EncryptUserInfo != config.User.EncryptUserInfo || effective.Key != config.User.Key {
		t.Fatal("native context did not preserve caller runtime fields")
	}
	if !reflect.DeepEqual(effective.OrganizationTags, config.User.OrganizationTags) {
		t.Fatal("native context changed organization tags during New")
	}

	prepareHost := &nativeInferOrderedHost{
		now:     time.UnixMilli(protocolFixtureUnixMilli),
		entropy: nativeInferVectorEntropy(),
	}
	prepareCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: prepareHost, Entropy: prepareHost})
	prepared, err := created.PrepareInferRequest(prepareCtx, nativeInferVectorInput())
	if err != nil {
		t.Fatalf("native context PrepareInferRequest returned kind %q", protocolErrorKindOf(err))
	}
	payload, _ := nativeInferAuthorizationForTest(t, prepared.Header)
	if prepared.Header.Get("Cosy-Key") != config.User.Key || payload.Info != config.User.EncryptUserInfo {
		t.Fatal("prepared request did not use caller runtime fields")
	}
}

func TestNativeContextFactoryCopiesConfigAndPreservesTagShape(t *testing.T) {
	for _, tt := range []struct {
		name string
		tags []string
	}{
		{name: "non-nil empty", tags: []string{}},
		{name: "populated", tags: []string{"synthetic-original"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := validNativeContextConfig(tt.tags)
			config.User.OrganizationID = ""
			want := config
			want.User.OrganizationTags = slices.Clone(config.User.OrganizationTags)
			ignoredGenerated := runtimeFieldOutput{
				EncryptUserInfo: "synthetic-copy-generated-info",
				Key:             "synthetic-copy-generated-key",
			}
			factory := &nativeContextFactory{
				host:          validNativeContextHost(),
				runtimeFields: &nativeContextRuntimeGeneratorFake{consume: true, output: ignoredGenerated},
			}
			created, err := factory.New(context.Background(), config)
			if err != nil {
				t.Fatalf("tag-shape New returned kind %q", protocolErrorKindOf(err))
			}
			defer func() { _ = created.Close() }()

			config.MachineID = "synthetic-mutated-machine"
			config.Version = "synthetic-mutated-version"
			config.User.UID = "synthetic-mutated-user"
			config.User.EncryptUserInfo = "synthetic-mutated-encrypted-field"
			config.User.Key = "synthetic-mutated-runtime-key"
			config.User.OrganizationID = "synthetic-mutated-org"
			config.Scene = protocolScene{ClientType: "mutated", BusinessProduct: "mutated", BusinessType: "mutated", Scene: "mutated"}
			if len(config.User.OrganizationTags) > 0 {
				config.User.OrganizationTags[0] = "synthetic-mutated-tag"
			}
			config.User.OrganizationTags = append(config.User.OrganizationTags, "synthetic-appended-tag")

			nativeCtx := created.(*nativeProtocolContext)
			nativeCtx.mu.RLock()
			gotMachineID := nativeCtx.machineID
			gotVersion := nativeCtx.version
			gotUser := nativeCtx.user
			gotUser.OrganizationTags = slices.Clone(gotUser.OrganizationTags)
			gotScene := nativeCtx.scene
			nativeCtx.mu.RUnlock()
			if gotMachineID != want.MachineID || gotVersion != want.Version || gotUser.UID != want.User.UID ||
				gotUser.EncryptUserInfo != want.User.EncryptUserInfo || gotUser.Key != want.User.Key ||
				gotUser.OrganizationID != want.User.OrganizationID || gotScene != want.Scene {
				t.Fatal("native context state changed after caller config mutation")
			}
			if !reflect.DeepEqual(gotUser.OrganizationTags, want.User.OrganizationTags) {
				t.Fatal("native context tags changed after caller mutation")
			}
			if (gotUser.OrganizationTags == nil) != (tt.tags == nil) {
				t.Fatal("native context did not preserve organization tag nilness")
			}
		})
	}
}

func TestNativeContextFactoryRuntimeInitializationFailureReturnsNoContextSafely(t *testing.T) {
	const sentinelValue = "SENTINEL-NATIVE-CONTEXT-RUNTIME-VALUE"
	cause := errors.New("synthetic runtime initialization failure containing " + sentinelValue)
	generator := &nativeContextRuntimeGeneratorFake{consume: true, err: cause}
	clock := &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)}
	entropy := &nativeContextHostProbe{fill: 0x5a}
	factory := &nativeContextFactory{
		host:          protocolHostDeps{Clock: clock, Entropy: entropy},
		runtimeFields: generator,
	}

	config := validNativeContextConfig([]string{"synthetic-tag"})
	created, err := factory.New(context.Background(), config)
	if created != nil {
		_ = created.Close()
		t.Fatal("runtime initialization failure returned a partial context")
	}
	if err == nil || protocolErrorKindOf(err) != protocolBackendFailure {
		t.Fatalf("runtime initialization error kind = %q, want %q", protocolErrorKindOf(err), protocolBackendFailure)
	}
	if strings.Contains(err.Error(), sentinelValue) {
		t.Fatal("runtime initialization public error exposed internal content")
	}
	if !errors.Is(protocolInternalError(err), cause) {
		t.Fatal("runtime initialization error lost its internal cause")
	}
	calls, inputs := generator.state()
	wantInput := runtimeFieldInput{
		UID:              config.User.UID,
		OrganizationID:   config.User.OrganizationID,
		OrganizationTags: slices.Clone(config.User.OrganizationTags),
		DataPolicyAgreed: config.User.DataPolicyAgreed,
	}
	if calls != 1 || len(inputs) != 1 || !reflect.DeepEqual(inputs[0], wantInput) {
		t.Fatal("runtime initialization generator did not receive the exact copied user metadata")
	}
	clockCalls, _ := clock.counts()
	_, entropyReads := entropy.counts()
	if clockCalls != 0 || !reflect.DeepEqual(entropyReads, []int{16, 109}) {
		t.Fatalf("runtime initialization host shape = clock %d entropy %v, want 0 and [16 109]", clockCalls, entropyReads)
	}
}

func TestNativeProtocolContextDefaultPrepareBuildsRequest(t *testing.T) {
	clock := &nativeContextHostProbe{now: time.UnixMilli(1781000123999)}
	entropy := &nativeContextHostProbe{fill: 0x5a}
	factory := &nativeContextFactory{host: protocolHostDeps{Clock: clock, Entropy: entropy}}
	created, err := factory.New(context.Background(), validNativeContextConfig([]string{"synthetic-tag"}))
	if err != nil {
		t.Fatalf("default-preparer New returned kind %q", protocolErrorKindOf(err))
	}
	defer func() { _ = created.Close() }()

	prepared, err := created.PrepareInferRequest(context.Background(), inferRequestInput{
		Endpoint:    "https://example.invalid",
		Body:        []byte(`{"synthetic":true}`),
		ModelKey:    "synthetic-model",
		ModelSource: "synthetic-source",
	})
	if err != nil {
		t.Fatalf("default native prepare returned kind %q", protocolErrorKindOf(err))
	}
	if prepared == nil {
		t.Fatal("default native prepare returned nil request")
	}
	if prepared.URL != nativeInferURL("https://example.invalid") {
		t.Fatalf("default native prepare URL length = %d", len(prepared.URL))
	}
	if len(prepared.Header) != 22 || !strings.HasPrefix(prepared.Header.Get("Authorization"), "Bearer COSY.") {
		t.Fatalf("default native prepare header shape = fields %d authorization length %d", len(prepared.Header), len(prepared.Header.Get("Authorization")))
	}
	if len(prepared.Body) == 0 {
		t.Fatal("default native prepare returned an empty encoded body")
	}
	clockCalls, _ := clock.counts()
	_, entropyReads := entropy.counts()
	if clockCalls != 1 || !reflect.DeepEqual(entropyReads, []int{16, 109, 16}) {
		t.Fatalf("default native context transcript shape = clock %d entropy %v", clockCalls, entropyReads)
	}
}

func newNativeProtocolContextForTest(t *testing.T, prepare nativePrepareFunc) *nativeProtocolContext {
	t.Helper()
	factory := &nativeContextFactory{
		host:          validNativeContextHost(),
		runtimeFields: &nativeContextRuntimeGeneratorFake{consume: true},
		prepare:       prepare,
	}
	created, err := factory.New(context.Background(), validNativeContextConfig([]string{"synthetic-original-tag"}))
	if err != nil {
		t.Fatalf("native context test setup returned kind %q", protocolErrorKindOf(err))
	}
	nativeCtx, ok := created.(*nativeProtocolContext)
	if !ok {
		t.Fatalf("native context test setup type = %T", created)
	}
	t.Cleanup(func() {
		if closeErr := nativeCtx.Close(); closeErr != nil {
			t.Errorf("native context cleanup returned kind %q", protocolErrorKindOf(closeErr))
		}
	})
	return nativeCtx
}

func TestNativeProtocolContextCloseIsIdempotentAndRejectsPrepare(t *testing.T) {
	var prepareCalls atomic.Int32
	nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
		prepareCalls.Add(1)
		return &preparedRequest{}, nil
	})

	if err := nativeCtx.Close(); err != nil {
		t.Fatalf("first native context Close returned kind %q", protocolErrorKindOf(err))
	}
	if err := nativeCtx.Close(); err != nil {
		t.Fatalf("second native context Close returned kind %q", protocolErrorKindOf(err))
	}
	prepared, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
	if prepared != nil {
		t.Fatal("Prepare after native context Close returned a request")
	}
	if err == nil || protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatalf("Prepare after Close error kind = %q, want %q", protocolErrorKindOf(err), protocolContextClosed)
	}
	if prepareCalls.Load() != 0 {
		t.Fatalf("preparer calls after Close = %d, want 0", prepareCalls.Load())
	}
}

func TestNativeProtocolContextClosedPrecedesCancellation(t *testing.T) {
	contexts := []struct {
		name string
		ctx  func() context.Context
	}{
		{
			name: "canceled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
		{
			name: "expired deadline",
			ctx: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
				t.Cleanup(cancel)
				return ctx
			},
		},
	}
	for _, tt := range contexts {
		t.Run(tt.name, func(t *testing.T) {
			nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
				t.Fatal("closed native context invoked its preparer")
				return nil, nil
			})
			if err := nativeCtx.Close(); err != nil {
				t.Fatalf("native context Close returned kind %q", protocolErrorKindOf(err))
			}
			prepared, err := nativeCtx.PrepareInferRequest(tt.ctx(), inferRequestInput{})
			if prepared != nil {
				t.Fatal("closed native context returned a request")
			}
			if err == nil || protocolErrorKindOf(err) != protocolContextClosed {
				t.Fatalf("closed-plus-cancellation error kind = %q, want %q", protocolErrorKindOf(err), protocolContextClosed)
			}
		})
	}

	t.Run("nil receiver with cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var nativeCtx *nativeProtocolContext
		prepared, err := nativeCtx.PrepareInferRequest(ctx, inferRequestInput{})
		if prepared != nil {
			t.Fatal("nil native context returned a request")
		}
		if err == nil || protocolErrorKindOf(err) != protocolContextClosed {
			t.Fatalf("nil-plus-cancellation error kind = %q, want %q", protocolErrorKindOf(err), protocolContextClosed)
		}
	})
}

func TestNativeProtocolContextRejectsCancellationBeforePreparerOrHostWork(t *testing.T) {
	var prepareCalls atomic.Int32
	nativeCtx := newNativeProtocolContextForTest(t, func(ctx context.Context, snapshot nativeContextSnapshot, _ inferRequestInput) (*preparedRequest, error) {
		prepareCalls.Add(1)
		deps := protocolHostDepsFor(ctx, snapshot.host)
		if deps.Entropy != nil {
			_ = deps.Entropy.Read(make([]byte, 16))
		}
		if deps.Clock != nil {
			_, _ = deps.Clock.Now()
		}
		return &preparedRequest{}, nil
	})
	clock := &nativeContextHostProbe{now: time.UnixMilli(protocolFixtureUnixMilli)}
	entropy := &nativeContextHostProbe{fill: 0x44}
	ctx, cancel := context.WithCancel(withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: clock, Entropy: entropy}))
	cancel()

	prepared, err := nativeCtx.PrepareInferRequest(ctx, inferRequestInput{Body: []byte("synthetic-body")})
	if prepared != nil {
		t.Fatal("canceled native prepare returned a request")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled native prepare error type = %T, want context cancellation", err)
	}
	if prepareCalls.Load() != 0 {
		t.Fatalf("preparer calls after cancellation = %d, want 0", prepareCalls.Load())
	}
	clockCalls, _ := clock.counts()
	_, entropyReads := entropy.counts()
	if clockCalls != 0 || len(entropyReads) != 0 {
		t.Fatalf("host calls after canceled prepare = clock %d entropy %v, want none", clockCalls, entropyReads)
	}
}

func TestNativeProtocolContextClonesPreparerInputAndSnapshot(t *testing.T) {
	var observedBodies [][]byte
	var observedTags [][]string
	nativeCtx := newNativeProtocolContextForTest(t, func(_ context.Context, snapshot nativeContextSnapshot, input inferRequestInput) (*preparedRequest, error) {
		observedBodies = append(observedBodies, append([]byte(nil), input.Body...))
		observedTags = append(observedTags, slices.Clone(snapshot.user.OrganizationTags))
		if len(input.Body) > 0 {
			input.Body[0] ^= 0xff
		}
		if len(snapshot.user.OrganizationTags) > 0 {
			snapshot.user.OrganizationTags[0] = "synthetic-preparer-mutated-tag"
		}
		return &preparedRequest{
			URL:    "https://example.invalid/native-test",
			Header: http.Header{"X-Synthetic": {"value"}},
			Body:   []byte("synthetic-prepared-body"),
		}, nil
	})
	callerBody := []byte("synthetic-caller-body")
	callerBefore := append([]byte(nil), callerBody...)
	input := inferRequestInput{
		Endpoint:    "https://example.invalid",
		Body:        callerBody,
		ModelKey:    "synthetic-model",
		ModelSource: "synthetic-source",
	}

	if _, err := nativeCtx.PrepareInferRequest(context.Background(), input); err != nil {
		t.Fatalf("first clone-boundary prepare returned kind %q", protocolErrorKindOf(err))
	}
	if !bytes.Equal(callerBody, callerBefore) {
		t.Fatal("preparer mutation changed caller-owned body")
	}
	if _, err := nativeCtx.PrepareInferRequest(context.Background(), input); err != nil {
		t.Fatalf("second clone-boundary prepare returned kind %q", protocolErrorKindOf(err))
	}

	bodies := append([][]byte(nil), observedBodies...)
	tags := append([][]string(nil), observedTags...)
	if len(bodies) != 2 || !bytes.Equal(bodies[0], callerBefore) || !bytes.Equal(bodies[1], callerBefore) {
		t.Fatal("preparer did not receive independent exact body copies")
	}
	wantTags := []string{"synthetic-original-tag"}
	if len(tags) != 2 || !reflect.DeepEqual(tags[0], wantTags) || !reflect.DeepEqual(tags[1], wantTags) {
		t.Fatal("preparer snapshot mutation changed later context state")
	}
	nativeCtx.mu.RLock()
	storedTags := slices.Clone(nativeCtx.user.OrganizationTags)
	nativeCtx.mu.RUnlock()
	if !reflect.DeepEqual(storedTags, wantTags) {
		t.Fatal("preparer snapshot mutation changed stored context tags")
	}
}

func TestNativeProtocolContextClonesPreparedResultsAcrossCalls(t *testing.T) {
	shared := &preparedRequest{
		URL: "https://example.invalid/shared",
		Header: http.Header{
			"X-Synthetic": {"first", "second"},
		},
		Body: []byte("synthetic-shared-body"),
	}
	nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
		return shared, nil
	})

	first, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil {
		t.Fatalf("first shared-result prepare returned kind %q", protocolErrorKindOf(err))
	}
	if first == shared {
		t.Fatal("native prepare returned the preparer's request pointer")
	}
	first.Header["X-Synthetic"][0] = "mutated"
	first.Header.Add("X-Synthetic", "appended")
	first.Body[0] ^= 0xff
	if shared.Header["X-Synthetic"][0] != "first" || len(shared.Header["X-Synthetic"]) != 2 || string(shared.Body) != "synthetic-shared-body" {
		t.Fatal("returned request mutation changed preparer-owned result")
	}

	second, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil {
		t.Fatalf("second shared-result prepare returned kind %q", protocolErrorKindOf(err))
	}
	if second == shared || second == first {
		t.Fatal("native prepare reused a request pointer across ownership boundaries")
	}
	if !reflect.DeepEqual(second.Header["X-Synthetic"], []string{"first", "second"}) || string(second.Body) != "synthetic-shared-body" {
		t.Fatal("mutation of one returned request affected a later call")
	}
	second.Header["X-Synthetic"][1] = "second-mutated"
	second.Body[1] ^= 0xff
	if first.Header["X-Synthetic"][1] != "second" || bytes.Equal(first.Body, second.Body) {
		t.Fatal("separate returned requests share header values or body storage")
	}
}

func TestNativeProtocolContextConcurrentPrepareUsesPerCallHostOverrides(t *testing.T) {
	nativeCtx := newNativeProtocolContextForTest(t, func(ctx context.Context, snapshot nativeContextSnapshot, input inferRequestInput) (*preparedRequest, error) {
		deps := protocolHostDepsFor(ctx, snapshot.host)
		var random [16]byte
		if deps.Entropy == nil {
			return nil, errors.New("synthetic per-call entropy missing")
		}
		if err := deps.Entropy.Read(random[:]); err != nil {
			return nil, err
		}
		if deps.Clock == nil {
			return nil, errors.New("synthetic per-call clock missing")
		}
		now, err := deps.Clock.Now()
		if err != nil {
			return nil, err
		}
		return &preparedRequest{
			URL:    fmt.Sprintf("https://example.invalid/%d/%d", random[0], now.UnixMilli()),
			Header: http.Header{"X-Synthetic-Call": {fmt.Sprintf("%d", random[0])}},
			Body:   append([]byte(nil), input.Body...),
		}, nil
	})

	const calls = 100
	type callResult struct {
		request *preparedRequest
		err     error
	}
	results := make([]callResult, calls)
	replays := make([]*transcriptReplay, calls)
	var wg sync.WaitGroup
	wg.Add(calls)
	for i := 0; i < calls; i++ {
		i := i
		value := byte(i + 1)
		when := protocolFixtureUnixMilli + int64(i)
		replays[i] = newTranscriptReplay(protocolTranscript{
			UnixMilli: []int64{when},
			EntropyReads: []entropyRead{{
				Length: 16,
				Bytes:  bytes.Repeat([]byte{value}, 16),
			}},
		})
		go func() {
			defer wg.Done()
			ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: replays[i], Entropy: replays[i]})
			results[i].request, results[i].err = nativeCtx.PrepareInferRequest(ctx, inferRequestInput{Body: []byte{value, 0x7f}})
		}()
	}
	wg.Wait()

	for i, result := range results {
		if result.err != nil {
			t.Fatalf("concurrent prepare %d returned kind %q", i, protocolErrorKindOf(result.err))
		}
		if result.request == nil {
			t.Fatalf("concurrent prepare %d returned nil", i)
		}
		value := byte(i + 1)
		wantURL := fmt.Sprintf("https://example.invalid/%d/%d", value, protocolFixtureUnixMilli+int64(i))
		if result.request.URL != wantURL || !bytes.Equal(result.request.Body, []byte{value, 0x7f}) {
			t.Fatalf("concurrent prepare %d returned the wrong transcript shape", i)
		}
		assertReplayExhausted(t, replays[i])
	}
}

func TestNativeProtocolContextCloseWaitsForInflightAndPreventsNewPrepare(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releasePrepare := func() { releaseOnce.Do(func() { close(release) }) }
	defer releasePrepare()
	var calls atomic.Int32
	nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return &preparedRequest{URL: "https://example.invalid/inflight", Header: make(http.Header), Body: []byte("synthetic")}, nil
	})

	firstDone := make(chan error, 1)
	go func() {
		_, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
		firstDone <- err
	}()
	<-started

	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- nativeCtx.Close()
	}()
	<-closeStarted
	if !waitForNativeContextWriter(nativeCtx) {
		t.Fatal("native context Close completed while PrepareInferRequest was in flight")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
		secondDone <- err
	}()

	releasePrepare()
	if err := <-firstDone; err != nil {
		t.Fatalf("in-flight native prepare returned kind %q", protocolErrorKindOf(err))
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("native context Close returned kind %q", protocolErrorKindOf(err))
	}
	if err := <-secondDone; err == nil || protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatalf("prepare admitted behind Close returned kind %q, want %q", protocolErrorKindOf(err), protocolContextClosed)
	}
	if calls.Load() != 1 {
		t.Fatalf("preparer calls across in-flight Close = %d, want 1", calls.Load())
	}
}

func waitForNativeContextWriter(nativeCtx *nativeProtocolContext) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !nativeCtx.mu.TryRLock() {
			return true
		}
		closed := nativeCtx.closed
		nativeCtx.mu.RUnlock()
		if closed {
			return false
		}
		runtime.Gosched()
	}
	return false
}

func TestNativeProtocolContextRejectsNilAndUnsafePreparerResults(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
			return nil, nil
		})
		prepared, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
		if prepared != nil {
			t.Fatal("nil preparer result became a request")
		}
		if err == nil || protocolErrorKindOf(err) != protocolBackendFailure {
			t.Fatalf("nil preparer result error kind = %q, want %q", protocolErrorKindOf(err), protocolBackendFailure)
		}
	})

	t.Run("unsafe error", func(t *testing.T) {
		const sentinel = "SENTINEL-NATIVE-PREPARE-CONTENT"
		cause := errors.New("synthetic preparer failure containing " + sentinel)
		nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
			return nil, cause
		})
		prepared, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{Body: []byte(sentinel)})
		if prepared != nil {
			t.Fatal("preparer error returned a request")
		}
		if err == nil || protocolErrorKindOf(err) != protocolBackendFailure {
			t.Fatalf("preparer failure error kind = %q, want %q", protocolErrorKindOf(err), protocolBackendFailure)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("preparer public error exposed request or internal content")
		}
		if !errors.Is(protocolInternalError(err), cause) {
			t.Fatal("preparer failure lost its internal cause")
		}
	})

	t.Run("wrapped cancellation", func(t *testing.T) {
		const sentinel = "SENTINEL-NATIVE-CANCELED-CONTENT"
		wrapped := fmt.Errorf("synthetic cancellation containing %s: %w", sentinel, context.Canceled)
		nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
			return nil, wrapped
		})
		prepared, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
		if prepared != nil {
			t.Fatal("wrapped cancellation returned a request")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wrapped cancellation error type = %T, want context cancellation", err)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("wrapped cancellation exposed internal content")
		}
	})

	for _, tt := range []struct {
		name string
		want error
	}{
		{name: "protocol error wrapping cancellation", want: context.Canceled},
		{name: "protocol error wrapping deadline", want: context.DeadlineExceeded},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := newProtocolError(
				protocolBackendFailure,
				"Qoder protocol operation failed",
				fmt.Errorf("synthetic prepare context failure: %w", tt.want),
			)
			nativeCtx := newNativeProtocolContextForTest(t, func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
				return nil, wrapped
			})
			prepared, err := nativeCtx.PrepareInferRequest(context.Background(), inferRequestInput{})
			if prepared != nil || !errors.Is(err, tt.want) {
				t.Fatalf("PrepareInferRequest() = (%#v, %v), want %v", prepared, err, tt.want)
			}
		})
	}
}

func TestRuntimeFieldsPersistedWASMInteropThroughNativeContext(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "infer-user.json")
	var input inferFixtureInput
	decodeExactJSON(t, fixture.Input, &input)

	var effective protocolUserInfo
	prepare := func(ctx context.Context, snapshot nativeContextSnapshot, request inferRequestInput) (*preparedRequest, error) {
		deps := protocolHostDepsFor(ctx, snapshot.host)
		var random [16]byte
		if deps.Entropy == nil {
			return nil, errors.New("synthetic interop entropy missing")
		}
		if err := deps.Entropy.Read(random[:]); err != nil {
			return nil, err
		}
		if deps.Clock == nil {
			return nil, errors.New("synthetic interop clock missing")
		}
		if _, err := deps.Clock.Now(); err != nil {
			return nil, err
		}
		effective = cloneNativeProtocolUserInfo(snapshot.user)
		return &preparedRequest{
			URL:    "https://example.invalid/native-context-stage",
			Header: http.Header{"X-Native-Stage": {"context-only"}},
			Body:   append([]byte(nil), request.Body...),
		}, nil
	}
	factory := &nativeContextFactory{host: validNativeContextHost(), prepare: prepare}
	newTranscript := deterministicRuntimeTranscript(false)
	if !reflect.DeepEqual(entropyReadLengths(newTranscript), []int{16, 109}) || len(newTranscript.UnixMilli) != 0 {
		t.Fatal("native interop New transcript setup does not match WASM [16 109] without clock")
	}
	newReplay := newTranscriptReplay(newTranscript)
	newCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: newReplay, Entropy: newReplay})
	created, err := factory.New(newCtx, protocolContextConfig{
		MachineID: input.MachineID,
		Version:   input.Version,
		User:      input.User,
		Scene:     input.Scene,
	})
	if err != nil {
		t.Fatalf("persisted WASM field native New returned kind %q", protocolErrorKindOf(err))
	}
	defer func() { _ = created.Close() }()
	assertReplayExhausted(t, newReplay)

	prepareTranscript := protocolTranscript{
		UnixMilli: []int64{protocolFixtureUnixMilli},
		EntropyReads: []entropyRead{{
			Length: 16,
			Bytes:  bytes.Repeat([]byte{0x33}, 16),
		}},
	}
	if !reflect.DeepEqual(entropyReadLengths(prepareTranscript), []int{16}) || len(prepareTranscript.UnixMilli) != 1 {
		t.Fatal("native interop Prepare transcript setup does not match WASM [16] plus one clock")
	}
	prepareReplay := newTranscriptReplay(prepareTranscript)
	prepareCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: prepareReplay, Entropy: prepareReplay})
	prepared, err := created.PrepareInferRequest(prepareCtx, inferRequestInput{
		Endpoint:    input.Endpoint,
		Body:        []byte(input.BodyRaw),
		ModelKey:    input.ModelKey,
		ModelSource: input.ModelSource,
	})
	if err != nil {
		t.Fatalf("persisted WASM field native fake prepare returned kind %q", protocolErrorKindOf(err))
	}
	if prepared == nil {
		t.Fatal("persisted WASM field native fake prepare returned nil")
	}
	assertReplayExhausted(t, prepareReplay)

	got := effective
	if got.EncryptUserInfo != input.User.EncryptUserInfo || got.Key != input.User.Key {
		t.Fatal("native context did not preserve persisted WASM runtime fields")
	}
	if got.UID != input.User.UID || got.OrganizationID != input.User.OrganizationID ||
		!reflect.DeepEqual(got.OrganizationTags, input.User.OrganizationTags) || got.DataPolicyAgreed != input.User.DataPolicyAgreed {
		t.Fatal("native context changed persisted WASM user metadata")
	}
}
