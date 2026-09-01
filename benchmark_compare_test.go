package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const nativeComparisonFixturesEnv = "QODER2API_BENCH_FIXTURES"

type nativeComparisonFixture struct {
	credential        credentialFixtureInput
	runtimeInput      runtimeFieldInput
	runtimeTranscript protocolTranscript
	modelInput        modelCacheFixtureInput
	modelExpected     modelCacheFixtureExpected
	config            protocolContextConfig
	request           inferRequestInput
	inferTranscript   protocolTranscript
}

type comparisonClock struct {
	now time.Time
}

func (c comparisonClock) Now() (time.Time, error) {
	return c.now, nil
}

type comparisonEntropyByLength map[int][]byte

func (e comparisonEntropyByLength) Read(dst []byte) error {
	value, ok := e[len(dst)]
	if !ok || len(value) != len(dst) {
		return fmt.Errorf("unexpected comparison entropy length %d", len(dst))
	}
	copy(dst, value)
	return nil
}

func TestNativeComparisonBenchmarkFixtureSetup(t *testing.T) {
	fixture, err := loadNativeComparisonFixture("testdata/protocol/1.1.34")
	if err != nil {
		t.Fatal(err)
	}
	if fixture.credential.Plain == "" || fixture.modelExpected.Encrypted == "" || len(fixture.request.Body) == 0 {
		t.Fatal("comparison benchmark fixture is incomplete")
	}
	if len(fixture.runtimeTranscript.EntropyReads) != 2 || len(fixture.inferTranscript.EntropyReads) != 3 {
		t.Fatal("comparison benchmark transcript shape is invalid")
	}
}

func loadNativeComparisonFixture(dir string) (nativeComparisonFixture, error) {
	credentialDocument, err := readNativeComparisonDocument(dir, "credential.json")
	if err != nil {
		return nativeComparisonFixture{}, err
	}
	runtimeDocument, err := readNativeComparisonDocument(dir, "runtime-fields.json")
	if err != nil {
		return nativeComparisonFixture{}, err
	}
	modelDocument, err := readNativeComparisonDocument(dir, "model-cache.json")
	if err != nil {
		return nativeComparisonFixture{}, err
	}
	inferDocument, err := readNativeComparisonDocument(dir, "infer-user.json")
	if err != nil {
		return nativeComparisonFixture{}, err
	}

	var credential credentialFixtureInput
	if err := decodeNativeComparisonJSON(credentialDocument.Input, &credential); err != nil {
		return nativeComparisonFixture{}, errors.New("credential fixture input is invalid")
	}
	var runtimeWire runtimeFixtureInput
	if err := decodeNativeComparisonJSON(runtimeDocument.Input, &runtimeWire); err != nil {
		return nativeComparisonFixture{}, errors.New("runtime fixture input is invalid")
	}
	var runtimeInput runtimeFieldInput
	if err := decodeNativeComparisonJSON([]byte(runtimeWire.Raw), &runtimeInput); err != nil {
		return nativeComparisonFixture{}, errors.New("runtime semantic input is invalid")
	}
	var modelInput modelCacheFixtureInput
	if err := decodeNativeComparisonJSON(modelDocument.Input, &modelInput); err != nil {
		return nativeComparisonFixture{}, errors.New("model-cache fixture input is invalid")
	}
	var modelExpected modelCacheFixtureExpected
	if err := decodeNativeComparisonJSON(modelDocument.Expected, &modelExpected); err != nil {
		return nativeComparisonFixture{}, errors.New("model-cache fixture output is invalid")
	}
	var inferInput inferFixtureInput
	if err := decodeNativeComparisonJSON(inferDocument.Input, &inferInput); err != nil {
		return nativeComparisonFixture{}, errors.New("infer fixture input is invalid")
	}

	if len(runtimeDocument.Transcript.UnixMilli) != 0 ||
		len(runtimeDocument.Transcript.EntropyReads) != 2 ||
		runtimeDocument.Transcript.EntropyReads[0].Length != 16 ||
		runtimeDocument.Transcript.EntropyReads[1].Length != 109 {
		return nativeComparisonFixture{}, errors.New("runtime fixture transcript is invalid")
	}
	if len(inferDocument.Transcript.UnixMilli) != 1 ||
		len(inferDocument.Transcript.EntropyReads) != 3 ||
		inferDocument.Transcript.EntropyReads[0].Length != 16 ||
		inferDocument.Transcript.EntropyReads[1].Length != 109 ||
		inferDocument.Transcript.EntropyReads[2].Length != 16 {
		return nativeComparisonFixture{}, errors.New("infer fixture transcript is invalid")
	}

	return nativeComparisonFixture{
		credential:        credential,
		runtimeInput:      runtimeInput,
		runtimeTranscript: cloneProtocolTranscript(runtimeDocument.Transcript),
		modelInput:        modelInput,
		modelExpected:     modelExpected,
		config: protocolContextConfig{
			MachineID: inferInput.MachineID,
			Version:   inferInput.Version,
			User:      cloneNativeProtocolUserInfo(inferInput.User),
			Scene:     cloneNativeProtocolScene(inferInput.Scene),
		},
		request: inferRequestInput{
			Endpoint:    inferInput.Endpoint,
			Body:        []byte(inferInput.BodyRaw),
			ModelKey:    inferInput.ModelKey,
			ModelSource: inferInput.ModelSource,
		},
		inferTranscript: cloneProtocolTranscript(inferDocument.Transcript),
	}, nil
}

func readNativeComparisonDocument(dir, name string) (protocolFixture, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return protocolFixture{}, fmt.Errorf("read %s: %w", name, err)
	}
	var document protocolFixture
	if err := decodeNativeComparisonJSON(data, &document); err != nil {
		return protocolFixture{}, fmt.Errorf("decode %s: %w", name, err)
	}
	return document, nil
}

func decodeNativeComparisonJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func BenchmarkCompareNative(b *testing.B) {
	fixturePath := os.Getenv(nativeComparisonFixturesEnv)
	if fixturePath == "" {
		fixturePath = "testdata/protocol/1.1.34"
	}
	fixture, err := loadNativeComparisonFixture(fixturePath)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ColdStart", benchmarkNativeComparisonColdStart(fixture))
	b.Run("BodyRoundTrip", benchmarkNativeComparisonBody(fixture))
	b.Run("CredentialRoundTrip", benchmarkNativeComparisonCredential(fixture))
	b.Run("RuntimeFields", benchmarkNativeComparisonRuntime(fixture))
	b.Run("ModelCacheDecrypt", benchmarkNativeComparisonModelCache(fixture))
	b.Run("ContextNew", benchmarkNativeComparisonContextNew(fixture))
	b.Run("InferHot", benchmarkNativeComparisonInfer(fixture))
}

func benchmarkNativeComparisonColdStart(fixture nativeComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		host := nativeComparisonRuntimeHost(fixture)
		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			services, err := newProtocolServices(host)
			if err != nil {
				b.Fatal("native cold-start construction failed")
			}
			if err := services.Close(ctx); err != nil {
				b.Fatal("native cold-start cleanup failed")
			}
			runtime.KeepAlive(services)
		}
	}
}

func benchmarkNativeComparisonBody(fixture nativeComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		codec := nativeBodyCodec{}
		raw := append([]byte(nil), fixture.request.Body...)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoded, err := codec.Encode(raw)
			if err != nil {
				b.Fatal("native body encode failed")
			}
			decoded, err := codec.Decode(encoded)
			if err != nil || !bytes.Equal(decoded, raw) {
				b.Fatal("native body round trip failed")
			}
			runtime.KeepAlive(decoded)
		}
	}
}

func benchmarkNativeComparisonCredential(fixture nativeComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		codec := nativeCredentialCodec{}
		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encrypted, err := codec.Encrypt(ctx, fixture.credential.Plain, fixture.credential.MachineKey)
			if err != nil {
				b.Fatal("native credential encrypt failed")
			}
			decrypted, err := codec.Decrypt(ctx, encrypted, fixture.credential.MachineKey)
			if err != nil || decrypted != fixture.credential.Plain {
				b.Fatal("native credential round trip failed")
			}
			runtime.KeepAlive(decrypted)
		}
	}
}

func benchmarkNativeComparisonRuntime(fixture nativeComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		generator := &nativeRuntimeFieldGenerator{host: nativeComparisonRuntimeHost(fixture)}
		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			output, err := generator.Generate(ctx, fixture.runtimeInput)
			if err != nil || output.EncryptUserInfo == "" || output.Key == "" {
				b.Fatal("native runtime-fields generation failed")
			}
			runtime.KeepAlive(output)
		}
	}
}

func benchmarkNativeComparisonModelCache(fixture nativeComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		decryptor := nativeModelCacheDecryptor{}
		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			plain, err := decryptor.Decrypt(ctx, fixture.modelExpected.Encrypted, fixture.modelInput.UID)
			if err != nil || string(plain) != fixture.modelExpected.Decrypted {
				b.Fatal("native model-cache decrypt failed")
			}
			runtime.KeepAlive(plain)
		}
	}
}

func benchmarkNativeComparisonContextNew(fixture nativeComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		factory := &nativeContextFactory{host: nativeComparisonRuntimeHost(fixture)}
		ctx := context.Background()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			created, err := factory.New(ctx, fixture.config)
			if err != nil {
				b.Fatal("native context construction failed")
			}
			if err := created.Close(); err != nil {
				b.Fatal("native context cleanup failed")
			}
			runtime.KeepAlive(created)
		}
	}
}

func benchmarkNativeComparisonInfer(fixture nativeComparisonFixture) func(*testing.B) {
	return func(b *testing.B) {
		factory := &nativeContextFactory{host: nativeComparisonRuntimeHost(fixture)}
		created, err := factory.New(context.Background(), fixture.config)
		if err != nil {
			b.Fatal("native infer context construction failed")
		}
		b.Cleanup(func() {
			if err := created.Close(); err != nil {
				b.Error("native infer context cleanup failed")
			}
		})
		operationCtx := withProtocolHostDeps(context.Background(), nativeComparisonInferHost(fixture))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			prepared, err := created.PrepareInferRequest(operationCtx, fixture.request)
			if err != nil || prepared == nil || prepared.URL == "" || len(prepared.Header) == 0 || len(prepared.Body) == 0 {
				b.Fatal("native infer preparation failed")
			}
			runtime.KeepAlive(prepared)
		}
	}
}

func nativeComparisonRuntimeHost(fixture nativeComparisonFixture) protocolHostDeps {
	return protocolHostDeps{
		Clock: comparisonClock{now: time.UnixMilli(fixture.inferTranscript.UnixMilli[0])},
		Entropy: comparisonEntropyByLength{
			16:  append([]byte(nil), fixture.runtimeTranscript.EntropyReads[0].Bytes...),
			109: append([]byte(nil), fixture.runtimeTranscript.EntropyReads[1].Bytes...),
		},
	}
}

func nativeComparisonInferHost(fixture nativeComparisonFixture) protocolHostDeps {
	return protocolHostDeps{
		Clock: comparisonClock{now: time.UnixMilli(fixture.inferTranscript.UnixMilli[0])},
		Entropy: comparisonEntropyByLength{
			16: append([]byte(nil), fixture.inferTranscript.EntropyReads[2].Bytes...),
		},
	}
}
