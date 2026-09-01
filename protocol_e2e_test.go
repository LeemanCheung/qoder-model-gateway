//go:build e2e

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Controller commands (all output is content-free):
//
//	QODER2API_E2E=1 go test -tags=e2e . -run '^TestProtocolE2E(Native|DefaultNative)$' -count=1 -v
//	QODER2API_E2E=1 QODER2API_E2E_REFRESH=1 go test -tags=e2e . -run '^TestProtocolE2ERefresh$' -count=1 -v
//
// The harness uses the production local auth directory and endpoints by default.
// Content-silent overrides are available through QODER2API_E2E_AUTH_DIR,
// QODER2API_E2E_INFER_ENDPOINT, QODER2API_E2E_OPENAPI_ENDPOINT, and
// QODER2API_E2E_WEB_ENDPOINT. QODER2API_DUMP_DIR is deliberately ignored.

const (
	protocolE2ESetupTimeout   = 90 * time.Second
	protocolE2ERouteTimeout   = 2 * time.Minute
	protocolE2ERefreshTimeout = 90 * time.Second
	protocolE2EPrompt         = "Synthetic protocol validation. Reply only OK."
)

type protocolE2EResult struct {
	Route          string
	Stream         bool
	HTTPStatus     int
	HTTPSuccess    bool
	SchemaSuccess  bool
	Duration       time.Duration
	UpstreamShapes []string
}

type protocolE2EConfig struct {
	authDir         string
	inferEndpoint   string
	openapiEndpoint string
	webEndpoint     string
}

type protocolE2ECapabilityCounts struct {
	credentialEncrypt atomic.Int64
	credentialDecrypt atomic.Int64
	runtimeGenerate   atomic.Int64
	modelCacheDecrypt atomic.Int64
	contextNew        atomic.Int64
	contextPrepare    atomic.Int64
}

type protocolE2ECountingCredentialCodec struct {
	inner  credentialCodec
	counts *protocolE2ECapabilityCounts
}

func (c *protocolE2ECountingCredentialCodec) Encrypt(ctx context.Context, plain, machineKey string) (string, error) {
	c.counts.credentialEncrypt.Add(1)
	return c.inner.Encrypt(ctx, plain, machineKey)
}

func (c *protocolE2ECountingCredentialCodec) Decrypt(ctx context.Context, blob, machineKey string) (string, error) {
	c.counts.credentialDecrypt.Add(1)
	return c.inner.Decrypt(ctx, blob, machineKey)
}

type protocolE2ECountingRuntimeFieldGenerator struct {
	inner  runtimeFieldGenerator
	counts *protocolE2ECapabilityCounts
}

func (g *protocolE2ECountingRuntimeFieldGenerator) Generate(ctx context.Context, input runtimeFieldInput) (runtimeFieldOutput, error) {
	g.counts.runtimeGenerate.Add(1)
	return g.inner.Generate(ctx, input)
}

type protocolE2ECountingModelCacheDecryptor struct {
	inner  modelCacheDecryptor
	counts *protocolE2ECapabilityCounts
}

func (d *protocolE2ECountingModelCacheDecryptor) Decrypt(ctx context.Context, blob, uid string) ([]byte, error) {
	d.counts.modelCacheDecrypt.Add(1)
	return d.inner.Decrypt(ctx, blob, uid)
}

type protocolE2ECountingContextFactory struct {
	inner  protocolContextFactory
	counts *protocolE2ECapabilityCounts
}

func (f *protocolE2ECountingContextFactory) New(ctx context.Context, config protocolContextConfig) (protocolContext, error) {
	f.counts.contextNew.Add(1)
	created, err := f.inner.New(ctx, config)
	if created == nil {
		return nil, err
	}
	return &protocolE2ECountingContext{inner: created, counts: f.counts}, err
}

type protocolE2ECountingContext struct {
	inner  protocolContext
	counts *protocolE2ECapabilityCounts
}

func (c *protocolE2ECountingContext) PrepareInferRequest(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	c.counts.contextPrepare.Add(1)
	return c.inner.PrepareInferRequest(ctx, input)
}

func (c *protocolE2ECountingContext) Close() error {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.Close()
}

const (
	protocolE2EUpstreamLineLimit  = 64 << 10
	protocolE2EUpstreamFrameLimit = 512 << 10
)

type protocolE2EUpstreamObserver struct {
	fragment             []byte
	discardLine          bool
	frameEvent           []byte
	frameData            []byte
	frameHasEvent        bool
	frameHasData         bool
	frameDataBeforeEvent bool
	shapes               map[protocolHarnessUpstreamShape]struct{}
	sawFinish            bool
	finishWithoutData    bool
	postFinish           bool
	incompleteFrame      bool
	frameFailure         protocolHarnessUpstreamReason
	finalized            bool
	success              bool
	reason               protocolHarnessUpstreamReason
	onShape              func(protocolHarnessUpstreamShape)
	onFinalize           func(protocolHarnessUpstreamReason)
}

func newProtocolE2EUpstreamObserver() *protocolE2EUpstreamObserver {
	return &protocolE2EUpstreamObserver{}
}

func (o *protocolE2EUpstreamObserver) Write(payload []byte) (int, error) {
	written := len(payload)
	for len(payload) > 0 {
		newline := bytes.IndexByte(payload, '\n')
		if newline < 0 {
			o.appendFragment(payload)
			break
		}
		o.appendFragment(payload[:newline])
		o.processFragment()
		payload = payload[newline+1:]
	}
	return written, nil
}

func (o *protocolE2EUpstreamObserver) appendFragment(fragment []byte) {
	if o.discardLine {
		return
	}
	if len(o.fragment)+len(fragment) > protocolE2EUpstreamLineLimit {
		o.zeroBytes(&o.fragment)
		o.discardLine = true
		o.incompleteFrame = true
		return
	}
	o.fragment = append(o.fragment, fragment...)
}

func (o *protocolE2EUpstreamObserver) processFragment() {
	if o.discardLine {
		o.discardLine = false
		o.zeroBytes(&o.fragment)
		return
	}
	line := bytes.TrimSuffix(o.fragment, []byte{'\r'})
	if len(line) == 0 {
		o.zeroBytes(&o.fragment)
		o.finishFrame()
		return
	}
	if line[0] == ':' {
		o.zeroBytes(&o.fragment)
		return
	}
	field, value, found := bytes.Cut(line, []byte{':'})
	if !found {
		o.addShape(protocolHarnessUpstreamUnknownField)
		o.zeroBytes(&o.fragment)
		return
	}
	switch string(field) {
	case "event":
		if o.sawFinish {
			o.postFinish = true
			o.zeroBytes(&o.fragment)
			return
		}
		if o.frameHasEvent {
			o.addShape(protocolHarnessUpstreamMultilineEvent)
		}
		value = bytes.TrimSpace(value)
		o.appendFrameValue(&o.frameEvent, value, ' ')
		o.frameHasEvent = true
	case "data":
		if o.sawFinish {
			o.postFinish = true
			o.zeroBytes(&o.fragment)
			return
		}
		if o.frameHasData {
			o.addShape(protocolHarnessUpstreamMultilineData)
		}
		if !o.frameHasEvent {
			o.frameDataBeforeEvent = true
		}
		value = bytes.TrimPrefix(value, []byte{' '})
		o.appendFrameValue(&o.frameData, value, '\n')
		o.frameHasData = true
	default:
		o.addShape(protocolHarnessUpstreamUnknownField)
	}
	o.zeroBytes(&o.fragment)
}

func (o *protocolE2EUpstreamObserver) appendFrameValue(target *[]byte, value []byte, separator byte) {
	extra := len(value)
	if len(*target) > 0 {
		extra++
	}
	if len(o.frameEvent)+len(o.frameData)+extra > protocolE2EUpstreamFrameLimit {
		o.incompleteFrame = true
		return
	}
	if len(*target) > 0 {
		*target = append(*target, separator)
	}
	*target = append(*target, value...)
}

func (o *protocolE2EUpstreamObserver) finishFrame() {
	if !o.frameHasEvent && !o.frameHasData {
		o.resetFrame()
		return
	}
	if o.sawFinish {
		o.postFinish = true
		o.resetFrame()
		return
	}
	event := string(o.frameEvent)
	if event == "finish" {
		if o.frameDataBeforeEvent {
			o.addShape(protocolHarnessUpstreamDataBeforeTerminalEvent)
		}
		if !o.frameHasData || len(o.frameData) == 0 {
			o.finishWithoutData = true
			o.resetFrame()
			return
		}
		var terminal map[string]json.RawMessage
		if json.Unmarshal(o.frameData, &terminal) != nil {
			o.markFrameFailure(protocolHarnessUpstreamFinishInvalidJSON)
		} else if terminal == nil {
			o.markFrameFailure(protocolHarnessUpstreamMalformed)
		} else {
			o.sawFinish = true
		}
		o.resetFrame()
		return
	}
	if o.frameHasData {
		o.validateEnvelope(o.frameData, event != "")
	}
	o.resetFrame()
}

func (o *protocolE2EUpstreamObserver) validateEnvelope(data []byte, namedEvent bool) {
	var envelope struct {
		StatusCodeValue *int            `json:"statusCodeValue"`
		Body            string          `json:"body"`
		Error           json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		if namedEvent {
			o.markFrameFailure(protocolHarnessUpstreamNamedEventInvalidJSON)
		} else {
			o.markFrameFailure(protocolHarnessClassifyUnnamedNonJSON(data))
		}
		return
	}
	if envelope.StatusCodeValue == nil {
		o.markFrameFailure(protocolHarnessUpstreamEnvelopeMissingStatus)
		return
	}
	if *envelope.StatusCodeValue != http.StatusOK {
		o.markFrameFailure(protocolHarnessUpstreamNonOKStatus)
		return
	}
	if len(envelope.Error) != 0 && string(bytes.TrimSpace(envelope.Error)) != "null" {
		o.markFrameFailure(protocolHarnessUpstreamOuterError)
		return
	}
	if envelope.Body == "" {
		return
	}
	var inner struct {
		Error json.RawMessage `json:"error"`
	}
	innerData := bytes.TrimSpace([]byte(envelope.Body))
	if bytes.Equal(innerData, []byte("[DONE]")) {
		o.addShape(protocolHarnessUpstreamInnerDoneMarkerShape)
		return
	}
	if len(innerData) == 0 || innerData[0] != '{' {
		o.markFrameFailure(protocolHarnessUpstreamInnerJSONNonObject)
		return
	}
	if json.Unmarshal(innerData, &inner) != nil {
		o.markFrameFailure(protocolHarnessUpstreamInnerNonJSONObj)
		return
	}
	if len(inner.Error) != 0 && string(bytes.TrimSpace(inner.Error)) != "null" {
		o.markFrameFailure(protocolHarnessUpstreamInnerError)
	}
}

func (o *protocolE2EUpstreamObserver) markFrameFailure(reason protocolHarnessUpstreamReason) {
	if o.frameFailure == "" {
		o.frameFailure = reason
	}
}

func (o *protocolE2EUpstreamObserver) addShape(shape protocolHarnessUpstreamShape) {
	if o.shapes == nil {
		o.shapes = make(map[protocolHarnessUpstreamShape]struct{})
	}
	if _, exists := o.shapes[shape]; exists {
		return
	}
	o.shapes[shape] = struct{}{}
	if o.onShape != nil {
		o.onShape(shape)
	}
}

func (o *protocolE2EUpstreamObserver) resetFrame() {
	o.zeroBytes(&o.frameEvent)
	o.zeroBytes(&o.frameData)
	o.frameHasEvent = false
	o.frameHasData = false
	o.frameDataBeforeEvent = false
}

func (*protocolE2EUpstreamObserver) zeroBytes(value *[]byte) {
	for index := range *value {
		(*value)[index] = 0
	}
	*value = nil
}

func (o *protocolE2EUpstreamObserver) Finalize(err error) {
	if o == nil || o.finalized {
		return
	}
	o.finalized = true
	if len(o.fragment) != 0 || o.discardLine || o.frameHasEvent || o.frameHasData {
		o.processFragment()
		o.finishFrame()
	}
	o.reason = o.failureReason(err)
	o.success = o.reason == ""
	if o.onFinalize != nil {
		o.onFinalize(o.reason)
	}
}

func (o *protocolE2EUpstreamObserver) failureReason(err error) protocolHarnessUpstreamReason {
	switch {
	case err != nil && !errors.Is(err, io.EOF):
		return protocolHarnessUpstreamReadFailure
	case o.postFinish:
		return protocolHarnessUpstreamPostFinish
	case o.incompleteFrame:
		return protocolHarnessUpstreamIncompleteFrame
	case o.frameFailure != "":
		return o.frameFailure
	case o.finishWithoutData:
		return protocolHarnessUpstreamFinishWithoutData
	case !o.sawFinish:
		return protocolHarnessUpstreamMissingFinish
	default:
		return ""
	}
}

func (o *protocolE2EUpstreamObserver) Success() bool {
	return o != nil && o.finalized && o.success
}

func (o *protocolE2EUpstreamObserver) Reason() protocolHarnessUpstreamReason {
	if o == nil || !o.finalized {
		return ""
	}
	return o.reason
}

func (o *protocolE2EUpstreamObserver) HasShape(shape protocolHarnessUpstreamShape) bool {
	if o == nil {
		return false
	}
	_, ok := o.shapes[shape]
	return ok
}

type protocolE2ECountingTransport struct {
	base                            http.RoundTripper
	calls                           atomic.Int64
	readFailures                    atomic.Int64
	upstreamObserved                atomic.Int64
	upstreamSuccess                 atomic.Int64
	upstreamMissingFinish           atomic.Int64
	upstreamFinishWithoutData       atomic.Int64
	upstreamFinishInvalidJSON       atomic.Int64
	upstreamNamedEventInvalidJSON   atomic.Int64
	upstreamEnvelopeDoneMarker      atomic.Int64
	upstreamEnvelopeNonJSONObj      atomic.Int64
	upstreamEnvelopeNonJSONArr      atomic.Int64
	upstreamEnvelopeNonJSONQuoted   atomic.Int64
	upstreamEnvelopeNonJSONNumber   atomic.Int64
	upstreamEnvelopeNonJSONLiteral  atomic.Int64
	upstreamEnvelopeNonJSONOther    atomic.Int64
	upstreamEnvelopeInvalidJSON     atomic.Int64
	upstreamEnvelopeMissingStatus   atomic.Int64
	upstreamNonOKStatus             atomic.Int64
	upstreamOuterError              atomic.Int64
	upstreamInnerError              atomic.Int64
	upstreamInnerJSONNonObject      atomic.Int64
	upstreamInnerNonJSONObj         atomic.Int64
	upstreamIncompleteFrame         atomic.Int64
	upstreamMalformed               atomic.Int64
	upstreamReadFailure             atomic.Int64
	upstreamPostFinish              atomic.Int64
	upstreamUnknownField            atomic.Int64
	upstreamMultilineEvent          atomic.Int64
	upstreamMultilineData           atomic.Int64
	upstreamDataBeforeTerminalEvent atomic.Int64
	upstreamInnerDoneMarkerShape    atomic.Int64
}

func (t *protocolE2ECountingTransport) upstreamSnapshot() protocolHarnessUpstreamSnapshot {
	if t == nil {
		return protocolHarnessUpstreamSnapshot{}
	}
	return protocolHarnessUpstreamSnapshot{
		Observed:                t.upstreamObserved.Load(),
		Success:                 t.upstreamSuccess.Load(),
		MissingFinish:           t.upstreamMissingFinish.Load(),
		FinishWithoutData:       t.upstreamFinishWithoutData.Load(),
		FinishInvalidJSON:       t.upstreamFinishInvalidJSON.Load(),
		NamedEventInvalidJSON:   t.upstreamNamedEventInvalidJSON.Load(),
		EnvelopeDoneMarker:      t.upstreamEnvelopeDoneMarker.Load(),
		EnvelopeNonJSONObj:      t.upstreamEnvelopeNonJSONObj.Load(),
		EnvelopeNonJSONArr:      t.upstreamEnvelopeNonJSONArr.Load(),
		EnvelopeNonJSONQuoted:   t.upstreamEnvelopeNonJSONQuoted.Load(),
		EnvelopeNonJSONNumber:   t.upstreamEnvelopeNonJSONNumber.Load(),
		EnvelopeNonJSONLiteral:  t.upstreamEnvelopeNonJSONLiteral.Load(),
		EnvelopeNonJSONOther:    t.upstreamEnvelopeNonJSONOther.Load(),
		EnvelopeInvalidJSON:     t.upstreamEnvelopeInvalidJSON.Load(),
		EnvelopeMissingStatus:   t.upstreamEnvelopeMissingStatus.Load(),
		NonOKStatus:             t.upstreamNonOKStatus.Load(),
		OuterError:              t.upstreamOuterError.Load(),
		InnerError:              t.upstreamInnerError.Load(),
		InnerJSONNonObject:      t.upstreamInnerJSONNonObject.Load(),
		InnerNonJSONObj:         t.upstreamInnerNonJSONObj.Load(),
		IncompleteFrame:         t.upstreamIncompleteFrame.Load(),
		Malformed:               t.upstreamMalformed.Load(),
		ReadFailure:             t.upstreamReadFailure.Load(),
		PostFinish:              t.upstreamPostFinish.Load(),
		UnknownField:            t.upstreamUnknownField.Load(),
		MultilineEvent:          t.upstreamMultilineEvent.Load(),
		MultilineData:           t.upstreamMultilineData.Load(),
		DataBeforeTerminalEvent: t.upstreamDataBeforeTerminalEvent.Load(),
		InnerDoneMarkerShape:    t.upstreamInnerDoneMarkerShape.Load(),
	}
}

func (t *protocolE2ECountingTransport) recordUpstreamShape(shape protocolHarnessUpstreamShape) {
	switch shape {
	case protocolHarnessUpstreamUnknownField:
		t.upstreamUnknownField.Add(1)
	case protocolHarnessUpstreamMultilineEvent:
		t.upstreamMultilineEvent.Add(1)
	case protocolHarnessUpstreamMultilineData:
		t.upstreamMultilineData.Add(1)
	case protocolHarnessUpstreamDataBeforeTerminalEvent:
		t.upstreamDataBeforeTerminalEvent.Add(1)
	case protocolHarnessUpstreamInnerDoneMarkerShape:
		t.upstreamInnerDoneMarkerShape.Add(1)
	}
}

func (t *protocolE2ECountingTransport) recordUpstreamResult(reason protocolHarnessUpstreamReason) {
	switch reason {
	case "":
		t.upstreamSuccess.Add(1)
	case protocolHarnessUpstreamMissingFinish:
		t.upstreamMissingFinish.Add(1)
	case protocolHarnessUpstreamFinishWithoutData:
		t.upstreamFinishWithoutData.Add(1)
	case protocolHarnessUpstreamFinishInvalidJSON:
		t.upstreamFinishInvalidJSON.Add(1)
	case protocolHarnessUpstreamNamedEventInvalidJSON:
		t.upstreamNamedEventInvalidJSON.Add(1)
	case protocolHarnessUpstreamEnvelopeDoneMarker:
		t.upstreamEnvelopeDoneMarker.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONObj:
		t.upstreamEnvelopeNonJSONObj.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONArr:
		t.upstreamEnvelopeNonJSONArr.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONQuoted:
		t.upstreamEnvelopeNonJSONQuoted.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONNumber:
		t.upstreamEnvelopeNonJSONNumber.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONLiteral:
		t.upstreamEnvelopeNonJSONLiteral.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONOther:
		t.upstreamEnvelopeNonJSONOther.Add(1)
	case protocolHarnessUpstreamEnvelopeInvalidJSON:
		t.upstreamEnvelopeInvalidJSON.Add(1)
	case protocolHarnessUpstreamEnvelopeMissingStatus:
		t.upstreamEnvelopeMissingStatus.Add(1)
	case protocolHarnessUpstreamNonOKStatus:
		t.upstreamNonOKStatus.Add(1)
	case protocolHarnessUpstreamOuterError:
		t.upstreamOuterError.Add(1)
	case protocolHarnessUpstreamInnerError:
		t.upstreamInnerError.Add(1)
	case protocolHarnessUpstreamInnerJSONNonObject:
		t.upstreamInnerJSONNonObject.Add(1)
	case protocolHarnessUpstreamInnerNonJSONObj:
		t.upstreamInnerNonJSONObj.Add(1)
	case protocolHarnessUpstreamIncompleteFrame:
		t.upstreamIncompleteFrame.Add(1)
	case protocolHarnessUpstreamMalformed:
		t.upstreamMalformed.Add(1)
	case protocolHarnessUpstreamReadFailure:
		t.upstreamReadFailure.Add(1)
	case protocolHarnessUpstreamPostFinish:
		t.upstreamPostFinish.Add(1)
	default:
		t.upstreamMalformed.Add(1)
	}
}

type protocolE2EObservedBody struct {
	inner    io.ReadCloser
	counter  *atomic.Int64
	failed   atomic.Bool
	observer *protocolE2EUpstreamObserver
}

func (b *protocolE2EObservedBody) Read(payload []byte) (int, error) {
	count, err := b.inner.Read(payload)
	if b.observer != nil && count > 0 {
		_, _ = b.observer.Write(payload[:count])
	}
	if err != nil {
		if b.observer != nil {
			b.observer.Finalize(err)
		}
		if !errors.Is(err, io.EOF) && b.failed.CompareAndSwap(false, true) {
			b.counter.Add(1)
		}
	}
	return count, err
}

func (b *protocolE2EObservedBody) Close() error {
	if b.observer != nil {
		b.observer.Finalize(nil)
	}
	return b.inner.Close()
}

func protocolE2EIsEventStream(response *http.Response) bool {
	if response == nil || response.StatusCode != http.StatusOK {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	return mediaType == "text/event-stream"
}

func (t *protocolE2ECountingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	response, err := t.base.RoundTrip(request)
	if response != nil && response.Body != nil {
		observed := &protocolE2EObservedBody{inner: response.Body, counter: &t.readFailures}
		if protocolE2EIsEventStream(response) {
			t.upstreamObserved.Add(1)
			observer := newProtocolE2EUpstreamObserver()
			observer.onShape = t.recordUpstreamShape
			observer.onFinalize = t.recordUpstreamResult
			observed.observer = observer
		}
		response.Body = observed
	}
	return response, err
}

type protocolE2EHarness struct {
	services         *protocolServices
	auth             *authManager
	handler          http.Handler
	capabilities     *protocolE2ECapabilityCounts
	transport        *protocolE2ECountingTransport
	refreshTransport *protocolE2ECountingTransport
	denyRefresh      *protocolHarnessDenyTransport
	readOnlyAuth     bool
	closeIdle        []func()
	closeOnce        sync.Once
	closeFailed      bool
}

type protocolE2EJSONField struct {
	key     string
	allowed []string
}

type protocolE2EJSONExpectation struct {
	strings []protocolE2EJSONField
	arrays  []string
}

type protocolE2ESSEExpectation struct {
	events            []string
	requireDone       bool
	validateData      func([]byte) bool
	validateEventData func(string, []byte) bool
}

type protocolE2ERouteSpec struct {
	name string
	path string
	json protocolE2EJSONExpectation
	sse  protocolE2ESSEExpectation
}

type protocolE2EValidation struct {
	ok       bool
	category string
}

type protocolE2EResponseProbe struct {
	header     http.Header
	status     int
	length     int64
	pipe       *io.PipeWriter
	validation <-chan protocolE2EValidation
}

func TestProtocolE2ENative(t *testing.T) {
	runProtocolE2ENative(t)
}

func TestProtocolE2ERefresh(t *testing.T) {
	runProtocolE2ERefresh(t)
}

func TestProtocolE2EDefaultNative(t *testing.T) {
	requireProtocolE2E(t)
	if _, err := parseAppConfig(nil, envLookup(nil), io.Discard); err != nil {
		protocolE2EFatal(t, "default-config")
	}
	harness := newProtocolE2EHarness(t, false)
	harness.runRoute(t, protocolE2ERouteSpecs()[0], false)
	if harness.Close() {
		t.Errorf("protocol E2E cleanup failed: status=0 category=cleanup length=0")
	}
}

type protocolE2ERoundTripperFunc func(*http.Request) (*http.Response, error)

func (f protocolE2ERoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type protocolE2ESingleReadBody struct {
	payload []byte
	read    bool
}

func (b *protocolE2ESingleReadBody) Read(payload []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	return copy(payload, b.payload), nil
}

func (*protocolE2ESingleReadBody) Close() error { return nil }

type protocolE2ESyntheticReadFailureBody struct{}

func (*protocolE2ESyntheticReadFailureBody) Read(payload []byte) (int, error) {
	return copy(payload, "synthetic"), errors.New("synthetic body read failure")
}

func (*protocolE2ESyntheticReadFailureBody) Close() error { return nil }

func TestProtocolE2EUpstreamObserverAcceptsSplitAuthoritativeFinish(t *testing.T) {
	payload := []byte("data:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\nevent:finish\ndata:{\"totalDuration\":1}\n\n")
	for split := 0; split <= len(payload); split++ {
		observer := newProtocolE2EUpstreamObserver()
		_, _ = observer.Write(payload[:split])
		_, _ = observer.Write(payload[split:])
		observer.Finalize(io.EOF)
		if !observer.Success() {
			t.Fatalf("authoritative finish rejected at synthetic split %d", split)
		}
	}
}

func TestProtocolE2EUpstreamObserverAcceptsProductionCompatibleFramesAcrossSplits(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		shapes  []protocolHarnessUpstreamShape
	}{
		{
			name:    "data before terminal event",
			payload: "data:{\"totalDuration\":1}\nevent:finish\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamDataBeforeTerminalEvent},
		},
		{
			name:    "multiline data",
			payload: "event:finish\ndata:{\"totalDuration\":\ndata:1}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamMultilineData},
		},
		{
			name:    "repeated event lines",
			payload: "event:synthetic\nevent:frame\ndata:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\nevent:finish\ndata:{}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamMultilineEvent},
		},
		{
			name:    "ignored standard and unknown fields",
			payload: "id:synthetic\nretry:1\nsynthetic:ignored\ndata:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\nevent:finish\ndata:{}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamUnknownField},
		},
		{
			name:    "inner done marker before authoritative finish",
			payload: "data:{\"statusCodeValue\":200,\"body\":\"  [DONE]  \"}\n\nevent:finish\ndata:{}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamInnerDoneMarkerShape},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(test.payload)
			for split := 0; split <= len(payload); split++ {
				observer := newProtocolE2EUpstreamObserver()
				_, _ = observer.Write(payload[:split])
				_, _ = observer.Write(payload[split:])
				observer.Finalize(io.EOF)
				if !observer.Success() {
					t.Fatalf("production-compatible upstream shape rejected as %q at synthetic split %d", observer.Reason(), split)
				}
				for _, shape := range test.shapes {
					if !observer.HasShape(shape) {
						t.Fatalf("safe upstream shape %q absent at synthetic split %d", shape, split)
					}
				}
			}
		})
	}
}

func TestProtocolE2EUpstreamObserverClassifiesUnsafeTerminalShapesAcrossSplits(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		endErr  error
		want    protocolHarnessUpstreamReason
	}{
		{name: "empty", want: protocolHarnessUpstreamMissingFinish},
		{name: "partial frame", payload: "data:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\n", want: protocolHarnessUpstreamMissingFinish},
		{name: "finish without data", payload: "event:finish\n\n", want: protocolHarnessUpstreamFinishWithoutData},
		{name: "finish data invalid JSON", payload: "event:finish\ndata:{\n\n", want: protocolHarnessUpstreamFinishInvalidJSON},
		{name: "named non-finish event data invalid JSON", payload: "event:heartbeat\ndata:{\n\n", want: protocolHarnessUpstreamNamedEventInvalidJSON},
		{name: "unnamed exact done marker", payload: "data:   [DONE]  \n\n", want: protocolHarnessUpstreamEnvelopeDoneMarker},
		{name: "unnamed nonjson object-like", payload: "data: {\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONObj},
		{name: "unnamed nonjson array-like", payload: "data: [synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONArr},
		{name: "unnamed nonjson quoted-like", payload: "data: \"synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONQuoted},
		{name: "unnamed nonjson number-like", payload: "data: -synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONNumber},
		{name: "unnamed nonjson literal-like", payload: "data: true-synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONLiteral},
		{name: "unnamed nonjson text token", payload: "data: synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONOther},
		{name: "normal envelope missing status", payload: "data:{\"body\":\"{}\"}\n\n", want: protocolHarnessUpstreamEnvelopeMissingStatus},
		{name: "non-200 status", payload: "data:{\"statusCodeValue\":503,\"body\":\"synthetic\"}\n\n", want: protocolHarnessUpstreamNonOKStatus},
		{name: "outer error", payload: "data:{\"statusCodeValue\":200,\"error\":{}}\n\n", want: protocolHarnessUpstreamOuterError},
		{name: "inner error", payload: "data:{\"statusCodeValue\":200,\"body\":\"{\\\"error\\\":{}}\"}\n\n", want: protocolHarnessUpstreamInnerError},
		{name: "inner JSON null", payload: "data:{\"statusCodeValue\":200,\"body\":\"null\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON array", payload: "data:{\"statusCodeValue\":200,\"body\":\"[]\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON string", payload: "data:{\"statusCodeValue\":200,\"body\":\"\\\"synthetic\\\"\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON number", payload: "data:{\"statusCodeValue\":200,\"body\":\"1\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON literal", payload: "data:{\"statusCodeValue\":200,\"body\":\"true\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner done marker without finish", payload: "data:{\"statusCodeValue\":200,\"body\":\"  [DONE]  \"}\n\n", want: protocolHarnessUpstreamMissingFinish},
		{name: "inner nonjson object-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"{\"}\n\n", want: protocolHarnessUpstreamInnerNonJSONObj},
		{name: "inner nonjson array-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"[synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson quoted-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"\\\"synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson number-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"-synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson literal-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"true-synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson text token", payload: "data:{\"statusCodeValue\":200,\"body\":\"synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "read failure after finish", payload: "event:finish\ndata:{}\n\n", endErr: errors.New("synthetic read failure"), want: protocolHarnessUpstreamReadFailure},
		{name: "data after finish", payload: "event:finish\ndata:{}\n\ndata:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\n", want: protocolHarnessUpstreamPostFinish},
		{name: "frame after finish", payload: "event:finish\ndata:{}\n\nevent:synthetic\n\n", want: protocolHarnessUpstreamPostFinish},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(test.payload)
			for split := 0; split <= len(payload); split++ {
				observer := newProtocolE2EUpstreamObserver()
				_, _ = observer.Write(payload[:split])
				_, _ = observer.Write(payload[split:])
				observer.Finalize(test.endErr)
				if observer.Success() {
					t.Fatalf("unsafe upstream terminal shape was accepted at synthetic split %d", split)
				}
				if got := observer.Reason(); got != test.want {
					t.Fatalf("upstream reason = %q, want %q at synthetic split %d", got, test.want, split)
				}
			}
		})
	}
}

func TestProtocolE2EUpstreamObserverClassifiesBoundedIncompleteFrame(t *testing.T) {
	observer := newProtocolE2EUpstreamObserver()
	_, _ = observer.Write(append([]byte("data:"), bytes.Repeat([]byte{'x'}, protocolE2EUpstreamLineLimit+1)...))
	observer.Finalize(io.EOF)
	if got := observer.Reason(); got != protocolHarnessUpstreamIncompleteFrame {
		t.Fatalf("bounded incomplete frame reason = %q, want %q", got, protocolHarnessUpstreamIncompleteFrame)
	}
}

func TestProtocolE2EUpstreamObservedBodyCloseFinalizesCompleteFinish(t *testing.T) {
	observer := newProtocolE2EUpstreamObserver()
	body := &protocolE2EObservedBody{
		inner:    &protocolE2ESingleReadBody{payload: []byte("event:finish\ndata:{}\n\n")},
		counter:  &atomic.Int64{},
		observer: observer,
	}
	buffer := make([]byte, 128)
	if count, err := body.Read(buffer); count == 0 || err != nil {
		t.Fatal("synthetic finish body read failed")
	}
	if err := body.Close(); err != nil {
		t.Fatal("synthetic finish body close failed")
	}
	if !observer.Success() {
		t.Fatal("complete authoritative finish did not finalize on close")
	}
}

func TestProtocolE2ETransportIgnoresNonEventStreamSuccess(t *testing.T) {
	transport := &protocolE2ECountingTransport{base: protocolE2ERoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"queue":{"isQueued":true}}`)),
		}, nil
	})}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://example.invalid/synthetic-queue", nil))
	if err != nil || response == nil {
		t.Fatal("synthetic non-event-stream response setup failed")
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if transport.upstreamSnapshot() != (protocolHarnessUpstreamSnapshot{}) {
		t.Fatal("non-event-stream response was classified as authoritative upstream SSE")
	}
}

func TestProtocolE2ETransportReadFailureAccounting(t *testing.T) {
	transport := &protocolE2ECountingTransport{base: protocolE2ERoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &protocolE2ESyntheticReadFailureBody{},
		}, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "https://example.invalid/synthetic-read-failure", nil)
	response, err := transport.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		t.Fatal("synthetic transport response setup failed")
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if transport.calls.Load() != 1 || transport.readFailures.Load() != 1 {
		t.Fatalf("transport calls/read failures = %d/%d, want 1/1", transport.calls.Load(), transport.readFailures.Load())
	}
}

func requireProtocolE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("QODER2API_E2E") != "1" {
		t.Skip("authorized protocol E2E disabled; set QODER2API_E2E=1")
	}
}

func protocolE2EEnvironmentConfig() protocolE2EConfig {
	authDir := strings.TrimSpace(os.Getenv("QODER2API_E2E_AUTH_DIR"))
	if authDir == "" {
		authDir = filepath.Join(homeDir(), ".qoder", ".auth")
	}
	return protocolE2EConfig{
		authDir:         authDir,
		inferEndpoint:   strings.TrimSpace(os.Getenv("QODER2API_E2E_INFER_ENDPOINT")),
		openapiEndpoint: strings.TrimSpace(os.Getenv("QODER2API_E2E_OPENAPI_ENDPOINT")),
		webEndpoint:     strings.TrimSpace(os.Getenv("QODER2API_E2E_WEB_ENDPOINT")),
	}
}

func protocolE2ECloneDefaultTransport() (http.RoundTripper, func()) {
	if standard, ok := http.DefaultTransport.(*http.Transport); ok {
		cloned := standard.Clone()
		return cloned, cloned.CloseIdleConnections
	}
	return http.DefaultTransport, func() {}
}

func protocolE2ERequireLocalAuth(t *testing.T, authDir string) {
	t.Helper()
	for _, name := range []string{"machine_id", "user"} {
		info, err := os.Stat(filepath.Join(authDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Skip("authorized encrypted local credential prerequisite unavailable")
		}
	}
}

func protocolE2EFatal(t *testing.T, category string) {
	t.Helper()
	t.Fatalf("protocol E2E setup failed: status=0 category=%s length=0", category)
}

func newProtocolE2EHarness(t *testing.T, allowRefresh bool) *protocolE2EHarness {
	t.Helper()
	requireProtocolE2E(t)
	config := protocolE2EEnvironmentConfig()
	protocolE2ERequireLocalAuth(t, config.authDir)

	setupCtx, cancel := context.WithTimeout(context.Background(), protocolE2ESetupTimeout)
	defer cancel()

	capabilities := &protocolE2ECapabilityCounts{}
	services, err := newProtocolServices(productionProtocolHostDeps())
	if err != nil || services == nil {
		protocolE2EFatal(t, "protocol-services")
	}

	harness := &protocolE2EHarness{
		services:     services,
		capabilities: capabilities,
		readOnlyAuth: !allowRefresh,
	}
	t.Cleanup(func() {
		harness.Close()
	})
	harness.installCapabilityCounters()

	auth, err := newAuthManager(
		services,
		config.authDir,
		config.openapiEndpoint,
		config.inferEndpoint,
		config.webEndpoint,
		func(string, ...any) {},
	)
	if err != nil || auth == nil {
		protocolE2EFatal(t, "auth-construction")
	}
	harness.auth = auth
	if err := auth.load(setupCtx); err != nil {
		protocolE2EFatal(t, "credential-load")
	}
	clearAuthManagerDirtyForHarness(auth)
	if harness.capabilities.credentialDecrypt.Load() == 0 {
		t.Skip("authorized encrypted local credential prerequisite unavailable")
	}
	if !protocolE2EHasUsableToken(auth) {
		t.Skip("authorized local token prerequisite unavailable")
	}
	if allowRefresh {
		baseTransport, closeIdle := protocolE2ECloneDefaultTransport()
		harness.refreshTransport = &protocolE2ECountingTransport{base: baseTransport}
		harness.closeIdle = append(harness.closeIdle, closeIdle)
		auth.httpc = &http.Client{
			Transport:     harness.refreshTransport,
			Timeout:       protocolE2ERefreshTimeout,
			CheckRedirect: protocolHarnessRejectRedirect,
		}
	} else {
		protocolE2ERequireFreshCredential(t, auth)
		harness.denyRefresh = &protocolHarnessDenyTransport{}
		auth.httpc = &http.Client{
			Transport:     harness.denyRefresh,
			Timeout:       protocolE2ERefreshTimeout,
			CheckRedirect: protocolHarnessRejectRedirect,
		}
	}

	input := protocolE2ERuntimeInput(auth)
	if _, err := services.runtimeFields.Generate(setupCtx, input); err != nil {
		protocolE2EFatal(t, "runtime-fields")
	}
	resolver := protocolE2ELoadCatalog(t, setupCtx, harness)

	baseTransport, closeIdle := protocolE2ECloneDefaultTransport()
	harness.closeIdle = append(harness.closeIdle, closeIdle)
	harness.transport = &protocolE2ECountingTransport{base: baseTransport}
	server := &server{
		auth:   auth,
		models: resolver,
		httpc: &http.Client{
			Transport:     harness.transport,
			Timeout:       protocolE2ERouteTimeout,
			CheckRedirect: protocolHarnessRejectRedirect,
		},
		logf:    func(string, ...any) {},
		dumpDir: "",
	}
	harness.handler = server.handler()
	return harness
}

func (h *protocolE2EHarness) installCapabilityCounters() {
	installProtocolE2ECapabilityCounters(h.services, h.capabilities)
}

func installProtocolE2ECapabilityCounters(services *protocolServices, counts *protocolE2ECapabilityCounts) {
	if services == nil || counts == nil {
		return
	}
	services.credentials = &protocolE2ECountingCredentialCodec{inner: services.credentials, counts: counts}
	services.runtimeFields = &protocolE2ECountingRuntimeFieldGenerator{inner: services.runtimeFields, counts: counts}
	services.modelCache = &protocolE2ECountingModelCacheDecryptor{inner: services.modelCache, counts: counts}
	services.contextFactory = &protocolE2ECountingContextFactory{inner: services.contextFactory, counts: counts}
}

func (c *protocolE2ECapabilityCounts) snapshot() protocolHarnessCapabilitySnapshot {
	if c == nil {
		return protocolHarnessCapabilitySnapshot{}
	}
	return protocolHarnessCapabilitySnapshot{
		CredentialEncrypt: c.credentialEncrypt.Load(),
		CredentialDecrypt: c.credentialDecrypt.Load(),
		RuntimeGenerate:   c.runtimeGenerate.Load(),
		ModelCacheDecrypt: c.modelCacheDecrypt.Load(),
		ContextNew:        c.contextNew.Load(),
		ContextPrepare:    c.contextPrepare.Load(),
	}
}

func protocolE2EHasUsableToken(auth *authManager) bool {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.ui != nil && auth.ui.SecurityOAuthToken != ""
}

func protocolE2EHasRefreshToken(auth *authManager) bool {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.ui != nil && auth.ui.RefreshToken != ""
}

func protocolE2ERequireFreshCredential(t *testing.T, auth *authManager) {
	t.Helper()
	auth.mu.Lock()
	expiry := int64(0)
	if auth.ui != nil {
		expiry = auth.ui.ExpireTime
	}
	auth.mu.Unlock()
	if expiry != 0 && expiry-refreshSkewSec < time.Now().Unix() {
		t.Skip("authorized local credential requires refresh; run the refresh E2E gate")
	}
}

func protocolE2ERuntimeInput(auth *authManager) runtimeFieldInput {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.runtimeFieldInputLocked()
}

func protocolE2ELoadCatalog(t *testing.T, ctx context.Context, harness *protocolE2EHarness) *modelResolver {
	t.Helper()
	if harness == nil || harness.auth == nil || harness.services == nil {
		protocolE2EFatal(t, "catalog-harness")
	}
	auth := harness.auth
	services := harness.services
	auth.mu.Lock()
	authFile := auth.authFile
	uid := ""
	if auth.ui != nil {
		uid = auth.ui.UID
	}
	auth.mu.Unlock()
	if uid == "" {
		t.Skip("authorized catalog UID prerequisite unavailable")
	}
	cachePath := filepath.Clean(filepath.Join(filepath.Dir(authFile), "..", ".models", uid, "catalog-v6"))
	info, err := os.Stat(cachePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Skip("authorized encrypted local catalog prerequisite unavailable")
	}
	if services.modelCache == nil || harness.capabilities == nil {
		protocolE2EFatal(t, "catalog-decryptor")
	}
	beforeDecrypt := harness.capabilities.modelCacheDecrypt.Load()
	merged := false
	catalog := loadCatalog(ctx, services.modelCache, authFile, uid, "", func(format string, _ ...any) {
		if format == "catalog merged: %d models" {
			merged = true
		}
	})
	afterDecrypt := harness.capabilities.modelCacheDecrypt.Load()
	if !merged || !protocolHarnessCapabilityCallAdvanced(beforeDecrypt, afterDecrypt) {
		protocolE2EFatal(t, "catalog-decrypt-or-schema")
	}
	resolver := newModelResolver(catalog, nil, "auto", "ultimate")
	if resolver == nil || len(resolver.byKey) == 0 {
		protocolE2EFatal(t, "model-resolver-empty")
	}
	return resolver
}

func protocolE2ERouteSpecs() []protocolE2ERouteSpec {
	return []protocolE2ERouteSpec{
		{
			name: "anthropic_messages",
			path: "/v1/messages",
			json: protocolE2EJSONExpectation{
				strings: []protocolE2EJSONField{
					{key: "type", allowed: []string{"message"}},
					{key: "role", allowed: []string{"assistant"}},
				},
				arrays: []string{"content"},
			},
			sse: protocolE2ESSEExpectation{
				events:            []string{"message_start", "message_stop"},
				validateEventData: protocolHarnessAnthropicStreamFrameValid,
			},
		},
		{
			name: "openai_chat_completions",
			path: "/v1/chat/completions",
			json: protocolE2EJSONExpectation{
				strings: []protocolE2EJSONField{{key: "object", allowed: []string{"chat.completion"}}},
				arrays:  []string{"choices"},
			},
			sse: protocolE2ESSEExpectation{
				requireDone:  true,
				validateData: protocolHarnessChatStreamFrameValid,
			},
		},
		{
			name: "openai_responses",
			path: "/v1/responses",
			json: protocolE2EJSONExpectation{
				strings: []protocolE2EJSONField{
					{key: "object", allowed: []string{"response"}},
					{key: "status", allowed: []string{"completed", "incomplete"}},
				},
				arrays: []string{"output"},
			},
			sse: protocolE2ESSEExpectation{
				events:            []string{"response.created", "response.completed"},
				validateEventData: protocolHarnessResponsesStreamFrameValid,
			},
		},
	}
}

func protocolE2ERequestBody(route string, stream bool) ([]byte, error) {
	switch route {
	case "anthropic_messages":
		return json.Marshal(map[string]any{
			"model":      "auto",
			"max_tokens": 8,
			"stream":     stream,
			"messages": []map[string]any{{
				"role": "user", "content": protocolE2EPrompt,
			}},
		})
	case "openai_chat_completions":
		return json.Marshal(map[string]any{
			"model":      "auto",
			"max_tokens": 8,
			"stream":     stream,
			"messages": []map[string]any{{
				"role": "user", "content": protocolE2EPrompt,
			}},
		})
	case "openai_responses":
		return json.Marshal(map[string]any{
			"model":             "auto",
			"max_output_tokens": 8,
			"stream":            stream,
			"input":             protocolE2EPrompt,
		})
	default:
		return nil, errors.New("unknown synthetic route")
	}
}

func newProtocolE2EResponseProbe(stream bool, jsonExpectation protocolE2EJSONExpectation, sseExpectation protocolE2ESSEExpectation) *protocolE2EResponseProbe {
	reader, writer := io.Pipe()
	validation := make(chan protocolE2EValidation, 1)
	go func() {
		defer reader.Close()
		if stream {
			validation <- validateProtocolE2ESSE(reader, sseExpectation)
			return
		}
		validation <- validateProtocolE2EJSON(reader, jsonExpectation)
	}()
	return &protocolE2EResponseProbe{
		header:     make(http.Header),
		pipe:       writer,
		validation: validation,
	}
}

func (p *protocolE2EResponseProbe) Header() http.Header {
	return p.header
}

func (p *protocolE2EResponseProbe) WriteHeader(status int) {
	if p.status == 0 {
		p.status = status
	}
}

func (p *protocolE2EResponseProbe) Write(payload []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	p.length += int64(len(payload))
	return p.pipe.Write(payload)
}

func (*protocolE2EResponseProbe) Flush() {}

func (p *protocolE2EResponseProbe) finish() protocolE2EValidation {
	_ = p.pipe.Close()
	return <-p.validation
}

func (p *protocolE2EResponseProbe) statusCode() int {
	if p.status == 0 {
		return http.StatusOK
	}
	return p.status
}

func validateProtocolE2EJSON(reader io.Reader, expectation protocolE2EJSONExpectation) protocolE2EValidation {
	defer func() {
		_, _ = io.Copy(io.Discard, reader)
	}()
	decoder := json.NewDecoder(reader)
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return protocolE2EValidation{category: "json-object"}
	}
	seenStrings := make([]bool, len(expectation.strings))
	seenArrays := make([]bool, len(expectation.arrays))
	valid := true
	category := ""
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, keyOK := keyToken.(string)
		if err != nil || !keyOK {
			valid = false
			category = "json-schema"
			break
		}
		matched := false
		for index, field := range expectation.strings {
			if key != field.key {
				continue
			}
			matched = true
			value, err := decoder.Token()
			if err != nil {
				valid = false
				category = "json-schema"
				break
			}
			if opening, ok := value.(json.Delim); ok {
				_ = discardProtocolE2EJSONContainer(decoder, opening)
				valid = false
				category = "json-discriminator"
				break
			}
			stringValue, ok := value.(string)
			if !ok || !protocolE2EStringAllowed(stringValue, field.allowed) {
				valid = false
				category = "json-discriminator"
				break
			}
			seenStrings[index] = true
			break
		}
		if !valid {
			break
		}
		if matched {
			continue
		}
		for index, arrayKey := range expectation.arrays {
			if key != arrayKey {
				continue
			}
			matched = true
			value, err := decoder.Token()
			if err != nil {
				valid = false
				category = "json-schema"
				break
			}
			opening, ok := value.(json.Delim)
			if !ok || opening != json.Delim('[') {
				if ok {
					_ = discardProtocolE2EJSONContainer(decoder, opening)
				}
				valid = false
				category = "json-array"
				break
			}
			seenArrays[index] = true
			if err := discardProtocolE2EJSONContainer(decoder, opening); err != nil {
				valid = false
				category = "json-schema"
			}
			break
		}
		if !valid {
			break
		}
		if matched {
			continue
		}
		if err := discardProtocolE2EJSONValue(decoder); err != nil {
			valid = false
			category = "json-schema"
			break
		}
	}
	if valid {
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			valid = false
			category = "json-schema"
		}
	}
	if valid {
		if _, err := decoder.Token(); err != io.EOF {
			valid = false
			category = "json-trailing"
		}
	}
	if valid {
		for _, seen := range seenStrings {
			if !seen {
				valid = false
				category = "json-discriminator"
				break
			}
		}
	}
	if valid {
		for _, seen := range seenArrays {
			if !seen {
				valid = false
				category = "json-array"
				break
			}
		}
	}
	if !valid {
		return protocolE2EValidation{category: category}
	}
	return protocolE2EValidation{ok: true}
}

func protocolE2EStringAllowed(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func discardProtocolE2EJSONValue(decoder *json.Decoder) error {
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	opening, ok := value.(json.Delim)
	if !ok {
		return nil
	}
	return discardProtocolE2EJSONContainer(decoder, opening)
}

func discardProtocolE2EJSONContainer(decoder *json.Decoder, opening json.Delim) error {
	switch opening {
	case json.Delim('{'):
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			if _, ok := key.(string); !ok {
				return errors.New("invalid JSON object key")
			}
			if err := discardProtocolE2EJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("invalid JSON object close")
		}
		return nil
	case json.Delim('['):
		for decoder.More() {
			if err := discardProtocolE2EJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid JSON array close")
		}
		return nil
	default:
		return errors.New("invalid JSON container")
	}
}

func validateProtocolE2ESSE(reader io.Reader, expectation protocolE2ESSEExpectation) protocolE2EValidation {
	defer func() {
		_, _ = io.Copy(io.Discard, reader)
	}()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 512<<10)
	seenEvents := make([]bool, len(expectation.events))
	sawData := false
	sawFrame := false
	frameHasData := false
	sawDone := false
	sawValidatedData := false
	dataValid := true
	currentEvent := ""
	for scanner.Scan() {
		line := bytes.TrimSuffix(scanner.Bytes(), []byte{'\r'})
		if len(line) == 0 {
			if frameHasData {
				sawFrame = true
			}
			frameHasData = false
			currentEvent = ""
			continue
		}
		if bytes.HasPrefix(line, []byte("event:")) {
			event := bytes.TrimSpace(line[len("event:"):])
			currentEvent = string(event)
			for index, required := range expectation.events {
				if bytes.Equal(event, []byte(required)) {
					seenEvents[index] = true
				}
			}
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			data := bytes.TrimSpace(line[len("data:"):])
			if len(data) > 0 {
				sawData = true
				frameHasData = true
			}
			if bytes.Equal(data, []byte("[DONE]")) {
				sawDone = true
				continue
			}
			if expectation.validateData != nil && len(data) > 0 {
				if expectation.validateData(data) {
					sawValidatedData = true
				} else {
					dataValid = false
				}
			}
			if expectation.validateEventData != nil && len(data) > 0 {
				if expectation.validateEventData(currentEvent, data) {
					sawValidatedData = true
				} else {
					dataValid = false
				}
			}
		}
	}
	if frameHasData {
		sawFrame = true
	}
	if scanner.Err() != nil {
		return protocolE2EValidation{category: "sse-read"}
	}
	if !sawData || !sawFrame {
		return protocolE2EValidation{category: "sse-framing"}
	}
	if !dataValid || ((expectation.validateData != nil || expectation.validateEventData != nil) && !sawValidatedData) {
		return protocolE2EValidation{category: "sse-payload"}
	}
	for _, seen := range seenEvents {
		if !seen {
			return protocolE2EValidation{category: "sse-event"}
		}
	}
	if expectation.requireDone && !sawDone {
		return protocolE2EValidation{category: "sse-terminal"}
	}
	return protocolE2EValidation{ok: true}
}

func protocolE2EContentTypeOK(stream bool, contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if stream {
		return mediaType == "text/event-stream"
	}
	return mediaType == "application/json"
}

func (h *protocolE2EHarness) runRoute(t *testing.T, spec protocolE2ERouteSpec, stream bool) protocolE2EResult {
	t.Helper()
	body, err := protocolE2ERequestBody(spec.name, stream)
	if err != nil {
		protocolE2EFatal(t, "synthetic-request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), protocolE2ERouteTimeout)
	defer cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, spec.path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	probe := newProtocolE2EResponseProbe(stream, spec.json, spec.sse)
	beforeCalls := h.transport.calls.Load()
	beforeReadFailures := h.transport.readFailures.Load()
	beforeUpstream := h.transport.upstreamSnapshot()
	beforePrepare := h.capabilities.contextPrepare.Load()
	beforeRefresh := int64(0)
	if h.denyRefresh != nil {
		beforeRefresh = h.denyRefresh.calls.Load()
	}
	started := time.Now()
	h.handler.ServeHTTP(probe, request)
	validation := probe.finish()
	duration := time.Since(started).Round(time.Millisecond)
	afterCalls := h.transport.calls.Load()
	afterPrepare := h.capabilities.contextPrepare.Load()
	afterRefresh := beforeRefresh
	if h.denyRefresh != nil {
		afterRefresh = h.denyRefresh.calls.Load()
	}
	status := probe.statusCode()
	httpSuccess := status == http.StatusOK
	schemaSuccess := validation.ok && protocolE2EContentTypeOK(stream, probe.header.Get("Content-Type"))
	afterUpstream := h.transport.upstreamSnapshot()
	upstreamReason := protocolHarnessUpstreamReasonDelta(beforeUpstream, afterUpstream)
	upstreamShapes := protocolHarnessUpstreamShapeDelta(beforeUpstream, afterUpstream)
	result := protocolE2EResult{
		Route:          spec.name,
		Stream:         stream,
		HTTPStatus:     status,
		HTTPSuccess:    httpSuccess,
		SchemaSuccess:  schemaSuccess,
		Duration:       duration,
		UpstreamShapes: upstreamShapes,
	}
	protocolE2ELogResult(t, result)

	category := ""
	switch {
	case ctx.Err() != nil:
		category = "route-timeout"
	case !httpSuccess:
		category = "http-status"
	case !protocolE2EContentTypeOK(stream, probe.header.Get("Content-Type")):
		category = "content-type"
	case upstreamReason != "":
		category = "upstream-sse-" + string(upstreamReason)
	case h.transport.readFailures.Load() != beforeReadFailures:
		category = "upstream-body-read"
	case !validation.ok:
		category = validation.category
	case !protocolHarnessPrimaryAttemptsValid(afterPrepare-beforePrepare, afterCalls-beforeCalls):
		category = "primary-attempt-count"
	case afterRefresh != beforeRefresh:
		category = "unexpected-refresh"
	}
	if category != "" {
		t.Errorf(
			"protocol E2E route failed: backend=native route=%s stream=%t status=%d category=%s length=%d",
			result.Route,
			result.Stream,
			result.HTTPStatus,
			category,
			probe.length,
		)
	}
	return result
}

func protocolE2ELogResult(t *testing.T, result protocolE2EResult) {
	t.Helper()
	upstreamShapes := strings.Join(result.UpstreamShapes, ",")
	if upstreamShapes == "" {
		upstreamShapes = "none"
	}
	t.Logf(
		"protocol_e2e backend=native route=%s stream=%t status=%d http_success=%t schema_success=%t duration=%s upstream_shapes=%s",
		result.Route,
		result.Stream,
		result.HTTPStatus,
		result.HTTPSuccess,
		result.SchemaSuccess,
		result.Duration,
		upstreamShapes,
	)
}

func runProtocolE2ENative(t *testing.T) {
	t.Helper()
	requireProtocolE2E(t)
	harness := newProtocolE2EHarness(t, false)
	for _, spec := range protocolE2ERouteSpecs() {
		for _, stream := range []bool{false, true} {
			name := spec.name + "/nonstream"
			if stream {
				name = spec.name + "/stream"
			}
			t.Run(name, func(t *testing.T) {
				harness.runRoute(t, spec, stream)
			})
		}
	}
	if harness.Close() {
		t.Errorf("protocol E2E cleanup failed: status=0 category=cleanup length=0")
	}
	if !harness.capabilities.snapshot().complete(false) {
		t.Errorf("protocol E2E native gate failed: status=0 category=capability-not-executed length=0")
	}
}

func runProtocolE2ERefresh(t *testing.T) {
	t.Helper()
	requireProtocolE2E(t)
	if os.Getenv("QODER2API_E2E_REFRESH") != "1" {
		t.Skip("authorized refresh E2E disabled; set QODER2API_E2E_REFRESH=1")
	}
	harness := newProtocolE2EHarness(t, true)
	if !protocolE2EHasRefreshToken(harness.auth) {
		t.Skip("authorized refresh token prerequisite unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), protocolE2ERefreshTimeout)
	beforeRefresh := protocolHarnessRefreshCounts{
		HTTP:    harness.refreshTransport.calls.Load(),
		Encrypt: harness.capabilities.credentialEncrypt.Load(),
		Runtime: harness.capabilities.runtimeGenerate.Load(),
		Context: harness.capabilities.contextNew.Load(),
	}
	started := time.Now()
	err := harness.auth.forceRefresh(ctx)
	duration := time.Since(started).Round(time.Millisecond)
	cancel()
	if err != nil {
		t.Fatalf("protocol E2E refresh failed: status=0 category=refresh-transaction length=0")
	}
	afterRefresh := protocolHarnessRefreshCounts{
		HTTP:    harness.refreshTransport.calls.Load(),
		Encrypt: harness.capabilities.credentialEncrypt.Load(),
		Runtime: harness.capabilities.runtimeGenerate.Load(),
		Context: harness.capabilities.contextNew.Load(),
	}
	if !protocolHarnessRefreshAccountingValid(beforeRefresh, afterRefresh) {
		t.Fatalf("protocol E2E refresh failed: status=0 category=refresh-accounting length=0")
	}
	harness.denyRefresh = &protocolHarnessDenyTransport{}
	harness.auth.httpc = &http.Client{
		Transport:     harness.denyRefresh,
		Timeout:       protocolE2ERefreshTimeout,
		CheckRedirect: protocolHarnessRejectRedirect,
	}
	protocolE2ELogResult(t, protocolE2EResult{
		Route:         "force_refresh",
		HTTPStatus:    http.StatusOK,
		HTTPSuccess:   true,
		SchemaSuccess: true,
		Duration:      duration,
	})
	beforePostRefreshRoute := harness.denyRefresh.calls.Load()
	harness.runRoute(t, protocolE2ERouteSpecs()[0], false)
	if harness.denyRefresh.calls.Load() != beforePostRefreshRoute {
		t.Errorf("protocol E2E refresh failed: status=0 category=post-refresh-attempt-count length=0")
	}
	if harness.Close() {
		t.Errorf("protocol E2E cleanup failed: status=0 category=cleanup length=0")
	}
}

func (h *protocolE2EHarness) Close() bool {
	if h == nil {
		return false
	}
	h.closeOnce.Do(func() {
		if h.auth != nil {
			var authCloseErr error
			if h.readOnlyAuth {
				authCloseErr = closeAuthManagerReadOnlyForTest(h.auth)
			} else {
				authCloseErr = h.auth.Close()
			}
			if authCloseErr != nil {
				h.closeFailed = true
			}
		}
		if h.services != nil && h.services.Close(context.Background()) != nil {
			h.closeFailed = true
		}
		for _, closeIdle := range h.closeIdle {
			if closeIdle != nil {
				closeIdle()
			}
		}
	})
	return h.closeFailed
}
