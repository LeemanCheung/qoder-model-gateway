package main

import (
	"fmt"
	"sync"
	"time"
)

type hostCallKind string

const (
	hostClock   hostCallKind = "clock"
	hostEntropy hostCallKind = "entropy"
)

type hostCall struct {
	Kind   hostCallKind
	Length int
}
type orderedReplay struct {
	mu                                     sync.Mutex
	transcript                             transcript
	expected                               []hostCall
	orderCursor, timeCursor, entropyCursor int
}

func newOrderedReplay(value transcript, expected []hostCall) *orderedReplay {
	return &orderedReplay{transcript: value, expected: append([]hostCall(nil), expected...)}
}
func (r *orderedReplay) expect(call hostCall) error {
	if r.orderCursor >= len(r.expected) {
		return fail("transcript-order-exhausted")
	}
	if r.expected[r.orderCursor] != call {
		return fail("transcript-order")
	}
	r.orderCursor++
	return nil
}
func (r *orderedReplay) Now() (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.expect(hostCall{Kind: hostClock}); err != nil {
		return time.Time{}, err
	}
	if r.timeCursor >= len(r.transcript.UnixMilli) {
		return time.Time{}, fail("transcript-clock-exhausted")
	}
	value := r.transcript.UnixMilli[r.timeCursor]
	r.timeCursor++
	return time.UnixMilli(value), nil
}
func (r *orderedReplay) Read(dst []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.expect(hostCall{Kind: hostEntropy, Length: len(dst)}); err != nil {
		return err
	}
	if r.entropyCursor >= len(r.transcript.EntropyReads) {
		return fail("transcript-entropy-exhausted")
	}
	read := r.transcript.EntropyReads[r.entropyCursor]
	r.entropyCursor++
	if read.Length != len(dst) {
		return fail("transcript-entropy-length")
	}
	copy(dst, read.Bytes)
	return nil
}
func (r *orderedReplay) Exhausted() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.orderCursor != len(r.expected) {
		return fail("transcript-order-unconsumed")
	}
	if r.timeCursor != len(r.transcript.UnixMilli) {
		return fail("transcript-clock-unconsumed")
	}
	if r.entropyCursor != len(r.transcript.EntropyReads) {
		return fail("transcript-entropy-unconsumed")
	}
	return nil
}
func entropyCalls(value transcript) []hostCall {
	calls := make([]hostCall, len(value.EntropyReads))
	for i, read := range value.EntropyReads {
		calls[i] = hostCall{Kind: hostEntropy, Length: read.Length}
	}
	return calls
}
func transcriptShape(value transcript) string {
	shape := "none"
	if len(value.EntropyReads) != 0 {
		shape = ""
		for i, read := range value.EntropyReads {
			if i != 0 {
				shape += ","
			}
			shape += fmt.Sprint(read.Length)
		}
	}
	return fmt.Sprintf("clock:%d,entropy:%s", len(value.UnixMilli), shape)
}
