package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixedProtocolClock struct {
	times []time.Time
	err   error
	next  int
}

func (c *fixedProtocolClock) Now() (time.Time, error) {
	if c.err != nil {
		return time.Time{}, c.err
	}
	if c.next >= len(c.times) {
		return time.Time{}, errors.New("fixed clock exhausted")
	}
	now := c.times[c.next]
	c.next++
	return now, nil
}

type fixedProtocolEntropy struct {
	reads [][]byte
	err   error
	next  int
}

func (e *fixedProtocolEntropy) Read(dst []byte) error {
	if e.err != nil {
		return e.err
	}
	if e.next >= len(e.reads) {
		return errors.New("fixed entropy exhausted")
	}
	read := e.reads[e.next]
	e.next++
	if len(read) != len(dst) {
		return errors.New("fixed entropy read length mismatch")
	}
	copy(dst, read)
	return nil
}

type repeatedByteEntropy byte

func (e repeatedByteEntropy) Read(dst []byte) error {
	for i := range dst {
		dst[i] = byte(e)
	}
	return nil
}

func TestProtocolTranscriptRecordAndReplay(t *testing.T) {
	firstTime := time.UnixMilli(1_700_000_000_123)
	secondTime := time.UnixMilli(1_700_000_000_456)
	recorder := newTranscriptRecorder(protocolHostDeps{
		Clock: &fixedProtocolClock{times: []time.Time{firstTime, secondTime}},
		Entropy: &fixedProtocolEntropy{reads: [][]byte{
			{1, 2, 3, 4},
			{5, 6},
		}},
	})

	gotFirstTime, err := recorder.Now()
	if err != nil {
		t.Fatalf("recorder.Now() first error = %v", err)
	}
	firstBytes := make([]byte, 4)
	if err := recorder.Read(firstBytes); err != nil {
		t.Fatalf("recorder.Read() first error = %v", err)
	}
	gotSecondTime, err := recorder.Now()
	if err != nil {
		t.Fatalf("recorder.Now() second error = %v", err)
	}
	secondBytes := make([]byte, 2)
	if err := recorder.Read(secondBytes); err != nil {
		t.Fatalf("recorder.Read() second error = %v", err)
	}

	transcript := recorder.Transcript()
	wantTranscript := protocolTranscript{
		UnixMilli: []int64{firstTime.UnixMilli(), secondTime.UnixMilli()},
		EntropyReads: []entropyRead{
			{Length: 4, Bytes: []byte{1, 2, 3, 4}},
			{Length: 2, Bytes: []byte{5, 6}},
		},
	}
	if !reflect.DeepEqual(transcript, wantTranscript) {
		t.Fatalf("Transcript() = %#v, want %#v", transcript, wantTranscript)
	}
	if !gotFirstTime.Equal(firstTime) || !gotSecondTime.Equal(secondTime) {
		t.Fatalf("recorded times = [%v %v], want [%v %v]", gotFirstTime, gotSecondTime, firstTime, secondTime)
	}
	if !reflect.DeepEqual(firstBytes, []byte{1, 2, 3, 4}) || !reflect.DeepEqual(secondBytes, []byte{5, 6}) {
		t.Fatalf("recorded entropy = [%v %v]", firstBytes, secondBytes)
	}

	// Both Transcript and replay construction must deep-copy entropy bytes.
	transcript.EntropyReads[0].Bytes[0] = 99
	if got := recorder.Transcript().EntropyReads[0].Bytes[0]; got != 1 {
		t.Fatalf("Transcript() shares entropy bytes: first byte = %d, want 1", got)
	}
	replayInput := recorder.Transcript()
	replay := newTranscriptReplay(replayInput)
	replayInput.UnixMilli[0] = 0
	replayInput.EntropyReads[0].Bytes[0] = 88

	replayedFirstTime, err := replay.Now()
	if err != nil {
		t.Fatalf("replay.Now() first error = %v", err)
	}
	replayedFirstBytes := make([]byte, 4)
	if err := replay.Read(replayedFirstBytes); err != nil {
		t.Fatalf("replay.Read() first error = %v", err)
	}
	replayedSecondTime, err := replay.Now()
	if err != nil {
		t.Fatalf("replay.Now() second error = %v", err)
	}
	replayedSecondBytes := make([]byte, 2)
	if err := replay.Read(replayedSecondBytes); err != nil {
		t.Fatalf("replay.Read() second error = %v", err)
	}
	if err := replay.Exhausted(); err != nil {
		t.Fatalf("replay.Exhausted() error = %v (internal: %v)", err, protocolInternalError(err))
	}
	if !replayedFirstTime.Equal(firstTime) || !replayedSecondTime.Equal(secondTime) {
		t.Fatalf("replayed times = [%v %v], want [%v %v]", replayedFirstTime, replayedSecondTime, firstTime, secondTime)
	}
	if !reflect.DeepEqual(replayedFirstBytes, []byte{1, 2, 3, 4}) || !reflect.DeepEqual(replayedSecondBytes, []byte{5, 6}) {
		t.Fatalf("replayed entropy = [%v %v]", replayedFirstBytes, replayedSecondBytes)
	}
}

func TestProtocolTranscriptReplayRejectsWrongEntropyLength(t *testing.T) {
	for _, tc := range []struct {
		name       string
		transcript protocolTranscript
		dstLength  int
	}{
		{
			name: "requested length",
			transcript: protocolTranscript{EntropyReads: []entropyRead{
				{Length: 4, Bytes: []byte{1, 2, 3, 4}},
			}},
			dstLength: 3,
		},
		{
			name: "recorded bytes",
			transcript: protocolTranscript{EntropyReads: []entropyRead{
				{Length: 4, Bytes: []byte{1, 2, 3}},
			}},
			dstLength: 4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replay := newTranscriptReplay(tc.transcript)
			dst := make([]byte, tc.dstLength)
			err := replay.Read(dst)
			assertSafeTranscriptError(t, err)
		})
	}
}

func TestProtocolTranscriptReplayConsumesRejectedEntropyRead(t *testing.T) {
	validBytes := make([]byte, 109)
	for i := range validBytes {
		validBytes[i] = 0x5a
	}
	replay := newTranscriptReplay(protocolTranscript{EntropyReads: []entropyRead{
		{Length: 15, Bytes: make([]byte, 15)},
		{Length: len(validBytes), Bytes: validBytes},
	}})

	assertSafeTranscriptError(t, replay.Read(make([]byte, 16)))
	dst := make([]byte, len(validBytes))
	if err := replay.Read(dst); err != nil {
		t.Fatalf("second replay.Read() error = %v (internal: %v)", err, protocolInternalError(err))
	}
	if !reflect.DeepEqual(dst, validBytes) {
		t.Fatalf("second replay.Read() bytes = %v, want deterministic bytes", dst)
	}
	if err := replay.Exhausted(); err != nil {
		t.Fatalf("replay.Exhausted() error = %v (internal: %v)", err, protocolInternalError(err))
	}
}

func TestProtocolTranscriptReplayRejectsEntropyExhaustion(t *testing.T) {
	replay := newTranscriptReplay(protocolTranscript{})
	err := replay.Read(make([]byte, 1))
	assertSafeTranscriptError(t, err)
}

func TestProtocolTranscriptReplayRejectsClockExhaustion(t *testing.T) {
	replay := newTranscriptReplay(protocolTranscript{})
	_, err := replay.Now()
	assertSafeTranscriptError(t, err)
}

func TestProtocolTranscriptReplayRejectsUnconsumedTranscript(t *testing.T) {
	replay := newTranscriptReplay(protocolTranscript{
		UnixMilli: []int64{1_700_000_000_123},
		EntropyReads: []entropyRead{
			{Length: 2, Bytes: []byte{1, 2}},
		},
	})
	if _, err := replay.Now(); err != nil {
		t.Fatalf("replay.Now() error = %v", err)
	}
	assertSafeTranscriptError(t, replay.Exhausted())
}

func TestProtocolHostDepsContextOverride(t *testing.T) {
	fallback := protocolHostDeps{
		Clock:   &fixedProtocolClock{times: []time.Time{time.UnixMilli(1)}},
		Entropy: repeatedByteEntropy(1),
	}
	override := protocolHostDeps{
		Clock:   &fixedProtocolClock{times: []time.Time{time.UnixMilli(2)}},
		Entropy: repeatedByteEntropy(2),
	}
	ctx := withProtocolHostDeps(context.Background(), override)

	if got := protocolHostDepsFor(ctx, fallback); got.Clock != override.Clock || got.Entropy != override.Entropy {
		t.Fatalf("protocolHostDepsFor() = %#v, want context override %#v", got, override)
	}
	if got := protocolHostDepsFor(context.Background(), fallback); got.Clock != fallback.Clock || got.Entropy != fallback.Entropy {
		t.Fatalf("protocolHostDepsFor() fallback = %#v, want %#v", got, fallback)
	}
}

func assertSafeTranscriptError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("transcript replay unexpectedly succeeded")
	}
	if got := protocolErrorKindOf(err); got != protocolBackendIncompatible {
		t.Fatalf("transcript replay error kind = %q, want %q", got, protocolBackendIncompatible)
	}
	if strings.Contains(err.Error(), "fixed") || strings.Contains(err.Error(), "1, 2") {
		t.Fatalf("transcript replay public error leaked internal details: %q", err.Error())
	}
}
