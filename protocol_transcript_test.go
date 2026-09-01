package main

import (
	"fmt"
	"sync"
	"time"
)

type entropyRead struct {
	Length int    `json:"length"`
	Bytes  []byte `json:"bytes"`
}

type protocolTranscript struct {
	UnixMilli    []int64       `json:"unix_milli"`
	EntropyReads []entropyRead `json:"entropy_reads"`
}

type transcriptRecorder struct {
	mu         sync.Mutex
	deps       protocolHostDeps
	transcript protocolTranscript
}

func newTranscriptRecorder(deps protocolHostDeps) *transcriptRecorder {
	return &transcriptRecorder{deps: deps}
}

func (r *transcriptRecorder) Now() (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now, err := r.deps.Clock.Now()
	if err != nil {
		return time.Time{}, err
	}
	r.transcript.UnixMilli = append(r.transcript.UnixMilli, now.UnixMilli())
	return now, nil
}

func (r *transcriptRecorder) Read(dst []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.deps.Entropy.Read(dst); err != nil {
		return err
	}
	r.transcript.EntropyReads = append(r.transcript.EntropyReads, entropyRead{
		Length: len(dst),
		Bytes:  append([]byte(nil), dst...),
	})
	return nil
}

func (r *transcriptRecorder) Transcript() protocolTranscript {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneProtocolTranscript(r.transcript)
}

type transcriptReplay struct {
	mu            sync.Mutex
	transcript    protocolTranscript
	timeCursor    int
	entropyCursor int
}

func newTranscriptReplay(transcript protocolTranscript) *transcriptReplay {
	return &transcriptReplay{transcript: cloneProtocolTranscript(transcript)}
}

func (r *transcriptReplay) Now() (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timeCursor >= len(r.transcript.UnixMilli) {
		return time.Time{}, transcriptReplayError(fmt.Errorf("clock transcript exhausted at read %d", r.timeCursor))
	}
	unixMilli := r.transcript.UnixMilli[r.timeCursor]
	r.timeCursor++
	return time.UnixMilli(unixMilli), nil
}

func (r *transcriptReplay) Read(dst []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entropyCursor >= len(r.transcript.EntropyReads) {
		return transcriptReplayError(fmt.Errorf("entropy transcript exhausted at read %d", r.entropyCursor))
	}
	readIndex := r.entropyCursor
	read := r.transcript.EntropyReads[readIndex]
	r.entropyCursor++
	if read.Length != len(dst) {
		return transcriptReplayError(fmt.Errorf("entropy read %d length = %d, want %d", readIndex, read.Length, len(dst)))
	}
	if len(read.Bytes) != read.Length {
		return transcriptReplayError(fmt.Errorf("entropy read %d byte count = %d, want %d", readIndex, len(read.Bytes), read.Length))
	}
	copy(dst, read.Bytes)
	return nil
}

func (r *transcriptReplay) Exhausted() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timeCursor != len(r.transcript.UnixMilli) || r.entropyCursor != len(r.transcript.EntropyReads) {
		return transcriptReplayError(fmt.Errorf(
			"unconsumed transcript: clock %d/%d, entropy %d/%d",
			r.timeCursor,
			len(r.transcript.UnixMilli),
			r.entropyCursor,
			len(r.transcript.EntropyReads),
		))
	}
	return nil
}

func cloneProtocolTranscript(transcript protocolTranscript) protocolTranscript {
	clone := protocolTranscript{
		UnixMilli:    append([]int64(nil), transcript.UnixMilli...),
		EntropyReads: make([]entropyRead, len(transcript.EntropyReads)),
	}
	for i, read := range transcript.EntropyReads {
		clone.EntropyReads[i] = entropyRead{
			Length: read.Length,
			Bytes:  append([]byte(nil), read.Bytes...),
		}
	}
	return clone
}

func transcriptReplayError(internal error) error {
	return newProtocolError(protocolBackendIncompatible, "protocol backend is incompatible", internal)
}
