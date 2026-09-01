package main

import (
	"context"
	"crypto/rand"
	"io"
	"time"
)

type protocolClock interface {
	Now() (time.Time, error)
}

type protocolEntropy interface {
	Read([]byte) error
}

type protocolHostDeps struct {
	Clock   protocolClock
	Entropy protocolEntropy
}

type wallProtocolClock struct{}

func (wallProtocolClock) Now() (time.Time, error) {
	return time.Now(), nil
}

type cryptoProtocolEntropy struct{}

func (cryptoProtocolEntropy) Read(dst []byte) error {
	_, err := io.ReadFull(rand.Reader, dst)
	return err
}

func productionProtocolHostDeps() protocolHostDeps {
	return protocolHostDeps{
		Clock:   wallProtocolClock{},
		Entropy: cryptoProtocolEntropy{},
	}
}

type protocolHostDepsContextKey struct{}

func withProtocolHostDeps(ctx context.Context, deps protocolHostDeps) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, protocolHostDepsContextKey{}, deps)
}

func protocolHostDepsFor(ctx context.Context, fallback protocolHostDeps) protocolHostDeps {
	if ctx == nil {
		return fallback
	}
	if deps, ok := ctx.Value(protocolHostDepsContextKey{}).(protocolHostDeps); ok {
		return deps
	}
	return fallback
}
