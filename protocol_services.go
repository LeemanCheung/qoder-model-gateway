package main

import (
	"context"
	"fmt"
	"sync"
)

type protocolServices struct {
	credentials    credentialCodec
	runtimeFields  runtimeFieldGenerator
	modelCache     modelCacheDecryptor
	contextFactory protocolContextFactory

	closeFn   func(context.Context) error
	closeOnce sync.Once
	closeErr  error
}

func newProtocolServices(host protocolHostDeps) (*protocolServices, error) {
	services, err := newNativeProtocolServices(host)
	if err != nil {
		return nil, err
	}
	if err := validateProtocolServices(services); err != nil {
		return nil, err
	}
	return services, nil
}

func validateProtocolServices(services *protocolServices) error {
	var missing string
	switch {
	case services == nil:
		missing = "services"
	case services.credentials == nil:
		missing = "credentials"
	case services.runtimeFields == nil:
		missing = "runtime-fields"
	case services.modelCache == nil:
		missing = "model-cache"
	case services.contextFactory == nil:
		missing = "context-factory"
	default:
		return nil
	}
	return newProtocolError(
		protocolBackendFailure,
		"protocol services are incomplete",
		fmt.Errorf("required protocol capability %s is unavailable", missing),
	)
}

func newNativeProtocolServices(host protocolHostDeps) (*protocolServices, error) {
	if host.Clock == nil || host.Entropy == nil {
		return nil, newProtocolError(
			protocolInvalidInput,
			"native protocol host dependencies are invalid",
			fmt.Errorf("native protocol services require clock and entropy dependencies"),
		)
	}
	runtimeFields := &nativeRuntimeFieldGenerator{host: host}
	return &protocolServices{
		credentials:   nativeCredentialCodec{},
		runtimeFields: runtimeFields,
		modelCache:    nativeModelCacheDecryptor{},
		contextFactory: &nativeContextFactory{
			host:          host,
			runtimeFields: runtimeFields,
			bodyCodec:     nativeBodyCodec{},
			prepare:       prepareNativeInferRequest,
		},
	}, nil
}

type protocolServiceCloseError struct {
	cause error
}

func (*protocolServiceCloseError) Error() string { return "close protocol service failed" }

func (e *protocolServiceCloseError) Unwrap() error { return e.cause }

func (s *protocolServices) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.closeOnce.Do(func() {
		if s.closeFn == nil {
			return
		}
		if err := s.closeFn(ctx); err != nil {
			s.closeErr = &protocolServiceCloseError{cause: err}
		}
	})
	return s.closeErr
}
