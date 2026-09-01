package main

import (
	"context"
	"strings"
	"testing"
)

func TestNewProtocolServicesConstructsNativeCapabilities(t *testing.T) {
	host := validNativeContextHost()
	services, err := newProtocolServices(host)
	if err != nil {
		t.Fatalf("newProtocolServices() returned error kind %q", protocolErrorKindOf(err))
	}
	if services == nil {
		t.Fatal("newProtocolServices() returned nil services")
	}
	if _, ok := services.credentials.(nativeCredentialCodec); !ok {
		t.Fatalf("credentials capability type = %T, want nativeCredentialCodec", services.credentials)
	}
	runtimeFields, ok := services.runtimeFields.(*nativeRuntimeFieldGenerator)
	if !ok || runtimeFields == nil {
		t.Fatalf("runtime-fields capability type = %T, want *nativeRuntimeFieldGenerator", services.runtimeFields)
	}
	if _, ok := services.modelCache.(nativeModelCacheDecryptor); !ok {
		t.Fatalf("model-cache capability type = %T, want nativeModelCacheDecryptor", services.modelCache)
	}
	factory, ok := services.contextFactory.(*nativeContextFactory)
	if !ok || factory == nil {
		t.Fatalf("context factory type = %T, want *nativeContextFactory", services.contextFactory)
	}
	if factory.runtimeFields != runtimeFields {
		t.Fatal("native context factory does not reuse the service runtime generator")
	}
	if factory.host.Clock != host.Clock || factory.host.Entropy != host.Entropy {
		t.Fatal("native context factory did not preserve host dependencies")
	}
	if err := services.Close(context.Background()); err != nil {
		t.Fatalf("native services Close() returned error kind %q", protocolErrorKindOf(err))
	}
}

func TestNewProtocolServicesRejectsIncompleteHost(t *testing.T) {
	valid := validNativeContextHost()
	for _, test := range []struct {
		name string
		host protocolHostDeps
	}{
		{name: "missing clock", host: protocolHostDeps{Entropy: valid.Entropy}},
		{name: "missing entropy", host: protocolHostDeps{Clock: valid.Clock}},
		{name: "missing both"},
	} {
		t.Run(test.name, func(t *testing.T) {
			services, err := newProtocolServices(test.host)
			if services != nil {
				t.Fatal("newProtocolServices() returned services for incomplete host")
			}
			if got := protocolErrorKindOf(err); got != protocolInvalidInput {
				t.Fatalf("error kind = %q, want %q", got, protocolInvalidInput)
			}
		})
	}
}

func TestValidateProtocolServicesRejectsMissingCapability(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*protocolServices)
	}{
		{name: "services", mutate: func(*protocolServices) {}},
		{name: "credentials", mutate: func(s *protocolServices) { s.credentials = nil }},
		{name: "runtime-fields", mutate: func(s *protocolServices) { s.runtimeFields = nil }},
		{name: "model-cache", mutate: func(s *protocolServices) { s.modelCache = nil }},
		{name: "context-factory", mutate: func(s *protocolServices) { s.contextFactory = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var services *protocolServices
			if test.name != "services" {
				var err error
				services, err = newNativeProtocolServices(validNativeContextHost())
				if err != nil {
					t.Fatal(err)
				}
				test.mutate(services)
			}
			err := validateProtocolServices(services)
			if got := protocolErrorKindOf(err); got != protocolBackendFailure {
				t.Fatalf("error kind = %q, want %q", got, protocolBackendFailure)
			}
			if !strings.Contains(protocolInternalError(err).Error(), test.name) {
				t.Fatalf("internal error does not identify missing %s", test.name)
			}
		})
	}
}

func TestProtocolServicesCloseIsNilSafeAndIdempotent(t *testing.T) {
	var nilServices *protocolServices
	if err := nilServices.Close(nil); err != nil {
		t.Fatalf("nil services Close() error = %v", err)
	}
	services := &protocolServices{}
	if err := services.Close(context.Background()); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := services.Close(context.Background()); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
