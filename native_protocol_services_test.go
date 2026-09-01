package main

import (
	"reflect"
	"testing"
)

var (
	_ credentialCodec        = nativeCredentialCodec{}
	_ runtimeFieldGenerator  = (*nativeRuntimeFieldGenerator)(nil)
	_ modelCacheDecryptor    = nativeModelCacheDecryptor{}
	_ protocolContextFactory = (*nativeContextFactory)(nil)
	_ protocolContext        = (*nativeProtocolContext)(nil)
)

func TestNativeProtocolServicesConstructorWiresRealInferPreparer(t *testing.T) {
	host := validNativeContextHost()
	services, err := newProtocolServices(host)
	if err != nil {
		t.Fatalf("newProtocolServices() returned error kind %q", protocolErrorKindOf(err))
	}
	factory, ok := services.contextFactory.(*nativeContextFactory)
	if !ok || factory == nil {
		t.Fatalf("context factory type = %T, want *nativeContextFactory", services.contextFactory)
	}
	if reflect.ValueOf(factory.prepare).Pointer() != reflect.ValueOf(prepareNativeInferRequest).Pointer() {
		t.Fatal("native context factory is not wired to real inference preparation")
	}
}
