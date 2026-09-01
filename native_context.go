package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
)

type nativePrepareFunc func(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error)

type nativeContextFactory struct {
	host          protocolHostDeps
	runtimeFields runtimeFieldGenerator
	bodyCodec     nativeBodyCodec
	prepare       nativePrepareFunc
}

type nativeContextSnapshot struct {
	host      protocolHostDeps
	bodyCodec nativeBodyCodec
	machineID string
	version   string
	user      protocolUserInfo
	scene     protocolScene
}

type nativeProtocolContext struct {
	mu        sync.RWMutex
	host      protocolHostDeps
	bodyCodec nativeBodyCodec
	machineID string
	version   string
	user      protocolUserInfo
	scene     protocolScene
	prepare   nativePrepareFunc
	closed    bool
	closeErr  error
}

var (
	_ protocolContextFactory = (*nativeContextFactory)(nil)
	_ protocolContext        = (*nativeProtocolContext)(nil)
)

func (f *nativeContextFactory) New(ctx context.Context, config protocolContextConfig) (protocolContext, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateNativeContextFactoryInput(f, config); err != nil {
		return nil, err
	}

	cloned := cloneNativeContextConfig(config)
	generator := f.runtimeFields
	if generator == nil {
		generator = &nativeRuntimeFieldGenerator{host: f.host}
	}
	operationHost := protocolHostDepsFor(ctx, f.host)
	operationCtx := withProtocolHostDeps(ctx, operationHost)
	// Pinned 1.1.34 consumes runtime-generation entropy during New but keeps the
	// caller's runtime fields as signing state; only the side effects and errors apply.
	_, err := generator.Generate(operationCtx, runtimeFieldInput{
		UID:              cloned.User.UID,
		OrganizationID:   cloned.User.OrganizationID,
		OrganizationTags: slices.Clone(cloned.User.OrganizationTags),
		DataPolicyAgreed: cloned.User.DataPolicyAgreed,
	})
	if err != nil {
		return nil, normalizeNativeContextStageError("initialize native context runtime fields", err)
	}

	prepare := f.prepare
	if prepare == nil {
		prepare = prepareNativeInferRequest
	}
	return &nativeProtocolContext{
		host:      f.host,
		bodyCodec: f.bodyCodec,
		machineID: cloned.MachineID,
		version:   cloned.Version,
		user:      cloned.User,
		scene:     cloned.Scene,
		prepare:   prepare,
	}, nil
}

func validateNativeContextFactoryInput(factory *nativeContextFactory, config protocolContextConfig) error {
	if factory == nil {
		return invalidNativeContextInput("native context factory is missing")
	}
	if factory.host.Clock == nil || factory.host.Entropy == nil {
		return invalidNativeContextInput("native context fallback host dependencies are incomplete")
	}
	switch {
	case config.MachineID == "":
		return invalidNativeContextInput("native context machine ID is empty")
	case config.Version == "":
		return invalidNativeContextInput("native context version is empty")
	case config.User.UID == "":
		return invalidNativeContextInput("native context user ID is empty")
	case config.User.OrganizationTags == nil:
		return newProtocolError(
			protocolBackendFailure,
			"Qoder protocol operation failed",
			errors.New("native context organization tags are nil"),
		)
	case config.Scene.ClientType == "":
		return invalidNativeContextInput("native context scene client type is empty")
	case config.Scene.BusinessProduct == "":
		return invalidNativeContextInput("native context scene business product is empty")
	case config.Scene.BusinessType == "":
		return invalidNativeContextInput("native context scene business type is empty")
	case config.Scene.Scene == "":
		return invalidNativeContextInput("native context scene name is empty")
	default:
		return nil
	}
}

func invalidNativeContextInput(category string) error {
	return newProtocolError(protocolInvalidInput, "native protocol context input is invalid", errors.New(category))
}

func normalizeNativeContextStageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var protocolErr *protocolError
	if errors.As(err, &protocolErr) {
		return err
	}
	return newProtocolError(
		protocolBackendFailure,
		"Qoder protocol operation failed",
		fmt.Errorf("%s: %w", stage, err),
	)
}

func cloneNativeContextConfig(config protocolContextConfig) protocolContextConfig {
	return protocolContextConfig{
		MachineID: strings.Clone(config.MachineID),
		Version:   strings.Clone(config.Version),
		User:      cloneNativeProtocolUserInfo(config.User),
		Scene:     cloneNativeProtocolScene(config.Scene),
	}
}

func cloneNativeProtocolUserInfo(user protocolUserInfo) protocolUserInfo {
	return protocolUserInfo{
		UID:              strings.Clone(user.UID),
		EncryptUserInfo:  strings.Clone(user.EncryptUserInfo),
		Key:              strings.Clone(user.Key),
		OrganizationID:   strings.Clone(user.OrganizationID),
		OrganizationTags: slices.Clone(user.OrganizationTags),
		DataPolicyAgreed: user.DataPolicyAgreed,
	}
}

func cloneNativeProtocolScene(scene protocolScene) protocolScene {
	return protocolScene{
		ClientType:      strings.Clone(scene.ClientType),
		BusinessProduct: strings.Clone(scene.BusinessProduct),
		BusinessType:    strings.Clone(scene.BusinessType),
		Scene:           strings.Clone(scene.Scene),
	}
}

func nativePrepareUnavailable(context.Context, nativeContextSnapshot, inferRequestInput) (*preparedRequest, error) {
	return nil, newProtocolError(
		protocolBackendIncompatible,
		"native inference preparation is unavailable in this stage",
		errors.New("native COSY request preparation is not implemented"),
	)
}

func (c *nativeProtocolContext) PrepareInferRequest(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil {
		return nil, nativeContextClosedError()
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, nativeContextClosedError()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot := c.snapshotLocked()
	prepare := c.prepare
	if prepare == nil {
		prepare = nativePrepareUnavailable
	}
	result, err := prepare(ctx, snapshot, cloneNativeInferRequestInput(input))
	if err != nil {
		return nil, normalizeNativeContextStageError("prepare native inference request", err)
	}
	if result == nil {
		return nil, newProtocolError(
			protocolBackendFailure,
			"Qoder protocol operation failed",
			errors.New("native inference preparer returned a nil request"),
		)
	}
	return cloneNativePreparedRequest(result), nil
}

func (c *nativeProtocolContext) snapshotLocked() nativeContextSnapshot {
	return nativeContextSnapshot{
		host:      c.host,
		bodyCodec: c.bodyCodec,
		machineID: strings.Clone(c.machineID),
		version:   strings.Clone(c.version),
		user:      cloneNativeProtocolUserInfo(c.user),
		scene:     cloneNativeProtocolScene(c.scene),
	}
}

func cloneNativeInferRequestInput(input inferRequestInput) inferRequestInput {
	input.Body = slices.Clone(input.Body)
	return input
}

func cloneNativePreparedRequest(result *preparedRequest) *preparedRequest {
	header := result.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	return &preparedRequest{
		URL:    result.URL,
		Header: header,
		Body:   slices.Clone(result.Body),
	}
}

func (c *nativeProtocolContext) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	return c.closeErr
}

func nativeContextClosedError() error {
	return newProtocolError(
		protocolContextClosed,
		"Qoder protocol context is closed",
		errors.New("native protocol context is closed"),
	)
}
