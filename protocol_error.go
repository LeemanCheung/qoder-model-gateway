package main

import (
	"errors"
	"fmt"
)

type protocolErrorKind string

const (
	protocolInvalidInput        protocolErrorKind = "invalid-input"
	protocolAuthUnavailable     protocolErrorKind = "auth-unavailable"
	protocolBackendIncompatible protocolErrorKind = "backend-incompatible"
	protocolEntropyFailure      protocolErrorKind = "entropy-failure"
	protocolBackendFailure      protocolErrorKind = "backend-failure"
	protocolContextClosed       protocolErrorKind = "context-closed"
)

type protocolError struct {
	kind     protocolErrorKind
	public   string
	internal error
}

func (e *protocolError) Error() string {
	if e == nil {
		return "Qoder protocol operation failed"
	}
	return e.public
}

func newProtocolError(kind protocolErrorKind, public string, internal error) error {
	return &protocolError{kind: kind, public: public, internal: internal}
}

func protocolErrorKindOf(err error) protocolErrorKind {
	if target := protocolErrorFrom(err); target != nil {
		return target.kind
	}
	return protocolBackendFailure
}

func protocolInternalError(err error) error {
	if target := protocolErrorFrom(err); target != nil {
		return target.internal
	}
	return err
}

func protocolErrorFrom(err error) *protocolError {
	var target *protocolError
	if errors.As(err, &target) && target != nil {
		return target
	}
	return nil
}

func normalizeHostDependencyError(err error, fallbackKind protocolErrorKind, fallbackPublic, action string) error {
	if protocolErrorFrom(err) != nil {
		return err
	}
	return newProtocolError(fallbackKind, fallbackPublic, fmt.Errorf("%s: %w", action, err))
}

func mergeProtocolErrors(primary, secondary error) error {
	if primary == nil {
		return secondary
	}
	if secondary == nil {
		return primary
	}
	if primaryProtocol := protocolErrorFrom(primary); primaryProtocol != nil {
		return newProtocolError(
			primaryProtocol.kind,
			primaryProtocol.public,
			errors.Join(protocolInternalError(primary), protocolInternalError(secondary)),
		)
	}
	return newProtocolError(
		protocolBackendFailure,
		"Qoder protocol operation failed",
		errors.Join(primary, protocolInternalError(secondary)),
	)
}
