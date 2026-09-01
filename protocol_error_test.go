package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProtocolErrorHidesInternalCauseFromPublicStringAndUnwraps(t *testing.T) {
	cause := errors.New("SENTINEL-PROTOCOL-SECRET")
	err := newProtocolError(protocolBackendIncompatible, "protocol backend is incompatible", cause)

	if strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("Error() leaked internal cause: %q", err.Error())
	}
	if got := protocolErrorKindOf(err); got != protocolBackendIncompatible {
		t.Fatalf("protocolErrorKindOf() = %q, want %q", got, protocolBackendIncompatible)
	}
	if !errors.Is(err, cause) {
		t.Fatal("protocolError does not unwrap its internal cause")
	}
	var target *protocolError
	if !errors.As(err, &target) || target == nil || target.kind != protocolBackendIncompatible {
		t.Fatalf("errors.As() = %#v, want backend-incompatible protocolError", target)
	}
}

func TestProtocolDiagnosticErrorKeepsPublicStageAndInternalCause(t *testing.T) {
	cause := errors.New("synthetic diagnostic cause")
	classified := newProtocolError(
		protocolBackendFailure,
		"Qoder protocol operation failed",
		fmt.Errorf("read native inference clock: %w", cause),
	)
	wrapped := fmt.Errorf("prepareInferRequest: %w", classified)

	diagnostic := protocolDiagnosticError(wrapped)
	if diagnostic == nil || !errors.Is(diagnostic, cause) {
		t.Fatalf("diagnostic = %v, want internal cause", diagnostic)
	}
	if !strings.Contains(diagnostic.Error(), "prepareInferRequest: Qoder protocol operation failed") ||
		!strings.Contains(diagnostic.Error(), "read native inference clock") {
		t.Fatalf("diagnostic lacks safe stage detail: %q", diagnostic)
	}
	if wrapped.Error() != "prepareInferRequest: Qoder protocol operation failed" {
		t.Fatalf("public wrapped error changed: %q", wrapped)
	}
}

func TestProtocolDiagnosticErrorNil(t *testing.T) {
	if got := protocolDiagnosticError(nil); got != nil {
		t.Fatalf("protocolDiagnosticError(nil) = %v", got)
	}
}

func TestProtocolErrorKindOfUnknownError(t *testing.T) {
	if got := protocolErrorKindOf(errors.New("unknown")); got != protocolBackendFailure {
		t.Fatalf("protocolErrorKindOf() = %q, want %q", got, protocolBackendFailure)
	}
}

func TestProtocolInternalErrorReturnsCause(t *testing.T) {
	cause := errors.New("internal cause")
	err := newProtocolError(protocolEntropyFailure, "entropy unavailable", cause)
	if got := protocolInternalError(err); got != cause {
		t.Fatalf("protocolInternalError() = %v, want original cause", got)
	}

	plain := errors.New("plain")
	if got := protocolInternalError(plain); got != plain {
		t.Fatalf("protocolInternalError(plain) = %v, want original error", got)
	}
}

func TestProtocolErrorInspectionFindsWrappedError(t *testing.T) {
	cause := errors.New("synthetic internal failure")
	classified := newProtocolError(protocolBackendFailure, "protocol operation failed", cause)
	wrapped := fmt.Errorf("synthetic wrapper: %w", classified)
	if got := protocolErrorKindOf(wrapped); got != protocolBackendFailure {
		t.Fatalf("wrapped error kind = %q, want %q", got, protocolBackendFailure)
	}
	if got := protocolInternalError(wrapped); got != cause {
		t.Fatalf("wrapped internal error = %v, want original cause", got)
	}
}

func TestProtocolTypedNilErrorInspectionIsSafe(t *testing.T) {
	var typedNil *protocolError
	direct := error(typedNil)
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("protocol error inspection panicked: %v", recovered)
		}
	}()
	if got := protocolErrorKindOf(direct); got != protocolBackendFailure {
		t.Fatalf("typed-nil error kind = %q, want %q", got, protocolBackendFailure)
	}
	if got := protocolInternalError(direct); got != direct {
		t.Fatal("typed-nil internal error was not preserved")
	}
}
