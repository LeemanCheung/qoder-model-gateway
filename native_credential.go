package main

import (
	"context"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"
)

type nativeCredentialCodec struct{}

var _ credentialCodec = nativeCredentialCodec{}

func (nativeCredentialCodec) Encrypt(ctx context.Context, plain, machineKey string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key, err := nativeCredentialKey(machineKey)
	if err != nil {
		return "", err
	}
	ciphertext, err := aesCBCEncryptPKCS7([]byte(plain), key, key)
	if err != nil {
		return "", nativeCredentialBackendFailure(fmt.Errorf("encrypt AES-CBC credential: %w", err))
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (nativeCredentialCodec) Decrypt(ctx context.Context, blob, machineKey string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key, err := nativeCredentialKey(machineKey)
	if err != nil {
		return "", err
	}
	ciphertext, err := decodeStrictStdBase64(blob)
	if err != nil {
		return "", nativeCredentialBackendIncompatible(fmt.Errorf("decode credential envelope: %w", err))
	}
	if len(ciphertext) == 0 {
		return "", nativeCredentialBackendIncompatible(errors.New("credential ciphertext is empty"))
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", nativeCredentialBackendIncompatible(fmt.Errorf("credential ciphertext length %d is not block aligned", len(ciphertext)))
	}
	plain, err := aesCBCDecryptPKCS7(ciphertext, key, key)
	if err != nil {
		return "", nativeCredentialBackendIncompatible(fmt.Errorf("decrypt credential envelope: %w", err))
	}
	if !utf8.Valid(plain) {
		return "", nativeCredentialBackendIncompatible(errors.New("credential plaintext is not valid UTF-8"))
	}
	return string(plain), nil
}

func nativeCredentialKey(machineKey string) ([]byte, error) {
	key := []byte(machineKey)
	if len(key) != aes.BlockSize {
		return nil, newProtocolError(
			protocolInvalidInput,
			"credential input is invalid",
			fmt.Errorf("credential machine key byte length %d, want %d", len(key), aes.BlockSize),
		)
	}
	return key, nil
}

func nativeCredentialBackendIncompatible(internal error) error {
	return newProtocolError(protocolBackendIncompatible, "credential data is incompatible", internal)
}

func nativeCredentialBackendFailure(internal error) error {
	return newProtocolError(protocolBackendFailure, "credential operation failed", internal)
}
