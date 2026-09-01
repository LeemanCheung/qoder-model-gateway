package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unicode/utf8"
)

const runtimePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----
`

type runtimeFieldOutputWire struct {
	EncryptUserInfo string `json:"encrypt_user_info"`
	Key             string `json:"key"`
}

type nativeRuntimeFieldGenerator struct {
	host protocolHostDeps
}

var _ runtimeFieldGenerator = (*nativeRuntimeFieldGenerator)(nil)

func (g *nativeRuntimeFieldGenerator) Generate(ctx context.Context, input runtimeFieldInput) (runtimeFieldOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return runtimeFieldOutput{}, err
	}
	encodedInput, err := json.Marshal(input)
	if err != nil {
		return runtimeFieldOutput{}, newProtocolError(
			protocolInvalidInput,
			"runtime fields input is invalid",
			errors.New("marshal typed runtime fields input"),
		)
	}
	var host protocolHostDeps
	if g != nil {
		host = g.host
	}
	encodedOutput, err := generateNativeRuntimeFieldsRaw(ctx, host, encodedInput)
	if err != nil {
		return runtimeFieldOutput{}, err
	}
	return decodeRuntimeFieldOutputJSON(encodedOutput)
}

func generateNativeRuntimeFieldsRaw(ctx context.Context, host protocolHostDeps, raw []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !utf8.Valid(raw) {
		return nil, newProtocolError(
			protocolInvalidInput,
			"runtime fields input is invalid",
			errors.New("runtime fields raw input is not valid UTF-8"),
		)
	}
	operationHost := protocolHostDepsFor(ctx, host)
	if operationHost.Entropy == nil {
		return nil, runtimeFieldsBackendIncompatible(errors.New("runtime fields entropy dependency is missing"))
	}

	var random [16]byte
	if err := operationHost.Entropy.Read(random[:]); err != nil {
		return nil, normalizeHostDependencyError(
			err,
			protocolEntropyFailure,
			"Secure protocol randomness is unavailable",
			"read runtime UUID entropy",
		)
	}
	uuid := reverseMaskUUID(random)
	key := []byte(runtimeASCIIKey(uuid))
	ciphertext, err := aesCBCEncryptPKCS7(raw, key, key)
	if err != nil {
		return nil, runtimeFieldsBackendFailure(fmt.Errorf("encrypt runtime user info: %w", err))
	}
	publicKey, err := runtimePublicKey()
	if err != nil {
		return nil, err
	}
	encryptedKey, err := rsaEncryptPKCS1v15Exact(publicKey, key, operationHost.Entropy)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(runtimeFieldOutputWire{
		EncryptUserInfo: base64.StdEncoding.EncodeToString(ciphertext),
		Key:             base64.StdEncoding.EncodeToString(encryptedKey),
	})
	if err != nil {
		return nil, runtimeFieldsBackendFailure(errors.New("marshal runtime fields output"))
	}
	return encoded, nil
}

func runtimePublicKey() (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(runtimePublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, runtimeFieldsBackendIncompatible(errors.New("pinned runtime public key PEM is invalid"))
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, runtimeFieldsBackendIncompatible(fmt.Errorf("parse pinned runtime public key: %w", err))
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, runtimeFieldsBackendIncompatible(fmt.Errorf("pinned runtime public key type %T is not RSA", parsed))
	}
	return publicKey, nil
}

func rsaEncryptPKCS1v15Exact(publicKey *rsa.PublicKey, message []byte, entropy protocolEntropy) ([]byte, error) {
	if publicKey == nil || publicKey.N == nil || publicKey.N.Sign() <= 0 || publicKey.E <= 1 {
		return nil, runtimeFieldsBackendIncompatible(errors.New("runtime RSA public key is invalid"))
	}
	k := publicKey.Size()
	if k < 11 || len(message) > k-11 {
		return nil, newProtocolError(
			protocolInvalidInput,
			"runtime fields input is invalid",
			fmt.Errorf("runtime RSA message byte length %d exceeds maximum %d", len(message), k-11),
		)
	}
	if entropy == nil {
		return nil, runtimeFieldsBackendIncompatible(errors.New("runtime RSA entropy dependency is missing"))
	}

	psLength := k - len(message) - 3
	encodedMessage := make([]byte, k)
	encodedMessage[1] = 2
	padding := encodedMessage[2 : 2+psLength]
	if err := entropy.Read(padding); err != nil {
		return nil, normalizeHostDependencyError(
			err,
			protocolEntropyFailure,
			"Secure protocol randomness is unavailable",
			"read runtime RSA padding entropy",
		)
	}
	for i := range padding {
		for padding[i] == 0 {
			if err := entropy.Read(padding[i : i+1]); err != nil {
				return nil, normalizeHostDependencyError(
					err,
					protocolEntropyFailure,
					"Secure protocol randomness is unavailable",
					"redraw runtime RSA padding entropy",
				)
			}
		}
	}
	encodedMessage[2+psLength] = 0
	copy(encodedMessage[3+psLength:], message)

	messageInteger := new(big.Int).SetBytes(encodedMessage)
	if messageInteger.Cmp(publicKey.N) >= 0 {
		return nil, runtimeFieldsBackendIncompatible(errors.New("runtime RSA encoded message is not below the modulus"))
	}
	messageInteger.Exp(messageInteger, big.NewInt(int64(publicKey.E)), publicKey.N)
	messageInteger.FillBytes(encodedMessage)
	return encodedMessage, nil
}

func decodeRuntimeFieldOutputJSON(raw []byte) (runtimeFieldOutput, error) {
	if !utf8.Valid(raw) {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output is malformed JSON")
	}
	opening, ok := first.(json.Delim)
	if !ok || opening != '{' {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output is not an object")
	}

	var output runtimeFieldOutput
	seenEncryptUserInfo := false
	seenKey := false
	for decoder.More() {
		fieldToken, err := decoder.Token()
		if err != nil {
			return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has a malformed field")
		}
		field, ok := fieldToken.(string)
		if !ok {
			return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has a non-string field name")
		}
		switch field {
		case "encrypt_user_info":
			if seenEncryptUserInfo {
				return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has a duplicate field")
			}
			seenEncryptUserInfo = true
			if err := decoder.Decode(&output.EncryptUserInfo); err != nil {
				return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has a non-string field value")
			}
		case "key":
			if seenKey {
				return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has a duplicate field")
			}
			seenKey = true
			if err := decoder.Decode(&output.Key); err != nil {
				return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has a non-string field value")
			}
		default:
			return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has an unknown field")
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output object is incomplete")
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output object is malformed")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has trailing data")
	}
	if !seenEncryptUserInfo || !seenKey {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output is missing a required field")
	}
	if output.EncryptUserInfo == "" || output.Key == "" {
		return runtimeFieldOutput{}, runtimeFieldsOutputFailure("runtime fields output has an empty field")
	}
	return output, nil
}

func runtimeFieldsOutputFailure(category string) error {
	return newProtocolError(protocolBackendFailure, "Qoder protocol operation failed", errors.New(category))
}

func runtimeFieldsBackendIncompatible(internal error) error {
	return newProtocolError(protocolBackendIncompatible, "runtime fields backend is incompatible", internal)
}

func runtimeFieldsBackendFailure(internal error) error {
	return newProtocolError(protocolBackendFailure, "runtime fields operation failed", internal)
}
