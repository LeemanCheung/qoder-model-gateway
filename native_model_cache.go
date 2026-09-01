package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const qmcV1Prefix = "QMC\x01"
const qmcNonceSize = 12
const qmcTagSize = 16

func deriveModelCacheKey(uid string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, []byte(uid), []byte("qoder-model-cache-enc"), "model-cache-v1", 32)
	if err != nil {
		return nil, modelCacheBackendFailure(fmt.Errorf("derive model cache key: %w", err))
	}
	if len(key) != 32 {
		return nil, modelCacheBackendFailure(fmt.Errorf("derived model cache key length %d, want 32", len(key)))
	}
	return key, nil
}

type nativeModelCacheDecryptor struct{}

var _ modelCacheDecryptor = nativeModelCacheDecryptor{}

func (nativeModelCacheDecryptor) Decrypt(ctx context.Context, blob, uid string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return decryptQMCV1(blob, uid)
}

func decryptQMCV1(blob, uid string) ([]byte, error) {
	envelope, err := decodeStrictStdBase64(blob)
	if err != nil {
		return nil, modelCacheBackendIncompatible(errors.New("model cache envelope encoding is invalid"))
	}
	minimumLength := len(qmcV1Prefix) + qmcNonceSize + qmcTagSize
	if len(envelope) < minimumLength {
		return nil, modelCacheBackendIncompatible(errors.New("model cache envelope is too short"))
	}
	if !bytes.Equal(envelope[:len(qmcV1Prefix)], []byte(qmcV1Prefix)) {
		return nil, modelCacheBackendIncompatible(errors.New("model cache envelope magic or version is unsupported"))
	}
	nonceStart := len(qmcV1Prefix)
	ciphertextStart := nonceStart + qmcNonceSize
	nonce := envelope[nonceStart:ciphertextStart]
	ciphertext := envelope[ciphertextStart:]
	key, err := deriveModelCacheKey(uid)
	if err != nil {
		return nil, err
	}
	gcm, err := newQMCGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, modelCacheBackendIncompatible(errors.New("model cache envelope authentication failed"))
	}
	return append([]byte(nil), plain...), nil
}

func encryptQMCV1ForTest(plain []byte, uid string, nonce []byte) (string, error) {
	if len(nonce) != qmcNonceSize {
		return "", newProtocolError(
			protocolInvalidInput,
			"model cache input is invalid",
			fmt.Errorf("model cache nonce length %d, want %d", len(nonce), qmcNonceSize),
		)
	}
	key, err := deriveModelCacheKey(uid)
	if err != nil {
		return "", err
	}
	gcm, err := newQMCGCM(key)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)
	envelope := make([]byte, 0, len(qmcV1Prefix)+len(nonce)+len(sealed))
	envelope = append(envelope, qmcV1Prefix...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, sealed...)
	return base64.StdEncoding.EncodeToString(envelope), nil
}

func newQMCGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, modelCacheBackendFailure(fmt.Errorf("create model cache AES cipher: %w", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, modelCacheBackendFailure(fmt.Errorf("create model cache GCM: %w", err))
	}
	if gcm.NonceSize() != qmcNonceSize || gcm.Overhead() != qmcTagSize {
		return nil, modelCacheBackendFailure(fmt.Errorf("model cache GCM layout nonce/tag lengths %d/%d", gcm.NonceSize(), gcm.Overhead()))
	}
	return gcm, nil
}

func modelCacheBackendIncompatible(internal error) error {
	return newProtocolError(protocolBackendIncompatible, "model cache data is incompatible", internal)
}

func modelCacheBackendFailure(internal error) error {
	return newProtocolError(protocolBackendFailure, "model cache operation failed", internal)
}
