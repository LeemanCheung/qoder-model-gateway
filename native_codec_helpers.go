package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func decodeStrictStdBase64(value string) ([]byte, error) {
	if strings.ContainsAny(value, "\r\n") {
		return nil, errors.New("standard base64 contains a line break")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("strict standard base64 decode: %w", err)
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("standard base64 is not canonical")
	}
	return decoded, nil
}

func pkcs7Pad(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("PKCS#7 block size %d is invalid", blockSize)
	}
	paddingLen := blockSize - len(src)%blockSize
	if len(src) > int(^uint(0)>>1)-paddingLen {
		return nil, errors.New("PKCS#7 padded length overflows int")
	}
	padded := make([]byte, len(src)+paddingLen)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(paddingLen)
	}
	return padded, nil
}

func pkcs7Unpad(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("PKCS#7 block size %d is invalid", blockSize)
	}
	if len(src) == 0 {
		return nil, errors.New("PKCS#7 input is empty")
	}
	if len(src)%blockSize != 0 {
		return nil, errors.New("PKCS#7 input is not block aligned")
	}
	paddingLen := int(src[len(src)-1])
	if paddingLen == 0 || paddingLen > blockSize || paddingLen > len(src) {
		return nil, errors.New("PKCS#7 padding length is invalid")
	}
	paddingStart := len(src) - paddingLen
	for i := paddingStart; i < len(src); i++ {
		if int(src[i]) != paddingLen {
			return nil, errors.New("PKCS#7 padding bytes are inconsistent")
		}
	}
	return src[:paddingStart], nil
}

func aesCBCEncryptPKCS7(plain, key, iv []byte) ([]byte, error) {
	if err := validateAESCBCKeyAndIV(key, iv); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	padded, err := pkcs7Pad(plain, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("pad AES-CBC plaintext: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func aesCBCDecryptPKCS7(ciphertext, key, iv []byte) ([]byte, error) {
	if err := validateAESCBCKeyAndIV(key, iv); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("AES-CBC ciphertext is empty")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES-CBC ciphertext length %d is not block aligned", len(ciphertext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	unpadded, err := pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("unpad AES-CBC plaintext: %w", err)
	}
	return unpadded, nil
}

func validateAESCBCKeyAndIV(key, iv []byte) error {
	switch len(key) {
	case 16, 24, 32:
	default:
		return fmt.Errorf("AES key length %d is invalid", len(key))
	}
	if len(iv) != aes.BlockSize {
		return fmt.Errorf("AES-CBC IV length %d does not match block size %d", len(iv), aes.BlockSize)
	}
	return nil
}
