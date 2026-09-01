package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestDecodeStrictStdBase64AcceptsCanonicalPaddedValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []byte
	}{
		{name: "empty", value: "", want: nil},
		{name: "one byte", value: "TQ==", want: []byte{'M'}},
		{name: "two bytes", value: "TWE=", want: []byte("Ma")},
		{name: "three bytes", value: "TWFu", want: []byte("Man")},
		{name: "standard symbols", value: "+/8=", want: []byte{0xfb, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeStrictStdBase64(tt.value)
			if err != nil {
				t.Fatalf("case %s encoded length %d: decode returned error", tt.name, len(tt.value))
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("case %s encoded length %d: decoded length %d, want %d", tt.name, len(tt.value), len(got), len(tt.want))
			}
		})
	}
}

func TestDecodeStrictStdBase64RejectsMalformedAndNonCanonicalValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "URL-safe alphabet", value: "-_8="},
		{name: "missing double padding", value: "TQ"},
		{name: "missing single padding", value: "TWE"},
		{name: "carriage return", value: "TQ==\r"},
		{name: "line feed", value: "TQ==\n"},
		{name: "space", value: "T Q=="},
		{name: "trailing bytes", value: "TQ==AAAA"},
		{name: "impossible length", value: "A"},
		{name: "non-canonical trailing bits", value: "TR=="},
		{name: "extra padding", value: "TQ==="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeStrictStdBase64(tt.value)
			if err == nil {
				t.Fatalf("case %s encoded length %d: decode succeeded with %d bytes", tt.name, len(tt.value), len(got))
			}
			if len(got) != 0 {
				t.Fatalf("case %s encoded length %d: rejected decode returned %d bytes", tt.name, len(tt.value), len(got))
			}
		})
	}
}

func TestPKCS7PadAndUnpadEveryAESPaddingLength(t *testing.T) {
	const blockSize = 16
	for plainLen := 0; plainLen < blockSize; plainLen++ {
		plainLen := plainLen
		t.Run(fmt.Sprintf("plain-length-%d", plainLen), func(t *testing.T) {
			plain := bytes.Repeat([]byte{0x5a}, plainLen)
			before := append([]byte(nil), plain...)
			padded, err := pkcs7Pad(plain, blockSize)
			if err != nil {
				t.Fatalf("plain length %d: pad returned error", plainLen)
			}
			wantPadLen := blockSize - plainLen
			if len(padded) != blockSize {
				t.Fatalf("plain length %d: padded length %d, want %d", plainLen, len(padded), blockSize)
			}
			for i := plainLen; i < len(padded); i++ {
				if padded[i] != byte(wantPadLen) {
					t.Fatalf("plain length %d: padding byte %d is invalid", plainLen, i-plainLen)
				}
			}
			if !bytes.Equal(plain, before) {
				t.Fatalf("plain length %d: pad mutated input", plainLen)
			}
			unpadded, err := pkcs7Unpad(padded, blockSize)
			if err != nil {
				t.Fatalf("plain length %d: unpad returned error", plainLen)
			}
			if !bytes.Equal(unpadded, plain) {
				t.Fatalf("plain length %d: unpadded length %d", plainLen, len(unpadded))
			}
		})
	}
}

func TestPKCS7PadAddsFullBlockForAlignedPlaintext(t *testing.T) {
	plain := bytes.Repeat([]byte{0x3c}, 16)
	padded, err := pkcs7Pad(plain, 16)
	if err != nil {
		t.Fatal("aligned plaintext: pad returned error")
	}
	if len(padded) != 32 {
		t.Fatalf("aligned plaintext length %d: padded length %d, want 32", len(plain), len(padded))
	}
	for i := 16; i < len(padded); i++ {
		if padded[i] != 16 {
			t.Fatalf("aligned plaintext: padding byte %d is invalid", i-16)
		}
	}
}

func TestPKCS7RejectsInvalidPaddingAndBlockSizes(t *testing.T) {
	invalidPadded := []struct {
		name      string
		value     []byte
		blockSize int
	}{
		{name: "empty", value: nil, blockSize: 16},
		{name: "zero pad byte", value: make([]byte, 16), blockSize: 16},
		{name: "pad exceeds block size", value: bytes.Repeat([]byte{17}, 16), blockSize: 16},
		{name: "inconsistent tail", value: append(bytes.Repeat([]byte{0x41}, 14), 1, 2), blockSize: 16},
		{name: "non-block-aligned", value: append(bytes.Repeat([]byte{0x41}, 14), 1), blockSize: 16},
		{name: "zero block size", value: []byte{1}, blockSize: 0},
		{name: "negative block size", value: []byte{1}, blockSize: -1},
		{name: "oversized block size", value: bytes.Repeat([]byte{1}, 256), blockSize: 256},
	}
	for _, tt := range invalidPadded {
		t.Run("unpad "+tt.name, func(t *testing.T) {
			before := append([]byte(nil), tt.value...)
			got, err := pkcs7Unpad(tt.value, tt.blockSize)
			if err == nil {
				t.Fatalf("case %s length %d block size %d: unpad succeeded with length %d", tt.name, len(tt.value), tt.blockSize, len(got))
			}
			if len(got) != 0 {
				t.Fatalf("case %s length %d block size %d: rejected unpad returned %d bytes", tt.name, len(tt.value), tt.blockSize, len(got))
			}
			if !bytes.Equal(tt.value, before) {
				t.Fatalf("case %s length %d block size %d: unpad mutated input", tt.name, len(tt.value), tt.blockSize)
			}
		})
	}

	for _, blockSize := range []int{0, -1, 256} {
		if got, err := pkcs7Pad([]byte("synthetic"), blockSize); err == nil || len(got) != 0 {
			t.Fatalf("block size %d: pad returned length %d with error presence %t", blockSize, len(got), err != nil)
		}
	}
}

func TestAESCBCPKCS7RoundTripIsExactAndDoesNotMutateInputs(t *testing.T) {
	plain := append([]byte("synthetic-unicode-"), []byte("合成🙂\x00payload")...)
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")
	plainBefore := append([]byte(nil), plain...)
	keyBefore := append([]byte(nil), key...)
	ivBefore := append([]byte(nil), iv...)

	ciphertext, err := aesCBCEncryptPKCS7(plain, key, iv)
	if err != nil {
		t.Fatalf("plain length %d key length %d IV length %d: encrypt returned error", len(plain), len(key), len(iv))
	}
	if len(ciphertext) == 0 || len(ciphertext)%16 != 0 {
		t.Fatalf("plain length %d: ciphertext length %d is not a non-empty block multiple", len(plain), len(ciphertext))
	}
	if !bytes.Equal(plain, plainBefore) || !bytes.Equal(key, keyBefore) || !bytes.Equal(iv, ivBefore) {
		t.Fatalf("encrypt mutated an input (plain=%t key=%t IV=%t)", !bytes.Equal(plain, plainBefore), !bytes.Equal(key, keyBefore), !bytes.Equal(iv, ivBefore))
	}

	ciphertextBefore := append([]byte(nil), ciphertext...)
	decrypted, err := aesCBCDecryptPKCS7(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("ciphertext length %d key length %d IV length %d: decrypt returned error", len(ciphertext), len(key), len(iv))
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("round trip lengths decrypted=%d plain=%d", len(decrypted), len(plain))
	}
	if !bytes.Equal(ciphertext, ciphertextBefore) || !bytes.Equal(key, keyBefore) || !bytes.Equal(iv, ivBefore) {
		t.Fatalf("decrypt mutated an input (ciphertext=%t key=%t IV=%t)", !bytes.Equal(ciphertext, ciphertextBefore), !bytes.Equal(key, keyBefore), !bytes.Equal(iv, ivBefore))
	}
}

func TestAESCBCPKCS7RejectsInvalidKeyIVAndCiphertextSizes(t *testing.T) {
	validKey := []byte("0123456789abcdef")
	validIV := []byte("fedcba9876543210")
	plain := []byte("synthetic")

	for _, keyLen := range []int{0, 15, 17} {
		key := bytes.Repeat([]byte{0x4b}, keyLen)
		if got, err := aesCBCEncryptPKCS7(plain, key, validIV); err == nil || len(got) != 0 {
			t.Fatalf("encrypt key length %d: result length %d error presence %t", keyLen, len(got), err != nil)
		}
		if got, err := aesCBCDecryptPKCS7(bytes.Repeat([]byte{0x31}, 16), key, validIV); err == nil || len(got) != 0 {
			t.Fatalf("decrypt key length %d: result length %d error presence %t", keyLen, len(got), err != nil)
		}
	}

	for _, ivLen := range []int{0, 15, 17} {
		iv := bytes.Repeat([]byte{0x49}, ivLen)
		if got, err := aesCBCEncryptPKCS7(plain, validKey, iv); err == nil || len(got) != 0 {
			t.Fatalf("encrypt IV length %d: result length %d error presence %t", ivLen, len(got), err != nil)
		}
		if got, err := aesCBCDecryptPKCS7(bytes.Repeat([]byte{0x31}, 16), validKey, iv); err == nil || len(got) != 0 {
			t.Fatalf("decrypt IV length %d: result length %d error presence %t", ivLen, len(got), err != nil)
		}
	}

	for _, ciphertextLen := range []int{0, 1, 15, 17, 31} {
		ciphertext := bytes.Repeat([]byte{0x43}, ciphertextLen)
		before := append([]byte(nil), ciphertext...)
		got, err := aesCBCDecryptPKCS7(ciphertext, validKey, validIV)
		if err == nil || len(got) != 0 {
			t.Fatalf("ciphertext length %d: result length %d error presence %t", ciphertextLen, len(got), err != nil)
		}
		if !bytes.Equal(ciphertext, before) {
			t.Fatalf("ciphertext length %d: rejected decrypt mutated input", ciphertextLen)
		}
	}
}
