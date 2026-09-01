package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

const qoderBodyAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"

var qoderBodyBase64 = base64.NewEncoding(qoderBodyAlphabet).WithPadding('$').Strict()

type nativeBodyCodec struct{}

func (nativeBodyCodec) Encode(raw []byte) ([]byte, error) {
	encoded := make([]byte, qoderBodyBase64.EncodedLen(len(raw)))
	qoderBodyBase64.Encode(encoded, raw)
	return swapOuterThirds(encoded), nil
}

func (nativeBodyCodec) Decode(encoded []byte) ([]byte, error) {
	if bytes.IndexByte(encoded, '\r') >= 0 || bytes.IndexByte(encoded, '\n') >= 0 {
		return nil, invalidNativeBodyError(errors.New("encoded body contains a line break"))
	}

	base64Body := swapOuterThirds(encoded)
	decoded := make([]byte, qoderBodyBase64.DecodedLen(len(base64Body)))
	decodedLen, err := qoderBodyBase64.Decode(decoded, base64Body)
	if err != nil {
		return nil, invalidNativeBodyError(fmt.Errorf("strict base64 decode: %w", err))
	}
	decoded = decoded[:decodedLen]

	canonical, err := (nativeBodyCodec{}).Encode(decoded)
	if err != nil {
		return nil, invalidNativeBodyError(fmt.Errorf("canonical body encode: %w", err))
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, invalidNativeBodyError(errors.New("encoded body is not canonical"))
	}
	return decoded, nil
}

func invalidNativeBodyError(internal error) error {
	return newProtocolError(protocolInvalidInput, "protocol body is invalid", internal)
}

func swapOuterThirds(src []byte) []byte {
	q := len(src) / 3
	out := make([]byte, 0, len(src))
	out = append(out, src[len(src)-q:]...)
	out = append(out, src[q:len(src)-q]...)
	out = append(out, src[:q]...)
	return out
}
