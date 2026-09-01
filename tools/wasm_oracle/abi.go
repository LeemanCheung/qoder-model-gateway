package main

import (
	"encoding/binary"
)

const objectResultOffset = 12

type stringResult struct{ ptr, length, errorRef, errorFlag uint32 }
type objectResult struct{ ptr, errorRef, errorFlag uint32 }

func decodeStringResult(data []byte) (stringResult, error) {
	if len(data) < 16 {
		return stringResult{}, fail("abi-string-result-length")
	}
	return stringResult{binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:]), binary.LittleEndian.Uint32(data[12:])}, nil
}
func decodeObjectResult(data []byte) (objectResult, error) {
	if len(data) < objectResultOffset {
		return objectResult{}, fail("abi-object-result-length")
	}
	return objectResult{binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:])}, nil
}
