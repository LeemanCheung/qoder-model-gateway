package main

import "encoding/hex"

func reverseMaskUUID(raw [16]byte) [16]byte {
	var value [16]byte
	for i := range raw {
		value[i] = raw[len(raw)-1-i]
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return value
}

func formatLowerUUID(value [16]byte) string {
	var formatted [36]byte
	hex.Encode(formatted[0:8], value[0:4])
	formatted[8] = '-'
	hex.Encode(formatted[9:13], value[4:6])
	formatted[13] = '-'
	hex.Encode(formatted[14:18], value[6:8])
	formatted[18] = '-'
	hex.Encode(formatted[19:23], value[8:10])
	formatted[23] = '-'
	hex.Encode(formatted[24:36], value[10:16])
	return string(formatted[:])
}

func runtimeASCIIKey(value [16]byte) string {
	var key [16]byte
	hex.Encode(key[:], value[:8])
	return string(key[:])
}
