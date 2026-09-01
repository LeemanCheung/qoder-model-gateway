package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzRuntimeFieldsEnvelope(f *testing.F) {
	fixtureBytes, err := os.ReadFile(filepath.Join(protocolFixtureDir(), "runtime-fields.json"))
	if err != nil {
		f.Fatalf("read official runtime fixture: %v", err)
	}
	var fixture protocolFixture
	if err := decodeStrictJSON(fixtureBytes, &fixture); err != nil {
		f.Fatal("decode official runtime fixture")
	}
	var expected runtimeFixtureExpected
	if err := decodeStrictJSON(fixture.Expected, &expected); err != nil {
		f.Fatal("decode official runtime fixture output")
	}

	seeds := [][]byte{
		[]byte(expected.Raw),
		[]byte(`{}`),
		[]byte(`{"key":"synthetic-key"}`),
		[]byte(`{"encrypt_user_info":"synthetic-a","encrypt_user_info":"synthetic-b","key":"synthetic-key"}`),
		[]byte(`{"encrypt_user_info":"synthetic-encrypted","key":"synthetic-key","unknown":"synthetic"}`),
		[]byte(`{"encrypt_user_info":"synthetic-encrypted","key":"synthetic-key"}{}`),
		[]byte(`{"encrypt_user_info":`),
		{0xff, 0xfe},
		[]byte(`{"encrypt_user_info":"a","key":"b"}`),
		[]byte(`{"encrypt_user_info":"` + strings.Repeat("a", 64<<10) + `","key":"` + strings.Repeat("b", 64<<10) + `"}`),
		[]byte(strings.Repeat("x", (1<<20)+1)),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		output, err := decodeRuntimeFieldOutputJSON(raw)
		if err != nil {
			return
		}
		if output.EncryptUserInfo == "" || output.Key == "" {
			t.Fatalf("successful parse of input length %d returned an empty field", len(raw))
		}
		canonical, err := json.Marshal(runtimeFieldOutputWire{
			EncryptUserInfo: output.EncryptUserInfo,
			Key:             output.Key,
		})
		if err != nil {
			t.Fatalf("successful parse of input length %d could not be re-marshaled", len(raw))
		}
		reparsed, err := decodeRuntimeFieldOutputJSON(canonical)
		if err != nil {
			t.Fatalf("canonical output length %d could not be parsed", len(canonical))
		}
		if reparsed != output {
			t.Fatalf("canonical output length %d changed parsed fields", len(canonical))
		}
	})
}
