package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

const (
	pinnedVersion  = "1.1.34"
	pinnedWASMSize = 297238
	pinnedWASMHash = "b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4"
	maxFixtureSize = 2 << 20
)

var (
	fixtureNames         = []string{"credential.json", "runtime-fields.json", "model-cache.json", "infer-user.json", "infer-user-no-org.json"}
	fixtureJSONNames     = []string{"credential.json", "infer-user-no-org.json", "infer-user.json", "manifest.json", "model-cache.json", "runtime-fields.json"}
	pinnedDocumentHashes = map[string]string{
		"credential.json":        "07b80f1d48141d763dab7065465b0bd531ae8e490f56a1999322b2faa1d29574",
		"infer-user-no-org.json": "1f7d66201ff1b3d25890cd4399d2aca67b582d938d715f2f0fb048a62e0e78d6",
		"infer-user.json":        "9732d0ca933bcf53e2e26e09b0e6a8ec46bd310ce925a8c2b74f24ab6f9b99ed",
		"model-cache.json":       "7c9dd168e83f6461b1826aae6b475c6ed419f5b9f45b4bfbecfbfd9617407cc8",
		"runtime-fields.json":    "9ab327de55b7ece6d429783152b77298c3b0eb1a51776213741ba8784954aaf0",
	}
)

type oracleError struct{ category string }

func (e *oracleError) Error() string { return e.category }
func fail(category string) error     { return &oracleError{category: category} }
func categoryOf(err error) string {
	var target *oracleError
	if errors.As(err, &target) {
		return target.category
	}
	if err == nil {
		return ""
	}
	return "internal"
}

type oracleIdentity struct {
	Version string `json:"version"`
	Size    int    `json:"size"`
	SHA256  string `json:"sha256"`
}
type fixtureManifest struct {
	Version   string            `json:"version"`
	Size      int               `json:"size"`
	SHA256    string            `json:"sha256"`
	Documents map[string]string `json:"documents"`
}
type fixtureDocument struct {
	Oracle     oracleIdentity  `json:"oracle"`
	Input      json.RawMessage `json:"input"`
	Transcript transcript      `json:"transcript"`
	Expected   json.RawMessage `json:"expected"`
}
type fixturePolicy struct {
	Identity       oracleIdentity
	DocumentHashes map[string]string
}

type entropyRead struct {
	Length int    `json:"length"`
	Bytes  []byte `json:"-"`
}

func (r *entropyRead) UnmarshalJSON(data []byte) error {
	var wire struct {
		Length int    `json:"length"`
		Bytes  string `json:"bytes"`
	}
	if err := decodeStrictObject(data, &wire, []string{"length", "bytes"}); err != nil || wire.Length < 0 {
		return fail("fixture-schema")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(wire.Bytes)
	if err != nil || len(decoded) != wire.Length || base64.StdEncoding.EncodeToString(decoded) != wire.Bytes {
		return fail("fixture-schema")
	}
	r.Length, r.Bytes = wire.Length, decoded
	return nil
}
func (r entropyRead) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Length int    `json:"length"`
		Bytes  string `json:"bytes"`
	}{r.Length, base64.StdEncoding.EncodeToString(r.Bytes)})
}

type transcript struct {
	UnixMilli    []int64       `json:"unix_milli"`
	EntropyReads []entropyRead `json:"entropy_reads"`
}

type fixtureSet map[string]fixtureDocument

func validateFixtureSafety(_ string, data []byte) error {
	for _, marker := range []string{
		"/home/", "/Users/", "/root/", `\\Users\\`, `C:\\Users\\`, ".qoder", "re/secrets", "SENTINEL-PROTOCOL-SECRET",
		"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "AKIA", "github_pat_", "ghp_", "xoxb-",
	} {
		if bytes.Contains(data, []byte(marker)) {
			return fail("fixture-safety")
		}
	}
	return nil
}

func validateInventory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail("fixture-inventory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(fixtureJSONNames) {
		return fail("fixture-inventory")
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		child, statErr := os.Lstat(path)
		if statErr != nil || !child.Mode().IsRegular() || child.Mode()&os.ModeSymlink != 0 {
			return fail("fixture-inventory")
		}
		got = append(got, entry.Name())
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, fixtureJSONNames) {
		return fail("fixture-inventory")
	}
	return nil
}

func decodeCanonicalJSON(data []byte, destination any) error {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Contains(data, []byte{'\r'}) || bytes.HasSuffix(data, []byte("\n\n")) {
		return fail("fixture-canonical-json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fail("fixture-canonical-json")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fail("fixture-canonical-json")
	}
	canonical, err := json.MarshalIndent(destination, "", "  ")
	if err != nil {
		return fail("fixture-canonical-json")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return fail("fixture-canonical-json")
	}
	return nil
}

func decodeStrictObject(data []byte, destination any, keys []string) error {
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&object); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || len(object) != len(keys) {
		return fail("fixture-schema")
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return fail("fixture-schema")
		}
	}
	return json.Unmarshal(data, destination)
}

func validateFixtureSet(dir string, policy fixturePolicy) (fixtureSet, error) {
	if err := validateInventory(dir); err != nil {
		return nil, err
	}
	manifestData, err := readBoundedRegularFile(filepath.Join(dir, "manifest.json"), maxFixtureSize, "fixture-read")
	if err != nil {
		return nil, err
	}
	if err := validateFixtureSafety("manifest.json", manifestData); err != nil {
		return nil, err
	}
	var manifest fixtureManifest
	if err := decodeCanonicalJSON(manifestData, &manifest); err != nil {
		return nil, err
	}
	if manifest.Version != policy.Identity.Version || manifest.Size != policy.Identity.Size || manifest.SHA256 != policy.Identity.SHA256 {
		return nil, fail("fixture-oracle-identity")
	}
	if !reflect.DeepEqual(manifest.Documents, policy.DocumentHashes) {
		return nil, fail("fixture-manifest-hash")
	}
	fixtures := make(fixtureSet, len(fixtureNames))
	for _, name := range fixtureNames {
		data, err := readBoundedRegularFile(filepath.Join(dir, name), maxFixtureSize, "fixture-read")
		if err != nil {
			return nil, err
		}
		if err := validateFixtureSafety(name, data); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != policy.DocumentHashes[name] {
			return nil, fail("fixture-document-hash")
		}
		var fixture fixtureDocument
		if err := decodeCanonicalJSON(data, &fixture); err != nil {
			return nil, err
		}
		if fixture.Oracle != policy.Identity {
			return nil, fail("fixture-oracle-identity")
		}
		if err := validateFixtureSchema(name, fixture); err != nil {
			return nil, err
		}
		fixtures[name] = fixture
	}
	if err := validateCrossFixtureRelationships(fixtures); err != nil {
		return nil, err
	}
	return fixtures, nil
}

func pinnedPolicy() fixturePolicy {
	return fixturePolicy{Identity: oracleIdentity{pinnedVersion, pinnedWASMSize, pinnedWASMHash}, DocumentHashes: pinnedDocumentHashes}
}

func validateFixtureSchema(name string, fixture fixtureDocument) error {
	return validateNestedFixture(name, fixture)
}

func mustDecode[T any](raw json.RawMessage) (T, error) {
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fail("fixture-schema")
	}
	return value, nil
}
func compactJSON(raw json.RawMessage) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fail("fixture-schema")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", fail("fixture-schema")
	}
	return string(data), nil
}
func validateWASM(data []byte) error {
	if len(data) != pinnedWASMSize {
		return fail("wasm-identity-size")
	}
	sum := sha256.Sum256(data)
	if fmt.Sprintf("%x", sum) != pinnedWASMHash {
		return fail("wasm-identity-sha256")
	}
	return nil
}
