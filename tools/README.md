# Optional external WASM oracle

`wasm_harness.py` is an analysis-only interoperability tool. It is not imported by the Go production build and is not required by ordinary Go tests.

The operator must supply an authorized external copy of the pinned `qoder_auth` WASM. The harness has no repository-asset fallback and validates the supplied bytes before instantiation:

- size: `297238` bytes
- SHA-256: `b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4`

The binary is read in place. The harness does not copy it into `tools/` or anywhere else in the repository.

## Safe self-test

The dependency-free self-test covers pinned-identity rejection, the separate 16-byte string Result and 12-byte object Result layouts, deterministic transcript ordering/exhaustion, and content-free output formatting:

```bash
python3 tools/wasm_harness.py --self-test
```

Expected output:

```text
self-test transcript=static result=PASS
```

## Verify the frozen synthetic fixtures

Run the command from the repository root. The Python launcher first invokes the standalone module's `validate-fixtures` command, so one recursive exact policy validates every nested fixture field and transcript before either runtime backend can instantiate WASM. If the pinned Python `wasmtime` dependency from `tools/requirements.txt` is already available in an operator-managed environment, the harness then uses its corrected wasm-bindgen host glue. Otherwise it invokes the fully standalone Go module in `tools/wasm_oracle` with an explicit argument vector. The nested module has its own `go.mod` and `go.sum`, pins wazero v1.12.0, imports nothing from the root module, and runs with both `GOWORK=off` and `GOPROXY=off`; dependencies must already be cached. Neither path performs a network install.

```bash
python3 tools/wasm_harness.py \
  --wasm /authorized/path/qoder_auth.wasm \
  --fixtures testdata/protocol/1.1.34 \
  verify-fixtures
```

Before launching either backend, the harness verifies the manifest identity, exact six-file inventory and hashes, per-document oracle identity, synthetic schema, canonical JSON, LF line endings, and transcript encoding. The standalone Go backend independently repeats those checks using bounded no-symlink regular-file reads, then replays the frozen credential, runtime-field, model-cache, full-org infer, and no-org infer transcripts in exact global host-call order and verifies wasm-bindgen result/object layouts plus cleanup accounting. Its ordered operations are `credential`, `runtime`, `model-cache`, `infer`, and `infer-no-org`. Output is newline-delimited JSON containing only operation names, transcript shapes, PASS/FAIL, and fixed categories; the Python fallback parses and validates those records before forwarding them. Neither path prints fixture inputs or outputs, keys, encrypted values, Authorization data, request bodies, user IDs, organization IDs, exception text, or tracebacks.

The standalone validator and verifier can also be invoked directly:

```bash
GOWORK=off GOPROXY=off go -C tools/wasm_oracle run . \
  --fixtures /external/path/to/frozen-fixtures \
  validate-fixtures

GOWORK=off GOPROXY=off go -C tools/wasm_oracle run . \
  --wasm /authorized/path/qoder_auth.wasm \
  --fixtures /external/path/to/frozen-fixtures \
  verify-fixtures
```

Run its short tests without an authorized WASM:

```bash
GOWORK=off GOPROXY=off go -C tools/wasm_oracle test ./...
```

The authorized integration test is opt-in and requires both explicit paths:

```bash
QODER2API_WASM_ORACLE=/authorized/path/qoder_auth.wasm \
QODER2API_WASM_ORACLE_FIXTURES=/external/path/to/frozen-fixtures \
GOWORK=off GOPROXY=off go -C tools/wasm_oracle test -run TestAuthorizedWASMFixtureIntegration -v
```

Use synthetic repository fixtures only. Do not supply real credentials, captures, tokens, request bodies, or user data to this tool. It performs no network requests.

## Redistribution and licensing

Only use a WASM binary that you are authorized to possess and execute. Do not copy or redistribute it without confirming the applicable license and permissions. Production is native-only and the root module has no WASM or wazero dependency; this independent tool workflow always requires an external operator-supplied binary.
