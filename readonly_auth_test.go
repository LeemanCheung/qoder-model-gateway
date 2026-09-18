package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readonlySyntheticFiles(t *testing.T, dir string, token string) {
	t.Helper()
	ui := userInfo{UID: "synthetic-readonly-user", SecurityOAuthToken: token,
		AccessToken: token, RefreshToken: "synthetic-refresh", ExpireTime: 1}
	data, err := json.Marshal(ui)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "user"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "machine_id"), []byte("synthetic-machine-id-1234"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readonlyHashes(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string][32]byte{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = sha256.Sum256(data)
	}
	return result
}

func readonlyServices() (*protocolServices, *fakeCredentialCodec) {
	codec := &fakeCredentialCodec{}
	return &protocolServices{credentials: codec, runtimeFields: &fakeRuntimeFieldGenerator{},
		contextFactory: &fakeProtocolContextFactory{contexts: []protocolContext{
			&fakeProtocolContext{}, &fakeProtocolContext{}, &fakeProtocolContext{}, &fakeProtocolContext{},
		}}}, codec
}

func TestReadOnlyAuthNeverCreatesOrRepairsMachineID(t *testing.T) {
	for _, broken := range []string{"missing-directory", "missing-user", "missing-machine", "empty-user", "empty-machine", "directory-machine"} {
		t.Run(broken, func(t *testing.T) {
			dir := t.TempDir()
			readonlySyntheticFiles(t, dir, "synthetic-original")
			switch broken {
			case "missing-directory":
				dir = filepath.Join(dir, "not-created")
			case "missing-user":
				if err := os.Remove(filepath.Join(dir, "user")); err != nil {
					t.Fatal(err)
				}
			case "missing-machine":
				if err := os.Remove(filepath.Join(dir, "machine_id")); err != nil {
					t.Fatal(err)
				}
			case "empty-user":
				if err := os.WriteFile(filepath.Join(dir, "user"), []byte(" \n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "empty-machine":
				if err := os.WriteFile(filepath.Join(dir, "machine_id"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory-machine":
				if err := os.Remove(filepath.Join(dir, "machine_id")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(dir, "machine_id"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			services, _ := readonlyServices()
			if _, err := newReadOnlyAuthManager(services, dir, "", "", "", nil); err == nil {
				t.Fatal("invalid shared authentication accepted")
			}
			if broken == "missing-directory" {
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatal("missing auth directory was created")
				}
			}
			if broken == "missing-machine" {
				if _, err := os.Stat(filepath.Join(dir, "machine_id")); !os.IsNotExist(err) {
					t.Fatal("missing machine ID was recreated")
				}
			}
			if broken == "empty-machine" {
				data, _ := os.ReadFile(filepath.Join(dir, "machine_id"))
				if len(data) != 0 {
					t.Fatal("empty machine ID repaired")
				}
			}
		})
	}
}

func TestReadOnlyAuthReloadsOfficialChangesWithoutRefreshNetworkOrWrites(t *testing.T) {
	dir := t.TempDir()
	readonlySyntheticFiles(t, dir, "synthetic-original")
	services, codec := readonlyServices()
	a, err := newReadOnlyAuthManager(services, dir, "https://auth.invalid", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !a.readOnly {
		t.Fatal("read-only flag must be set before load")
	}
	before := readonlyHashes(t, dir)
	if err := a.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.ui.Key == "" || a.ui.EncryptUserInfo == "" {
		t.Fatal("runtime fields were not generated in memory")
	}
	if err := a.ensureFresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, readonlyHashes(t, dir)) {
		t.Fatal("load/freshness mutated shared authentication")
	}
	// Simulate the official CLI replacing its login, never network-refresh it.
	readonlySyntheticFiles(t, dir, "synthetic-official-update")
	before = readonlyHashes(t, dir)
	if err := a.forceRefresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.ui.SecurityOAuthToken != "synthetic-official-update" {
		t.Fatal("forceRefresh did not reload disk login")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, readonlyHashes(t, dir)) {
		t.Fatal("forceRefresh/Close changed original files")
	}
	if codec.encryptCalls != 0 {
		t.Fatal("read-only mode invoked credential encryption")
	}
}

func TestReadOnlyAuthDirtyStateCannotPersistAndLoginCannotCallNetwork(t *testing.T) {
	dir := t.TempDir()
	readonlySyntheticFiles(t, dir, "synthetic-original")
	before := readonlyHashes(t, dir)
	services, codec := readonlyServices()
	a, err := newReadOnlyAuthManager(services, dir, "https://never-called.invalid", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.credentialDirty = true // A stale or manually injected dirty state must not bypass the boundary.
	a.credentialPersistRetryAt = time.Now().Add(-time.Hour)
	if err := a.save(context.Background()); err == nil {
		t.Fatal("explicit save silently accepted")
	}
	a.mu.Lock()
	if _, err := a.stageCredentialForUserLocked(context.Background(), a.ui); err == nil {
		t.Error("staging accepted")
	}
	if err := a.persistDirtyCredentialLocked(context.Background()); err != nil {
		t.Error(err)
	}
	a.persistDirtyCredentialBestEffortLocked(context.Background(), "synthetic", true)
	if err := a.refreshLocked(context.Background()); err == nil {
		t.Error("direct refresh accepted")
	}
	if err := a.preserveRefreshRotationAndSaveLocked(context.Background(), "new-synthetic-refresh", 100); err == nil {
		t.Error("rotation accepted")
	}
	if err := a.commitLoginCandidateLocked(context.Background(), &userInfo{}); err == nil {
		t.Error("login candidate accepted")
	}
	a.mu.Unlock()
	if err := a.deviceLogin(context.Background(), io.Discard); err == nil {
		t.Fatal("device login accepted")
	}
	if _, ok := a.httpc.Transport.(readOnlyAuthTransport); !ok {
		t.Fatal("authentication transport permits networking")
	}
	if err := patLogin(context.Background(), a, "synthetic-pat"); err == nil {
		t.Fatal("PAT login accepted")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, readonlyHashes(t, dir)) {
		t.Fatal("dirty/login/close path changed authentication")
	}
	if codec.encryptCalls != 0 {
		t.Fatal("dirty state reached persistence codec")
	}
}

func TestReadOnlyAuthAppRejectsLoginBeforeConstructingServices(t *testing.T) {
	for _, args := range [][]string{{"--read-only-auth", "--login"}, {"--read-only-auth", "--login-pat", "synthetic-pat"}} {
		cfg, err := parseAppConfig(args, envLookup(nil), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		called := false
		err = run(context.Background(), cfg, appDeps{newProtocolServices: func(protocolHostDeps) (*protocolServices, error) { called = true; return nil, nil }}, io.Discard, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("expected read-only rejection, got %v", err)
		}
		if called {
			t.Fatal("services constructed before incompatible login rejection")
		}
	}
	cfg, err := parseAppConfig(nil, envLookup(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.readOnlyAuth {
		t.Fatal("upstream default changed")
	}
}

func TestReadOnlyAuthMissingOrCorruptReloadFailsClosed(t *testing.T) {
	for _, replacement := range []string{"missing", "invalid-json"} {
		t.Run(replacement, func(t *testing.T) {
			dir := t.TempDir()
			readonlySyntheticFiles(t, dir, "synthetic-original")
			services, _ := readonlyServices()
			a, err := newReadOnlyAuthManager(services, dir, "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if err := a.load(context.Background()); err != nil {
				t.Fatal(err)
			}
			if replacement == "missing" {
				if err := os.Remove(filepath.Join(dir, "user")); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(dir, "user"), []byte("{broken"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := readonlyHashes(t, dir)
			if _, err := a.PrepareInferRequest(context.Background(), inferRequestInput{}); err == nil {
				t.Fatal("inference reused stale authentication after disk failure")
			}
			if err := a.forceRefresh(context.Background()); err == nil {
				t.Fatal("failed disk reload accepted")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, readonlyHashes(t, dir)) {
				t.Fatal("failed reload repaired shared authentication")
			}
		})
	}
}

func TestReadOnlyAuthAppSetsFlagBeforeLoadingAndSkipsNormalConstructor(t *testing.T) {
	h := newAppRunHarness(t)
	readonlySyntheticFiles(t, h.cfg.authDir, "synthetic-original")
	h.cfg.readOnlyAuth = true
	h.deps.newAuthManager = func(*protocolServices, string, string, string, string, func(string, ...any)) (*authManager, error) {
		t.Fatal("write-capable constructor used")
		return nil, nil
	}
	h.deps.newReadOnlyAuthManager = func(*protocolServices, string, string, string, string, func(string, ...any)) (*authManager, error) {
		return h.auth, nil
	}
	h.deps.loadCredentials = func(_ context.Context, a *authManager) error {
		if !a.readOnly {
			t.Fatal("flag absent before load")
		}
		return nil
	}
	h.deps.listenAndServe = func(*http.Server) error { return http.ErrServerClosed }
	if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil); err != nil {
		t.Fatal(err)
	}
	h.assertClosedOnce(t)
}
