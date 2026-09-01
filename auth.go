package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	prodClientID                = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
	nonProdClientID             = "e93fe488-5778-4c35-a6fc-0f54ed7b3139"
	defaultOpenapi              = "https://openapi.qoder.sh"
	defaultInfer                = "https://api2.qoder.sh"
	defaultBase                 = "https://qoder.com"
	refreshSkewSec              = 3600
	defaultRefreshCommitTimeout = 30 * time.Second
)

type userInfo struct {
	UID                    string   `json:"uid"`
	Name                   string   `json:"name,omitempty"`
	Email                  string   `json:"email,omitempty"`
	AvatarURL              string   `json:"avatar_url,omitempty"`
	OrgID                  string   `json:"organization_id,omitempty"`
	OrgName                string   `json:"organization_name,omitempty"`
	OrgTags                []string `json:"organization_tags,omitempty"`
	DataPolicyAgreed       bool     `json:"data_policy_agreed"`
	IsDataPolicyModifiable bool     `json:"is_data_policy_modifiable,omitempty"`
	SecurityOAuthToken     string   `json:"security_oauth_token"`
	AccessToken            string   `json:"access_token"`
	RefreshToken           string   `json:"refresh_token"`
	ExpireTime             int64    `json:"expire_time"`
	RefreshTokenExpireTime int64    `json:"refresh_token_expire_time,omitempty"`
	LoginMethod            string   `json:"login_method"`
	LoginTimestamp         int64    `json:"login_timestamp"`
	EncryptUserInfo        string   `json:"encrypt_user_info"`
	Key                    string   `json:"key"`
	PersonalAccessToken    string   `json:"personal_access_token,omitempty"`
}

type authManager struct {
	mu       sync.Mutex
	protocol *protocolServices

	ctxMu     sync.RWMutex
	protoCtx  protocolContext
	closed    bool
	closeOnce sync.Once
	closeErr  error

	authFile        string
	machineID       string
	openapiBase     string
	inferBase       string
	webBase         string
	httpc           *http.Client
	ui              *userInfo
	credentialDirty bool
	commitTimeout   time.Duration
	logf            func(string, ...any)
}

func newAuthManager(services *protocolServices, authDir, openapiBase, inferBase, webBase string, logf func(string, ...any)) (*authManager, error) {
	if services == nil || services.credentials == nil || services.runtimeFields == nil || services.contextFactory == nil {
		return nil, newProtocolError(
			protocolInvalidInput,
			"Protocol services are unavailable",
			fmt.Errorf("auth manager requires credentials, runtime fields, and context factory capabilities"),
		)
	}
	mid, err := loadOrCreateMachineID(authDir)
	if err != nil {
		return nil, err
	}
	if openapiBase == "" {
		openapiBase = defaultOpenapi
	}
	if inferBase == "" {
		inferBase = defaultInfer
	}
	if webBase == "" {
		webBase = defaultBase
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	manager := &authManager{
		protocol: services, authFile: filepath.Join(authDir, "user"), machineID: mid,
		openapiBase: openapiBase, inferBase: inferBase, webBase: webBase,
		httpc: &http.Client{Timeout: 30 * time.Second}, logf: logf,
	}
	return manager, nil
}

func machineCredentialKey(machineID string) string {
	if len(machineID) > 16 {
		return machineID[:16]
	}
	return machineID
}

func loadOrCreateMachineID(dir string) (string, error) {
	p := filepath.Join(dir, "machine_id")
	if b, err := os.ReadFile(p); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	mid := newUUID()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(mid), 0o600); err != nil {
		return "", err
	}
	return mid, nil
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func authManagerClosedError() error {
	return newProtocolError(
		protocolContextClosed,
		"Qoder protocol context is closed",
		fmt.Errorf("auth manager is closed"),
	)
}

func (a *authManager) closedStateError() error {
	a.ctxMu.RLock()
	defer a.ctxMu.RUnlock()
	if a.closed {
		return authManagerClosedError()
	}
	return nil
}

func (a *authManager) loggedIn() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closedStateError() == nil && a.ui != nil && a.ui.SecurityOAuthToken != ""
}

func (a *authManager) safeLogf(format string, args ...any) {
	if a.logf != nil {
		a.logf(format, args...)
	}
}

func (a *authManager) replaceContext(next protocolContext) error {
	if next == nil {
		return newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("replacement protocol context is nil"),
		)
	}

	a.ctxMu.Lock()
	if a.closed {
		a.ctxMu.Unlock()
		if err := next.Close(); err != nil {
			a.safeLogf("close rejected protocol context failed")
		}
		return authManagerClosedError()
	}
	old := a.protoCtx
	a.protoCtx = next
	a.ctxMu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			a.safeLogf("close replaced protocol context failed")
		}
	}
	return nil
}

func (a *authManager) prepareWithCurrentContext(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	a.ctxMu.RLock()
	defer a.ctxMu.RUnlock()
	if a.closed {
		return nil, authManagerClosedError()
	}
	if a.protoCtx == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("protocol context is unavailable"),
		)
	}
	return a.protoCtx.PrepareInferRequest(ctx, input)
}

func (a *authManager) PrepareInferRequest(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	if err := a.closedStateError(); err != nil {
		return nil, err
	}
	if err := a.ensureFresh(ctx); err != nil {
		if protocolErrorKindOf(err) == protocolContextClosed {
			return nil, err
		}
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("refresh authentication: %w", protocolInternalError(err)),
		)
	}
	return a.prepareWithCurrentContext(ctx, input)
}

func (a *authManager) Close() error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		persistErr := a.persistDirtyCredentialLocked(context.Background())
		a.ctxMu.Lock()
		a.closed = true
		current := a.protoCtx
		a.protoCtx = nil
		a.ctxMu.Unlock()
		a.mu.Unlock()

		var contextErr error
		if current != nil {
			contextErr = current.Close()
		}
		a.closeErr = mergeProtocolErrors(persistErr, contextErr)
	})
	return a.closeErr
}

func (a *authManager) load(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closedStateError(); err != nil {
		return err
	}
	b, err := os.ReadFile(a.authFile)
	if err != nil {
		return err
	}
	s := strings.TrimSpace(string(b))
	var plain []byte
	if strings.HasPrefix(s, "{") {
		plain = []byte(s)
	} else {
		dec, err := a.protocol.credentials.Decrypt(ctx, s, machineCredentialKey(a.machineID))
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", a.authFile, err)
		}
		plain = []byte(dec)
	}
	var ui userInfo
	if err := json.Unmarshal(plain, &ui); err != nil {
		return err
	}
	a.ui = &ui
	a.credentialDirty = false
	return a.rebuildContextLocked(ctx)
}

func credentialPersistenceError(action string, err error) error {
	if err == nil {
		return nil
	}
	return newProtocolError(
		protocolBackendFailure,
		"Authentication state could not be saved",
		fmt.Errorf("%s: %w", action, protocolInternalError(err)),
	)
}

type stagedCredential struct {
	tempPath  string
	finalPath string
	published bool
}

func (s *stagedCredential) discard() {
	if s == nil || s.published || s.tempPath == "" {
		return
	}
	_ = os.Remove(s.tempPath)
}

func (s *stagedCredential) publish() error {
	if s == nil || s.tempPath == "" || s.finalPath == "" {
		return fmt.Errorf("staged credential is incomplete")
	}
	if err := os.Rename(s.tempPath, s.finalPath); err != nil {
		return err
	}
	s.published = true
	return nil
}

func (a *authManager) stageCredentialForUserLocked(ctx context.Context, ui *userInfo) (*stagedCredential, error) {
	if ui == nil {
		return nil, nil
	}
	if a.protocol == nil || a.protocol.credentials == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("credential codec is unavailable"),
		)
	}
	plain, err := json.Marshal(ui)
	if err != nil {
		return nil, err
	}
	enc, err := a.protocol.credentials.Encrypt(ctx, string(plain), machineCredentialKey(a.machineID))
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(a.authFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(dir, ".user-*")
	if err != nil {
		return nil, err
	}
	staged := &stagedCredential{tempPath: temp.Name(), finalPath: a.authFile}
	succeeded := false
	defer func() {
		_ = temp.Close()
		if !succeeded {
			staged.discard()
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return nil, err
	}
	written, err := io.Copy(temp, strings.NewReader(enc))
	if err != nil {
		return nil, err
	}
	if written != int64(len(enc)) {
		return nil, io.ErrShortWrite
	}
	if err := temp.Sync(); err != nil {
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	succeeded = true
	return staged, nil
}

func (a *authManager) saveLocked(ctx context.Context) error {
	if err := a.closedStateError(); err != nil {
		return err
	}
	if a.ui == nil {
		return nil
	}
	a.credentialDirty = true
	staged, err := a.stageCredentialForUserLocked(ctx, a.ui)
	if err != nil {
		return err
	}
	defer staged.discard()
	if err := staged.publish(); err != nil {
		return err
	}
	a.credentialDirty = false
	return nil
}

func (a *authManager) detachedCommitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := a.commitTimeout
	if timeout <= 0 {
		timeout = defaultRefreshCommitTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (a *authManager) persistDirtyCredentialLocked(ctx context.Context) error {
	if !a.credentialDirty {
		return nil
	}
	persistCtx, cancel := a.detachedCommitContext(ctx)
	defer cancel()
	if err := a.saveLocked(persistCtx); err != nil {
		return credentialPersistenceError("persist pending credentials", err)
	}
	return nil
}

func (a *authManager) save(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveLocked(ctx)
}

func cloneUserInfo(ui *userInfo) *userInfo {
	if ui == nil {
		return nil
	}
	cloned := *ui
	cloned.OrgTags = slices.Clone(ui.OrgTags)
	return &cloned
}

func normalizedOrganizationTags(tags []string) []string {
	normalized := make([]string, len(tags))
	copy(normalized, tags)
	return normalized
}

func (a *authManager) runtimeFieldInputForLocked(ui *userInfo) runtimeFieldInput {
	if ui == nil {
		return runtimeFieldInput{}
	}
	return runtimeFieldInput{
		UID:              ui.UID,
		OrganizationID:   ui.OrgID,
		OrganizationTags: normalizedOrganizationTags(ui.OrgTags),
		DataPolicyAgreed: ui.DataPolicyAgreed,
	}
}

func (a *authManager) runtimeFieldInputLocked() runtimeFieldInput {
	return a.runtimeFieldInputForLocked(a.ui)
}

func (a *authManager) contextConfigForLocked(ui *userInfo) protocolContextConfig {
	if ui == nil {
		return protocolContextConfig{MachineID: a.machineID, Version: qoderProtocolVersion, Scene: defaultProtocolScene()}
	}
	return protocolContextConfig{
		MachineID: a.machineID,
		Version:   qoderProtocolVersion,
		User: protocolUserInfo{
			UID:              ui.UID,
			EncryptUserInfo:  ui.EncryptUserInfo,
			Key:              ui.Key,
			OrganizationID:   ui.OrgID,
			OrganizationTags: normalizedOrganizationTags(ui.OrgTags),
			DataPolicyAgreed: ui.DataPolicyAgreed,
		},
		Scene: defaultProtocolScene(),
	}
}

func (a *authManager) contextConfigLocked() protocolContextConfig {
	return a.contextConfigForLocked(a.ui)
}

func (a *authManager) buildContextForUserLocked(ctx context.Context, ui *userInfo) (protocolContext, error) {
	if err := a.closedStateError(); err != nil {
		return nil, err
	}
	if ui == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("user credentials are unavailable"),
		)
	}
	if a.protocol == nil || a.protocol.runtimeFields == nil || a.protocol.contextFactory == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("required protocol capabilities are unavailable"),
		)
	}
	if ui.EncryptUserInfo == "" || ui.Key == "" {
		fields, err := a.protocol.runtimeFields.Generate(ctx, a.runtimeFieldInputForLocked(ui))
		if err != nil {
			return nil, err
		}
		if fields.EncryptUserInfo == "" || fields.Key == "" {
			return nil, newProtocolError(
				protocolAuthUnavailable,
				"Authentication is unavailable",
				fmt.Errorf("generated runtime authentication fields are incomplete"),
			)
		}
		ui.EncryptUserInfo, ui.Key = fields.EncryptUserInfo, fields.Key
		if ui == a.ui {
			a.credentialDirty = true
		}
	}
	return a.protocol.contextFactory.New(ctx, a.contextConfigForLocked(ui))
}

func (a *authManager) rebuildContextLocked(ctx context.Context) error {
	next, err := a.buildContextForUserLocked(ctx, a.ui)
	if err != nil {
		return err
	}
	return a.replaceContext(next)
}

func (a *authManager) closeRejectedLoginContext(candidate protocolContext) {
	if candidate == nil {
		return
	}
	if err := candidate.Close(); err != nil {
		a.safeLogf("close rejected login protocol context failed")
	}
}

func (a *authManager) commitLoginCandidateLocked(ctx context.Context, candidate *userInfo) error {
	next, err := a.buildContextForUserLocked(ctx, candidate)
	if err != nil {
		a.closeRejectedLoginContext(next)
		return err
	}
	if next == nil {
		return newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("candidate protocol context is unavailable"),
		)
	}
	if err := a.closedStateError(); err != nil {
		a.closeRejectedLoginContext(next)
		return err
	}
	staged, err := a.stageCredentialForUserLocked(ctx, candidate)
	if err != nil {
		a.closeRejectedLoginContext(next)
		return err
	}
	defer staged.discard()

	a.ctxMu.Lock()
	if a.closed {
		a.ctxMu.Unlock()
		a.closeRejectedLoginContext(next)
		return authManagerClosedError()
	}
	if err := staged.publish(); err != nil {
		a.ctxMu.Unlock()
		a.closeRejectedLoginContext(next)
		return err
	}
	old := a.protoCtx
	a.protoCtx = next
	a.ui = candidate
	a.credentialDirty = false
	a.ctxMu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			a.safeLogf("close replaced protocol context failed")
		}
	}
	return nil
}

func (a *authManager) inferEndpoint() string { return a.inferBase }

// ensureFresh refreshes the device token when it expires within refreshSkewSec.
func (a *authManager) ensureFresh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closedStateError(); err != nil {
		return err
	}
	if err := a.persistDirtyCredentialLocked(ctx); err != nil {
		return err
	}
	if a.ui == nil {
		return fmt.Errorf("not authenticated")
	}
	now := time.Now().Unix()
	if a.ui.ExpireTime == 0 || a.ui.ExpireTime-refreshSkewSec >= now {
		return nil
	}
	if a.ui.RefreshTokenExpireTime != 0 && now > a.ui.RefreshTokenExpireTime {
		return fmt.Errorf("refresh token expired; please re-login")
	}
	return a.refreshLocked(ctx)
}

func (a *authManager) forceRefresh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closedStateError(); err != nil {
		return err
	}
	if err := a.persistDirtyCredentialLocked(ctx); err != nil {
		return err
	}
	return a.refreshLocked(ctx)
}

func (a *authManager) preserveRefreshRotationAndSaveLocked(ctx context.Context, refreshToken string, refreshExpiry int64) error {
	if a.ui == nil {
		return nil
	}
	refreshChanged := refreshToken != "" && a.ui.RefreshToken != refreshToken
	expiryChanged := refreshExpiry != 0 && a.ui.RefreshTokenExpireTime != refreshExpiry
	if !refreshChanged && !expiryChanged {
		return nil
	}
	a.credentialDirty = true
	if refreshChanged {
		a.ui.RefreshToken = refreshToken
	}
	if expiryChanged {
		a.ui.RefreshTokenExpireTime = refreshExpiry
	}
	return a.persistDirtyCredentialLocked(ctx)
}

func (a *authManager) refreshLocked(ctx context.Context) error {
	if err := a.closedStateError(); err != nil {
		return err
	}
	if a.ui == nil {
		return fmt.Errorf("not authenticated")
	}
	if a.ui.RefreshToken == "" {
		return fmt.Errorf("no refresh_token")
	}
	body, _ := json.Marshal(map[string]string{"refresh_token": a.ui.RefreshToken})
	req, err := http.NewRequestWithContext(ctx, "POST", a.openapiBase+"/api/v1/deviceToken/refresh", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", qoderUserAgent())
	resp, err := a.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("deviceToken/refresh status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var r struct {
		DeviceToken  string `json:"device_token"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshExpAt string `json:"refresh_token_expires_at"`
		RefreshExpIn int64  `json:"refresh_token_expires_in"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	tok := r.DeviceToken
	if tok == "" {
		tok = r.Token
	}
	if tok == "" {
		return fmt.Errorf("refresh response missing token")
	}
	commitCtx, cancelCommit := a.detachedCommitContext(ctx)
	defer cancelCommit()

	candidate := cloneUserInfo(a.ui)
	candidate.SecurityOAuthToken, candidate.AccessToken = tok, tok
	if r.RefreshToken != "" {
		candidate.RefreshToken = r.RefreshToken
	}
	candidate.ExpireTime = parseExpiry(r.ExpiresAt, r.ExpiresIn)
	refreshExpiry := parseExpiry(r.RefreshExpAt, r.RefreshExpIn)
	if refreshExpiry != 0 {
		candidate.RefreshTokenExpireTime = refreshExpiry
	}
	if a.protocol != nil && a.protocol.runtimeFields != nil {
		fields, fieldErr := a.protocol.runtimeFields.Generate(commitCtx, a.runtimeFieldInputForLocked(candidate))
		if fieldErr == nil && fields.EncryptUserInfo != "" && fields.Key != "" {
			candidate.EncryptUserInfo, candidate.Key = fields.EncryptUserInfo, fields.Key
		}
	}
	next, err := a.buildContextForUserLocked(commitCtx, candidate)
	if err != nil {
		return mergeProtocolErrors(err, a.preserveRefreshRotationAndSaveLocked(commitCtx, r.RefreshToken, refreshExpiry))
	}
	if err := a.replaceContext(next); err != nil {
		return mergeProtocolErrors(err, a.preserveRefreshRotationAndSaveLocked(commitCtx, r.RefreshToken, refreshExpiry))
	}
	a.credentialDirty = true
	a.ui = candidate
	if err := a.persistDirtyCredentialLocked(commitCtx); err != nil {
		return err
	}
	a.safeLogf("device token refreshed, new expiry %d", a.ui.ExpireTime)
	return nil
}

func parseExpiry(iso string, inSec int64) int64 {
	if iso != "" {
		if t, err := time.Parse(time.RFC3339, iso); err == nil {
			return t.Unix()
		}
	}
	if inSec != 0 {
		return time.Now().Unix() + inSec
	}
	return 0
}

// ---- device flow login ----

func pkcePair() (verifier, challenge string) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	n := 43 + int(randBytes(1)[0]%86)
	rb := randBytes(n)
	vb := make([]byte, n)
	for i := range vb {
		vb[i] = charset[int(rb[i])%len(charset)]
	}
	verifier = string(vb)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// deviceLogin runs the full device authorization flow and persists credentials.
func (a *authManager) deviceLogin(ctx context.Context, out io.Writer) error {
	if err := a.closedStateError(); err != nil {
		return err
	}
	verifier, challenge := pkcePair()
	nonce := newUUID()
	authURL := fmt.Sprintf("%s/device/selectAccounts?challenge=%s&challenge_method=S256&nonce=%s&machine_id=%s&client_id=%s",
		a.webBase, challenge, nonce, a.machineID, prodClientID)
	fmt.Fprintf(out, "\nOpen this URL in your browser to authorize:\n\n  %s\n\nWaiting for authorization (up to 5 minutes)...\n", authURL)
	pollURL := fmt.Sprintf("%s/api/v1/deviceToken/poll?nonce=%s&verifier=%s&challenge_method=S256",
		a.openapiBase, nonce, verifier)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := a.httpc.Do(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 404 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("poll status %d: %s", resp.StatusCode, truncate(string(raw), 200))
		}
		var dr struct {
			Token            string `json:"token"`
			RefreshToken     string `json:"refresh_token"`
			ExpiresAt        string `json:"expires_at"`
			ExpiresIn        int64  `json:"expires_in"`
			RefreshExpiresAt string `json:"refresh_token_expires_at"`
			RefreshExpiresIn int64  `json:"refresh_token_expires_in"`
			UserID           string `json:"user_id"`
			UserName         string `json:"user_name"`
		}
		if err := json.Unmarshal(raw, &dr); err != nil {
			return err
		}
		if dr.Token == "" {
			return fmt.Errorf("poll response missing token: %s", truncate(string(raw), 200))
		}
		candidate := &userInfo{
			UID: dr.UserID, Name: dr.UserName,
			SecurityOAuthToken: dr.Token, AccessToken: dr.Token,
			RefreshToken: dr.RefreshToken, ExpireTime: parseExpiry(dr.ExpiresAt, dr.ExpiresIn),
			RefreshTokenExpireTime: parseExpiry(dr.RefreshExpiresAt, dr.RefreshExpiresIn),
			LoginMethod:            "browser", LoginTimestamp: time.Now().Unix(),
		}
		a.mu.Lock()
		if err := a.closedStateError(); err != nil {
			a.mu.Unlock()
			return err
		}
		if err := a.commitLoginCandidateLocked(ctx, candidate); err != nil {
			a.mu.Unlock()
			return err
		}
		a.mu.Unlock()
		// best-effort profile enrichment for this exact committed candidate.
		a.fetchUserInfo(ctx, candidate)
		a.mu.Lock()
		successUID, successName := candidate.UID, candidate.Name
		a.mu.Unlock()
		fmt.Fprintf(out, "Login successful. uid=%s name=%s\n", successUID, successName)
		return nil
	}
	return fmt.Errorf("device flow timed out after 5 minutes")
}

type authUserInfoProfile struct {
	UID     string   `json:"uid"`
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	OrgID   string   `json:"organization_id"`
	OrgName string   `json:"organization_name"`
	OrgTags []string `json:"organization_tags"`
}

func (a *authManager) requestUserInfo(ctx context.Context, token string) (authUserInfoProfile, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.openapiBase+"/api/v1/userinfo", nil)
	if err != nil {
		return authUserInfoProfile{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", qoderUserAgent())
	resp, err := a.httpc.Do(req)
	if err != nil {
		return authUserInfoProfile{}, err
	}
	if resp == nil {
		return authUserInfoProfile{}, fmt.Errorf("userinfo response is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authUserInfoProfile{}, fmt.Errorf("userinfo status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return authUserInfoProfile{}, err
	}
	var profile authUserInfoProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return authUserInfoProfile{}, err
	}
	return profile, nil
}

func applyAuthUserInfoProfile(ui *userInfo, profile authUserInfoProfile) {
	if ui == nil {
		return
	}
	if profile.UID != "" {
		ui.UID = profile.UID
	}
	if profile.Email != "" {
		ui.Email = profile.Email
	}
	if profile.Name != "" {
		ui.Name = profile.Name
	}
	if profile.OrgID != "" {
		ui.OrgID, ui.OrgName = profile.OrgID, profile.OrgName
	}
	if len(profile.OrgTags) > 0 {
		ui.OrgTags = slices.Clone(profile.OrgTags)
	}
}

func (a *authManager) fetchUserInfo(ctx context.Context, target *userInfo) {
	if target == nil {
		return
	}
	a.mu.Lock()
	if a.closedStateError() != nil || a.ui != target {
		a.mu.Unlock()
		return
	}
	tok := target.SecurityOAuthToken
	a.mu.Unlock()
	profile, err := a.requestUserInfo(ctx, tok)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closedStateError() != nil || a.ui != target {
		return
	}
	a.credentialDirty = true
	applyAuthUserInfoProfile(target, profile)
	_ = a.rebuildContextLocked(ctx)
	_ = a.saveLocked(ctx)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
