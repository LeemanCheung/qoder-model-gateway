package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	cfg, err := parseAppConfig(os.Args[1:], os.LookupEnv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	debugf := func(format string, args ...any) {
		if cfg.verbose {
			log.Printf(format, args...)
		}
	}
	always := func(format string, args ...any) { log.Printf(format, args...) }
	if err := run(ctx, cfg, defaultAppDeps(), os.Stdout, debugf, always); err != nil {
		log.Fatal(err)
	}
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "~"
	}
	return h
}

func (r *modelResolver) keys() []string {
	out := make([]string, 0, len(r.byKey))
	for k := range r.byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadCatalog builds the model catalog: built-in defaults, optionally overridden
// by a plaintext catalog file or the CLI's encrypted model cache.
func loadCatalog(ctx context.Context, decryptor modelCacheDecryptor, authFile, uid, catalogPath string, logf func(string, ...any)) []*modelConfig {
	catalog := builtinCatalog()
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var raw []byte
	if catalogPath != "" {
		var err error
		raw, err = os.ReadFile(catalogPath)
		if err != nil {
			logf("catalog read %s: %v", catalogPath, err)
		}
	} else {
		cachePath := filepath.Clean(filepath.Join(filepath.Dir(authFile), "..", ".models", uid, "catalog-v6"))
		blob, err := os.ReadFile(cachePath)
		if err != nil {
			logf("catalog cache read failed")
		} else if decryptor == nil {
			logf("catalog decrypt failed")
		} else {
			raw, err = decryptor.Decrypt(ctx, strings.TrimSpace(string(blob)), uid)
			if err != nil {
				logf("catalog decrypt failed")
				raw = nil
			}
		}
	}
	if len(raw) > 0 {
		var cat struct {
			Chat []*modelConfig `json:"chat"`
		}
		if json.Unmarshal(raw, &cat) == nil && len(cat.Chat) > 0 {
			merged := map[string]*modelConfig{}
			for _, mc := range catalog {
				merged[mc.Key] = mc
			}
			for _, mc := range cat.Chat {
				if mc.Format == "" {
					mc.Format = "openai"
				}
				if mc.Source == "" {
					mc.Source = "system"
				}
				mc.Enable = true
				for _, tier := range mc.ContextConfig {
					if tier.TokenCount > mc.MaxInputTokens {
						mc.MaxInputTokens = tier.TokenCount
					}
				}
				merged[mc.Key] = mc
			}
			catalog = catalog[:0]
			for _, mc := range merged {
				catalog = append(catalog, mc)
			}
			logf("catalog merged: %d models", len(catalog))
		}
	}
	return catalog
}

func builtinCatalog() []*modelConfig {
	type spec struct {
		key, name string
		reasoning bool
		maxIn     int
	}
	specs := []spec{
		{"auto", "Auto", false, 180000},
		{"ultimate", "Ultimate", true, 1000000},
		{"performance", "Performance", false, 1000000},
		{"efficient", "Efficient", false, 180000},
		{"lite", "Lite", false, 180000},
		{"cmodel", "Cantus", true, 1000000},
		{"qmodel_38max", "Qwen3.8-Max", true, 1000000},
		{"qmodel_latest", "Qwen3.7-Max", false, 1000000},
		{"qmodel", "Qwen3.7-Plus", false, 1000000},
		{"kmodel_latest", "Kimi-K3", false, 1000000},
		{"kmodel", "Kimi-K2.7-Code", false, 256000},
		{"gmodel", "GLM-5.3", true, 1000000},
		{"gm51model", "GLM-5.2", true, 1000000},
		{"dmodel", "DeepSeek-V4-Pro", true, 1000000},
		{"dfmodel", "DeepSeek-V4-Flash", true, 1000000},
		{"mmodel", "MiniMax-M3", false, 1000000},
	}
	out := make([]*modelConfig, 0, len(specs))
	for _, sp := range specs {
		out = append(out, &modelConfig{
			Key: sp.key, Format: "openai", Source: "system", Enable: true,
			DisplayName: sp.name, IsVL: true, IsReasoning: sp.reasoning,
			PriceFactor: 1.0, MaxInputTokens: sp.maxIn,
		})
	}
	return out
}

// patLogin exchanges a personal access token for a device token.
func patLogin(ctx context.Context, am *authManager, pat string) error {
	if err := am.closedStateError(); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"personal_token": pat})
	req, err := http.NewRequestWithContext(ctx, "POST", am.openapiBase+"/api/v1/jobToken/exchange", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", qoderUserAgent())
	resp, err := am.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("jobToken/exchange status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var r struct {
		Token        string `json:"token"`
		DeviceToken  string `json:"device_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshExpAt string `json:"refresh_token_expires_at"`
		RefreshExpIn int64  `json:"refresh_token_expires_in"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	tok := r.Token
	if tok == "" {
		tok = r.DeviceToken
	}
	if tok == "" {
		tok = r.AccessToken
	}
	if tok == "" {
		return fmt.Errorf("exchange response missing token")
	}
	candidate := &userInfo{
		SecurityOAuthToken: tok, AccessToken: tok,
		RefreshToken: r.RefreshToken, ExpireTime: parseExpiry(r.ExpiresAt, r.ExpiresIn),
		RefreshTokenExpireTime: parseExpiry(r.RefreshExpAt, r.RefreshExpIn),
		PersonalAccessToken:    pat,
		LoginMethod:            "token", LoginTimestamp: time.Now().Unix(),
	}
	profile, err := am.requestUserInfo(ctx, tok)
	if err != nil {
		return fmt.Errorf("could not fetch user info after exchange")
	}
	applyAuthUserInfoProfile(candidate, profile)
	if candidate.UID == "" {
		return fmt.Errorf("could not fetch user info after exchange")
	}
	am.mu.Lock()
	if err := am.closedStateError(); err != nil {
		am.mu.Unlock()
		return err
	}
	if err := am.commitLoginCandidateLocked(ctx, candidate); err != nil {
		am.mu.Unlock()
		return err
	}
	am.mu.Unlock()
	return nil
}
