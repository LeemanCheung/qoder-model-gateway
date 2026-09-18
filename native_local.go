package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
)

var nativeShutdown func()

func nativeLockedDown() bool     { return os.Getenv("QODER2API_NATIVE_LOCKDOWN") == "1" }
func localHost(name string) bool { return name == "127.0.0.1" || name == "localhost" || name == "::1" }
func validateLocalNativeConfig(cfg appConfig) error {
	if !nativeLockedDown() {
		return nil
	}
	host, _, err := net.SplitHostPort(cfg.addr)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("native proxy requires IPv4 loopback binding")
	}
	if len(cfg.sk) < 32 {
		return fmt.Errorf("native proxy requires a local credential")
	}
	if cfg.dumpDir != "" || cfg.verbose {
		return fmt.Errorf("request dumps and verbose logs are disabled in native local mode")
	}
	if !cfg.readOnlyAuth {
		return fmt.Errorf("native local mode requires read-only authentication")
	}
	if cfg.inferEndpoint != "https://gateway.qoder.com.cn" || cfg.openapiEndpoint != "https://openapi.qoder.com.cn" || cfg.webEndpoint != "https://qoder.cn" {
		return fmt.Errorf("native proxy requires verified CN endpoints")
	}
	return nil
}
func localNativeGuard(next http.Handler) http.Handler {
	if !nativeLockedDown() {
		return next
	}
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || !localHost(host) {
			http.Error(w, "loopback host required", 403)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || !localHost(u.Hostname()) {
				http.Error(w, "local origin required", 403)
				return
			}
		}
		if r.URL.Path == "/health" || r.URL.Path == "/_qoder/shutdown" || r.URL.Path == "/v1/models" {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "2")
			http.Error(w, "local inference concurrency limit", 429)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		next.ServeHTTP(w, r)
	})
}

func nativePublicError(message string) string {
	if nativeLockedDown() {
		return "Qoder model inference failed. Check the original Qoder CLI login and account model availability."
	}
	return message
}
