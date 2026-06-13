package kiro

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// generatePKCE generates a PKCE code verifier and SHA256 code challenge.
// This is the single source of truth for PKCE generation across the kiro package.
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// generateOAuthState generates a cryptographically random state parameter for OAuth flows.
func generateOAuthState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// normalizeExpiresIn returns a valid expires-in seconds value, defaulting to 3600 if invalid.
func normalizeExpiresIn(expiresIn int) int {
	if expiresIn <= 0 {
		return 3600
	}
	return expiresIn
}

// expiresAtFromSeconds computes an expiration time from an expires-in seconds value.
func expiresAtFromSeconds(expiresIn int) time.Time {
	return time.Now().Add(time.Duration(normalizeExpiresIn(expiresIn)) * time.Second)
}

// callbackResult holds the standard OAuth callback parameters.
type callbackResult struct {
	Code  string
	State string
	Error string
}

// callbackServerConfig configures the generic OAuth callback HTTP server.
type callbackServerConfig struct {
	// DefaultPort is the preferred port; 0 means dynamic allocation.
	DefaultPort int
	// CallbackPath is the HTTP path for the callback (e.g., "/oauth/callback").
	CallbackPath string
	// Timeout is the maximum time to wait for the callback.
	Timeout time.Duration
	// BindAddr overrides the default bind address (default "localhost").
	BindAddr string
}

// startCallbackServer starts a local HTTP server that receives an OAuth callback.
// It returns the redirect URI, a channel for the callback result, and any startup error.
// The server shuts down automatically when the context is cancelled, the timeout expires,
// or a callback is received.
func startCallbackServer(ctx context.Context, expectedState string, cfg callbackServerConfig) (string, <-chan callbackResult, error) {
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = "/oauth/callback"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Minute
	}
	bindAddr := cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "localhost"
	}

	// Try the default port first, then fall back to dynamic allocation.
	listenAddr := fmt.Sprintf("%s:%d", bindAddr, cfg.DefaultPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil && cfg.DefaultPort != 0 {
		log.Debugf("callback server: default port %d busy, falling back to dynamic port", cfg.DefaultPort)
		listener, err = net.Listen("tcp", fmt.Sprintf("%s:0", bindAddr))
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to start callback server: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", port, cfg.CallbackPath)
	resultCh := make(chan callbackResult, 1)

	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		errParam := r.URL.Query().Get("error")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if errParam != "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Login Failed</title></head>
<body><h1>Login Failed</h1><p>Error: %s</p><p>You can close this window.</p></body></html>`, html.EscapeString(errParam))
			resultCh <- callbackResult{Error: errParam}
			return
		}

		if state != expectedState {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Login Failed</title></head>
<body><h1>Login Failed</h1><p>Invalid state parameter</p><p>You can close this window.</p></body></html>`)
			resultCh <- callbackResult{Error: "state mismatch"}
			return
		}

		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Login Successful</title></head>
<body><h1>Login Successful!</h1><p>You can close this window and return to the terminal.</p>
<script>window.close();</script></body></html>`)
		resultCh <- callbackResult{Code: code, State: state}
	})

	server.Handler = mux

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Debugf("callback server error: %v", err)
		}
	}()

	// Auto-shutdown on context cancellation or timeout.
	// NOTE: Do NOT read from resultCh here — it would race with the caller
	// and consume the callback result before the caller can process it.
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(cfg.Timeout):
		}
		_ = server.Shutdown(context.Background())
	}()

	return redirectURI, resultCh, nil
}

// doJSONPost sends a JSON POST request and returns the response body, status code, and error.
// This eliminates repetitive HTTP POST boilerplate across OAuth token exchanges.
func doJSONPost(ctx context.Context, httpClient *http.Client, reqURL string, payload any, headers map[string]string) ([]byte, int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("failed to close response body: %v", errClose)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}
