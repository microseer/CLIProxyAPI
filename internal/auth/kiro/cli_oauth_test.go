package kiro

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildKiroCLISignInURLExact(t *testing.T) {
	state := "AbC123xyZ9"
	challenge := "pkce_challenge_value"
	got := buildKiroCLISignInURL(state, challenge)
	want := "https://app.kiro.dev/signin?state=AbC123xyZ9&code_challenge=pkce_challenge_value&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3128&redirect_from=kirocli"
	if got != want {
		t.Fatalf("signin URL mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestKiroCLITokenRedirectURIMatchesSignInRedirect(t *testing.T) {
	if kiroCLITokenRedirectURI != "http://localhost:3128" {
		t.Fatalf("unexpected token redirect URI: %s", kiroCLITokenRedirectURI)
	}
}

func TestKiroCLICallbackServerAcceptsRootCallback(t *testing.T) {
	o := &KiroCLIOAuth{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh, shutdown, err := o.startCallbackServer(ctx, "state-1")
	if err != nil {
		t.Fatalf("startCallbackServer failed: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = shutdown(shutdownCtx)
	}()

	resp, err := http.Get("http://localhost:3128/?code=code-1&state=state-1")
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case got := <-resultCh:
		if got.Err != "" || got.Code != "code-1" || got.State != "state-1" || got.RedirectURI != kiroCLITokenRedirectURI {
			t.Fatalf("unexpected callback result: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestKiroCLICallbackServerPreservesGoogleCallbackRedirectURI(t *testing.T) {
	o := &KiroCLIOAuth{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh, shutdown, err := o.startCallbackServer(ctx, "state-google")
	if err != nil {
		t.Fatalf("startCallbackServer failed: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = shutdown(shutdownCtx)
	}()

	resp, err := http.Get("http://localhost:3128/oauth/callback?login_option=google&code=code-google&state=state-google")
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case got := <-resultCh:
		wantRedirectURI := "http://localhost:3128/oauth/callback?login_option=google"
		if got.Err != "" || got.Code != "code-google" || got.State != "state-google" || got.LoginOption != "google" || got.RedirectURI != wantRedirectURI {
			t.Fatalf("unexpected callback result: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestKiroCLICallbackServerAcceptsBuilderIDLoginOption(t *testing.T) {
	o := &KiroCLIOAuth{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh, shutdown, err := o.startCallbackServer(ctx, "state-2")
	if err != nil {
		t.Fatalf("startCallbackServer failed: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = shutdown(shutdownCtx)
	}()

	resp, err := http.Get("http://localhost:3128/signin/callback?login_option=builderid&issuer_url=https%3A%2F%2Fview.awsapps.com%2Fstart&idc_region=us-east-1&state=state-2")
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case got := <-resultCh:
		if got.Err != "" || got.Code != "" || got.State != "state-2" || got.LoginOption != "builderid" || got.IssuerURL != builderIDStartURL || got.IDCRegion != "us-east-1" {
			t.Fatalf("unexpected callback result: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestGenerateKiroCLIStateShape(t *testing.T) {
	state, err := generateKiroCLIState()
	if err != nil {
		t.Fatalf("generateKiroCLIState failed: %v", err)
	}
	if len(state) != 10 {
		t.Fatalf("state length mismatch: got %d want 10", len(state))
	}
	for _, ch := range state {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
			t.Fatalf("state has non-alnum character: %q", ch)
		}
	}
}

func TestGenerateKiroCLIPKCEShape(t *testing.T) {
	verifier, challenge, err := generateKiroCLIPKCE()
	if err != nil {
		t.Fatalf("generateKiroCLIPKCE failed: %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatalf("verifier/challenge must be non-empty")
	}
	if strings.ContainsAny(verifier, "+/=") {
		t.Fatalf("verifier not base64url raw: %s", verifier)
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Fatalf("challenge not base64url raw: %s", challenge)
	}
	h := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != wantChallenge {
		t.Fatalf("challenge mismatch with verifier: got %s want %s", challenge, wantChallenge)
	}
}

func TestSignTelemetryRequestHeaderShape(t *testing.T) {
	o := &KiroCLIOAuth{}
	body := []byte(`{"x":1}`)
	creds := &telemetryTemporaryCredentials{
		AccessKeyID:  "ASIAEXAMPLE",
		SecretKey:    "secret",
		SessionToken: "session-token",
	}
	now := time.Date(2026, 4, 17, 11, 49, 2, 0, time.UTC)
	req := httptest.NewRequest(http.MethodPost, kiroCLITelemetryEndpoint, strings.NewReader(string(body)))

	o.signTelemetryRequest(req, body, creds, now)

	if got := req.Header.Get("User-Agent"); got != kiroCLIRustUserAgent {
		t.Fatalf("unexpected User-Agent: %s", got)
	}
	if got := req.Header.Get("X-Amz-User-Agent"); got != kiroCLITelemetryAmzUA {
		t.Fatalf("unexpected X-Amz-User-Agent: %s", got)
	}
	if got := req.Header.Get("X-Amz-Date"); got == "" {
		t.Fatalf("missing X-Amz-Date")
	}
	if got := req.Header.Get("Authorization"); !strings.Contains(got, "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/") {
		t.Fatalf("invalid Authorization header: %s", got)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "session-token" {
		t.Fatalf("unexpected security token: %s", got)
	}
}

func TestNormalizeTelemetryOS(t *testing.T) {
	if got := normalizeTelemetryOS("darwin"); got != "macos" {
		t.Fatalf("darwin mapping mismatch: %s", got)
	}
	if got := normalizeTelemetryOS("linux"); got != "linux" {
		t.Fatalf("linux mapping mismatch: %s", got)
	}
	if got := normalizeTelemetryOS("windows"); got != "windows" {
		t.Fatalf("windows mapping mismatch: %s", got)
	}
}
