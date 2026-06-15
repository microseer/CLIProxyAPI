// Package kiro provides OAuth2 authentication for Kiro using native Google login.
package kiro

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

const (
	// Kiro auth endpoint
	kiroAuthEndpoint = "https://prod.us-east-1.auth.desktop.kiro.dev"
)

// KiroTokenResponse represents the response from Kiro token endpoint.
type KiroTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileArn   string `json:"profileArn"`
	ExpiresIn    int    `json:"expiresIn"`
}

// KiroOAuth handles the OAuth flow for Kiro authentication.
type KiroOAuth struct {
	httpClient  *http.Client
	cfg         *config.Config
	machineID   string
	kiroVersion string
}

// NewKiroOAuth creates a new Kiro OAuth handler.
func NewKiroOAuth(cfg *config.Config) *KiroOAuth {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	fp := GlobalFingerprintManager().GetFingerprint("login")
	return &KiroOAuth{
		httpClient:  client,
		cfg:         cfg,
		machineID:   fp.KiroHash,
		kiroVersion: fp.KiroVersion,
	}
}

// LoginWithBuilderID performs OAuth login with AWS Builder ID using device code flow.
func (o *KiroOAuth) LoginWithBuilderID(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	ssoClient := NewSSOOIDCClient(o.cfg)
	return ssoClient.LoginWithBuilderID(ctx, noBrowser)
}

// LoginWithBuilderIDAuthCode performs OAuth login with AWS Builder ID using authorization code flow.
// This provides a better UX than device code flow as it uses automatic browser callback.
func (o *KiroOAuth) LoginWithBuilderIDAuthCode(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	ssoClient := NewSSOOIDCClient(o.cfg)
	return ssoClient.LoginWithBuilderIDAuthCode(ctx, noBrowser)
}

// exchangeCodeForToken exchanges the authorization code for tokens.
func (o *KiroOAuth) exchangeCodeForToken(ctx context.Context, code, codeVerifier, redirectURI string) (*KiroTokenData, error) {
	tokenURL := kiroAuthEndpoint + "/oauth/token"
	userAgent := fmt.Sprintf("KiroIDE-%s-%s", o.kiroVersion, o.machineID)
	return doTokenExchange(ctx, o.httpClient, tokenURL, code, codeVerifier, redirectURI, userAgent, "social", "")
}

// RefreshToken refreshes an expired access token.
// Uses KiroIDE-style User-Agent to match official Kiro IDE behavior.
func (o *KiroOAuth) RefreshToken(ctx context.Context, refreshToken string) (*KiroTokenData, error) {
	return o.RefreshTokenWithFingerprint(ctx, refreshToken, "")
}

// RefreshTokenWithFingerprint refreshes an expired access token with a specific fingerprint.
// tokenKey is used to generate a consistent fingerprint for the token.
func (o *KiroOAuth) RefreshTokenWithFingerprint(ctx context.Context, refreshToken, tokenKey string) (*KiroTokenData, error) {
	refreshURL := kiroAuthEndpoint + "/refreshToken"
	userAgent := fmt.Sprintf("KiroIDE-%s-%s", o.kiroVersion, o.machineID)
	return doRefreshToken(ctx, o.httpClient, refreshURL, refreshToken, userAgent, "social", "")
}

// LoginWithGoogle performs OAuth login with Google using Kiro's social auth.
// This uses a custom protocol handler (kiro://) to receive the callback.
func (o *KiroOAuth) LoginWithGoogle(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	socialClient := NewSocialAuthClient(o.cfg)
	return socialClient.LoginWithGoogle(ctx, noBrowser)
}

// LoginWithGitHub performs OAuth login with GitHub using Kiro's social auth.
// This uses a custom protocol handler (kiro://) to receive the callback.
func (o *KiroOAuth) LoginWithGitHub(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	socialClient := NewSocialAuthClient(o.cfg)
	return socialClient.LoginWithGitHub(ctx, noBrowser)
}
