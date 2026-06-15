// Package kiro provides social authentication (Google/GitHub) for Kiro via AuthServiceClient.
package kiro

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

const (
	// Kiro AuthService endpoint
	kiroAuthServiceEndpoint = "https://prod.us-east-1.auth.desktop.kiro.dev"

	// OAuth timeout
	socialAuthTimeout = 10 * time.Minute
)

// SocialProvider represents the social login provider.
type SocialProvider string

const (
	// ProviderGoogle is Google OAuth provider
	ProviderGoogle SocialProvider = "Google"
	// ProviderGitHub is GitHub OAuth provider
	ProviderGitHub SocialProvider = "Github"
	// Note: AWS Builder ID is NOT supported by Kiro's auth service.
	// It only supports: Google, Github, Cognito
	// AWS Builder ID must use device code flow via SSO OIDC.
)

// CreateTokenRequest is sent to Kiro's /oauth/token endpoint.
type CreateTokenRequest struct {
	Code           string `json:"code"`
	CodeVerifier   string `json:"code_verifier"`
	RedirectURI    string `json:"redirect_uri"`
	InvitationCode string `json:"invitation_code,omitempty"`
}

// SocialTokenResponse from Kiro's /oauth/token endpoint for social auth.
type SocialTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileArn   string `json:"profileArn"`
	ExpiresIn    int    `json:"expiresIn"`
}

// SocialAuthClient handles social authentication with Kiro.
type SocialAuthClient struct {
	httpClient      *http.Client
	cfg             *config.Config
	protocolHandler *ProtocolHandler
	machineID       string
	kiroVersion     string
}

// NewSocialAuthClient creates a new social auth client.
func NewSocialAuthClient(cfg *config.Config) *SocialAuthClient {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	fp := GlobalFingerprintManager().GetFingerprint("login")
	return &SocialAuthClient{
		httpClient:      client,
		cfg:             cfg,
		protocolHandler: NewProtocolHandler(),
		machineID:       fp.KiroHash,
		kiroVersion:     fp.KiroVersion,
	}
}

// buildLoginURL constructs the Kiro OAuth login URL.
// The login endpoint expects a GET request with query parameters.
// Format: /login?idp=Google&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...&prompt=select_account
// The prompt=select_account parameter forces the account selection screen even if already logged in.
func (c *SocialAuthClient) buildLoginURL(provider, redirectURI, codeChallenge, state string) string {
	return fmt.Sprintf("%s/login?idp=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&prompt=select_account",
		kiroAuthServiceEndpoint,
		provider,
		url.QueryEscape(redirectURI),
		codeChallenge,
		state,
	)
}

// CreateToken exchanges the authorization code for tokens.
func (c *SocialAuthClient) CreateToken(ctx context.Context, req *CreateTokenRequest) (*SocialTokenResponse, error) {
	tokenURL := kiroAuthServiceEndpoint + "/oauth/token"
	respBody, statusCode, err := doJSONPost(ctx, c.httpClient, tokenURL, req,
		map[string]string{
			"User-Agent": fmt.Sprintf("KiroIDE-%s-%s", c.kiroVersion, c.machineID),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}

	if statusCode != http.StatusOK {
		log.Debugf("token exchange failed (status %d): %s", statusCode, string(respBody))
		return nil, fmt.Errorf("token exchange failed (status %d)", statusCode)
	}

	var tokenResp SocialTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// RefreshSocialToken refreshes an expired social auth token.
func (c *SocialAuthClient) RefreshSocialToken(ctx context.Context, refreshToken string) (*KiroTokenData, error) {
	refreshURL := kiroAuthServiceEndpoint + "/refreshToken"
	userAgent := fmt.Sprintf("KiroIDE-%s-%s", c.kiroVersion, c.machineID)
	return doRefreshToken(ctx, c.httpClient, refreshURL, refreshToken, userAgent, "social", "")
}

// LoginWithSocial performs OAuth login with Google or GitHub.
// Uses kiro:// protocol handler for OAuth callback (aligned with Kiro Desktop/Account Manager).
func (c *SocialAuthClient) LoginWithSocial(ctx context.Context, provider SocialProvider, noBrowser bool) (*KiroTokenData, error) {
	providerName := string(provider)

	fmt.Println("\n╔══════════════════════════════════════════════════════════╗")
	fmt.Printf("║         Kiro Authentication (%s)                    ║\n", providerName)
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	fmt.Println("\nSetting up authentication...")

	if !IsProtocolHandlerInstalled() {
		fmt.Println("\nInstalling kiro:// protocol handler...")
		port, err := c.protocolHandler.Start(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to start protocol handler: %w", err)
		}
		if err := InstallProtocolHandler(port); err != nil {
			return nil, fmt.Errorf("failed to install protocol handler: %w\n\nPlease install manually or use Builder ID authentication instead", err)
		}
		fmt.Printf("✓ Protocol handler installed on port %d\n", port)
	}

	port, err := c.protocolHandler.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start protocol handler: %w", err)
	}
	log.Debugf("kiro social auth: protocol handler started on port %d", port)

	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	state, err := generateOAuthState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Use kiro:// protocol handler for OAuth callback
	redirectURI := KiroRedirectURI
	authURL := c.buildLoginURL(providerName, redirectURI, codeChallenge, state)

	if c.cfg != nil {
		browser.SetIncognitoMode(c.cfg.IncognitoBrowser)
		if !c.cfg.IncognitoBrowser {
			log.Info("kiro: using normal browser mode (--no-incognito). Note: You may not be able to select a different account.")
		} else {
			log.Debug("kiro: using incognito mode for multi-account support")
		}
	} else {
		browser.SetIncognitoMode(true)
		log.Debug("kiro: using incognito mode for multi-account support (default)")
	}

	fmt.Println("\n════════════════════════════════════════════════════════════")
	fmt.Printf("  Opening browser for %s authentication...\n", providerName)
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("\n  URL: %s\n\n", authURL)

	if err := openBrowserURL(authURL, noBrowser); err != nil {
		log.Warnf("Could not open browser automatically: %v", err)
	}

	fmt.Println("\n  Waiting for authentication callback...")

	callback, err := c.protocolHandler.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to receive callback: %w", err)
	}

	if callback.Error != "" {
		return nil, fmt.Errorf("authentication error: %s", callback.Error)
	}

	if callback.State != state {
		return nil, fmt.Errorf("state mismatch - possible CSRF attack")
	}

	if callback.Code == "" {
		return nil, fmt.Errorf("no authorization code received")
	}

	fmt.Println("\n✓ Authorization received!")
	fmt.Println("Exchanging code for tokens...")

	tokenReq := &CreateTokenRequest{
		Code:         callback.Code,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
	}

	tokenResp, err := c.CreateToken(ctx, tokenReq)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	fmt.Println("\n✓ Authentication successful!")

	if err := browser.CloseBrowser(); err != nil {
		log.Debugf("Failed to close browser: %v", err)
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	email := ExtractEmailFromJWT(tokenResp.AccessToken)

	if email == "" && isInteractiveTerminal() {
		fmt.Print("\n  Enter account label for file naming (optional, press Enter to skip): ")
		reader := bufio.NewReader(os.Stdin)
		var err error
		email, err = reader.ReadString('\n')
		if err != nil {
			log.Debugf("Failed to read account label: %v", err)
		}
		email = strings.TrimSpace(email)
	}

	return &KiroTokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ProfileArn:   tokenResp.ProfileArn,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		AuthMethod:   "social",
		Provider:     providerName,
		Email:        email,
		Region:       "us-east-1",
	}, nil
}

// LoginWithGoogle performs OAuth login with Google.
func (c *SocialAuthClient) LoginWithGoogle(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	return c.LoginWithSocial(ctx, ProviderGoogle, noBrowser)
}

// LoginWithGitHub performs OAuth login with GitHub.
func (c *SocialAuthClient) LoginWithGitHub(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	return c.LoginWithSocial(ctx, ProviderGitHub, noBrowser)
}

// forceDefaultProtocolHandler sets our protocol handler as the default for kiro:// URLs.
// This prevents the "Open with" dialog from appearing on Linux.
// On non-Linux platforms, this is a no-op as they use different mechanisms.
func forceDefaultProtocolHandler() {
	if runtime.GOOS != "linux" {
		return // Non-Linux platforms use different handler mechanisms
	}

	// Set our handler as default using xdg-mime
	cmd := exec.Command("xdg-mime", "default", "kiro-oauth-handler.desktop", "x-scheme-handler/kiro")
	if err := cmd.Run(); err != nil {
		log.Warnf("Failed to set default protocol handler: %v. You may see a handler selection dialog.", err)
	}
}

// isInteractiveTerminal checks if stdin is connected to an interactive terminal.
// Returns false in CI/automated environments or when stdin is piped.
func isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
