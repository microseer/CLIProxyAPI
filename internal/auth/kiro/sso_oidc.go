// Package kiro provides AWS SSO OIDC authentication for Kiro.
package kiro

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	// AWS SSO OIDC endpoints
	ssoOIDCEndpoint = "https://oidc.us-east-1.amazonaws.com"

	// Kiro's start URL for Builder ID
	builderIDStartURL = "https://view.awsapps.com/start"

	// Amazon internal Identity Center start URL used by Enterprise accounts when no URL is supplied.
	enterpriseStartURL = "https://amzn.awsapps.com/start"

	// Default region for IDC
	defaultIDCRegion = "us-east-1"

	// Polling interval
	pollInterval = 5 * time.Second

	// Authorization code flow callback
	authCodeCallbackPort = 19877
	authCodeCallbackPath = "/oauth/callback"
)

func (c *SSOOIDCClient) getOIDCEndpointOverride() config.OAuthEndpointConfig {
	if c.cfg != nil {
		return c.cfg.GetOAuthEndpointOverride("kiro")
	}
	return config.OAuthEndpointConfig{}
}

func (c *SSOOIDCClient) getOIDCEndpointWithOverride(region string) string {
	if override := c.getOIDCEndpointOverride(); override.ApiBaseURL != "" {
		return strings.TrimRight(override.ApiBaseURL, "/")
	}
	return getOIDCEndpoint(region)
}

var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
)

type SSOOIDCClient struct {
	httpClient *http.Client
	cfg        *config.Config
}

// NewSSOOIDCClient creates a new SSO OIDC client.
func NewSSOOIDCClient(cfg *config.Config) *SSOOIDCClient {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	return &SSOOIDCClient{
		httpClient: client,
		cfg:        cfg,
	}
}

// RegisterClientResponse from AWS SSO OIDC.
type RegisterClientResponse struct {
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ClientIDIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
}

// StartDeviceAuthResponse from AWS SSO OIDC.
type StartDeviceAuthResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

// CreateTokenResponse from AWS SSO OIDC.
type CreateTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
	RefreshToken string `json:"refreshToken"`
}

// getOIDCEndpoint returns the OIDC endpoint for the given region.
func getOIDCEndpoint(region string) string {
	if region == "" {
		region = defaultIDCRegion
	}
	return fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
}

// promptInput prompts the user for input with an optional default value.
func promptInput(prompt, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Warnf("Error reading input: %v", err)
		return defaultValue
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

// promptSelect prompts the user to select from options using number input.
func promptSelect(prompt string, options []string) int {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println(prompt)
		for i, opt := range options {
			fmt.Printf("  %d) %s\n", i+1, opt)
		}
		fmt.Printf("Enter selection (1-%d): ", len(options))

		input, err := reader.ReadString('\n')
		if err != nil {
			log.Warnf("Error reading input: %v", err)
			return 0 // Default to first option on error
		}
		input = strings.TrimSpace(input)

		// Parse the selection
		selection, err := strconv.Atoi(input)
		if err != nil || selection < 1 || selection > len(options) {
			fmt.Printf("Invalid selection '%s'. Please enter a number between 1 and %d.\n\n", input, len(options))
			continue
		}
		return selection - 1
	}
}

// RegisterClientWithRegion registers a new OIDC client with AWS using a specific region.
func (c *SSOOIDCClient) RegisterClientWithRegion(ctx context.Context, region string) (*RegisterClientResponse, error) {
	endpoint := c.getOIDCEndpointWithOverride(region)

	payload := map[string]interface{}{
		"clientName": "Kiro IDE",
		"clientType": "public",
		"scopes":     []string{"codewhisperer:completions", "codewhisperer:analysis", "codewhisperer:conversations", "codewhisperer:transformations", "codewhisperer:taskassist"},
		"grantTypes": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/client/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	SetOIDCHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("register client failed (status %d): %s", resp.StatusCode, string(respBody))
		return nil, fmt.Errorf("register client failed (status %d)", resp.StatusCode)
	}

	var result RegisterClientResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// StartDeviceAuthorizationWithIDC starts the device authorization flow for IDC.
func (c *SSOOIDCClient) StartDeviceAuthorizationWithIDC(ctx context.Context, clientID, clientSecret, startURL, region string) (*StartDeviceAuthResponse, error) {
	endpoint := c.getOIDCEndpointWithOverride(region)

	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"startUrl":     startURL,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/device_authorization", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	SetOIDCHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("start device auth failed (status %d): %s", resp.StatusCode, string(respBody))
		return nil, fmt.Errorf("start device auth failed (status %d)", resp.StatusCode)
	}

	var result StartDeviceAuthResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateTokenWithRegion polls for the access token after user authorization using a specific region.
func (c *SSOOIDCClient) CreateTokenWithRegion(ctx context.Context, clientID, clientSecret, deviceCode, region string) (*CreateTokenResponse, error) {
	endpoint := c.getOIDCEndpointWithOverride(region)

	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"deviceCode":   deviceCode,
		"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/token", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	SetOIDCHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	// Check for pending authorization
	if resp.StatusCode == http.StatusBadRequest {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil {
			if errResp.Error == "authorization_pending" {
				return nil, ErrAuthorizationPending
			}
			if errResp.Error == "slow_down" {
				return nil, ErrSlowDown
			}
		}
		log.Debugf("create token failed: %s", string(respBody))
		return nil, fmt.Errorf("create token failed")
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("create token failed (status %d): %s", resp.StatusCode, string(respBody))
		return nil, fmt.Errorf("create token failed (status %d)", resp.StatusCode)
	}

	var result CreateTokenResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// RefreshTokenWithRegion refreshes an access token using the refresh token with a specific OIDC region.
func (c *SSOOIDCClient) RefreshTokenWithRegion(ctx context.Context, clientID, clientSecret, refreshToken, region, startURL string) (*KiroTokenData, error) {
	if region == "" {
		region = defaultIDCRegion
	}
	endpoint := c.getOIDCEndpointWithOverride(region)

	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"refreshToken": refreshToken,
		"grantType":    "refresh_token",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/token", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	SetOIDCHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Warnf("IDC token refresh failed (status %d): %s", resp.StatusCode, string(respBody))
		return nil, fmt.Errorf("token refresh failed (status %d)", resp.StatusCode)
	}

	var result CreateTokenResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	return &KiroTokenData{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		AuthMethod:   "idc",
		Provider:     "AWS",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		StartURL:     startURL,
		Region:       region,
	}, nil
}

// LoginWithIDC performs the full device code flow for AWS Identity Center (IDC).
func (c *SSOOIDCClient) LoginWithIDC(ctx context.Context, startURL, region string, noBrowser bool) (*KiroTokenData, error) {
	provider := normalizeIDCProvider("", startURL)
	return c.performDeviceCodeFlow(ctx, deviceCodeFlowConfig{
		StartURL:    startURL,
		Region:      region,
		AuthMethod:  "idc",
		Provider:    provider,
		NoBrowser:   noBrowser,
		HeaderTitle: "Kiro Authentication (AWS Identity Center)",
	})
}

// openBrowserURL opens the given URL in the browser unless noBrowser is set.
// When noBrowser is true, the URL is printed to stdout for manual opening.
func openBrowserURL(rawURL string, noBrowser bool) error {
	if noBrowser {
		fmt.Printf("Open this URL in browser to continue login:\n%s\n", rawURL)
		return nil
	}
	if errOpen := browser.OpenURL(rawURL); errOpen != nil {
		log.Warnf("failed to open browser: %v", errOpen)
		fmt.Printf("Open this URL in browser to continue login:\n%s\n", rawURL)
		return errOpen
	}
	fmt.Println("  (Browser opened automatically)")
	return nil
}

// IDCLoginOptions holds optional parameters for IDC login.
type IDCLoginOptions struct {
	StartURL      string // Pre-configured start URL (skips prompt if set)
	Region        string // OIDC region for login and token refresh (defaults to us-east-1)
	Provider      string // BuilderId or Enterprise
	UseDeviceCode bool   // Use Device Code flow instead of Auth Code flow
	NoBrowser     bool   // Don't open browser automatically for OAuth
}

// LoginWithMethodSelection prompts the user to select between Builder ID and IDC, then performs the login.
// Options can be provided to pre-configure IDC parameters (startURL, region).
// If StartURL is provided in opts, IDC flow is used directly without prompting.
func (c *SSOOIDCClient) LoginWithMethodSelection(ctx context.Context, opts *IDCLoginOptions) (*KiroTokenData, error) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║              Kiro Authentication (AWS)                    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	// If IDC options with StartURL are provided, skip method selection and use IDC directly
	if opts != nil && (opts.StartURL != "" || strings.EqualFold(opts.Provider, "BuilderId") || strings.EqualFold(opts.Provider, "Enterprise")) {
		region := opts.Region
		if region == "" {
			region = defaultIDCRegion
		}
		provider := normalizeIDCProvider(opts.Provider, opts.StartURL)
		startURL := resolveIDCStartURL(provider, opts.StartURL)
		noBrowser := opts.NoBrowser
		fmt.Printf("\n  Using %s with Start URL: %s\n", provider, startURL)
		fmt.Printf("  Region: %s\n", region)

		if opts.UseDeviceCode {
			if strings.EqualFold(provider, "BuilderId") {
				return c.LoginWithBuilderID(ctx, noBrowser)
			}
			return c.LoginWithIDC(ctx, startURL, region, noBrowser)
		}
		return c.LoginWithIDCAuthCodeProvider(ctx, startURL, region, provider, noBrowser)
	}

	// Prompt for login method
	options := []string{
		"Use with Builder ID (personal AWS account)",
		"Use with IDC Account (organization SSO)",
	}
	selection := promptSelect("\n? Select login method:", options)

	if selection == 0 {
		if opts != nil && opts.UseDeviceCode {
			return c.LoginWithBuilderID(ctx, opts.NoBrowser)
		}
		noBrowser := false
		if opts != nil {
			noBrowser = opts.NoBrowser
		}
		return c.LoginWithBuilderIDAuthCode(ctx, noBrowser)
	}

	// IDC flow - use pre-configured values or prompt
	var startURL, region string

	if opts != nil {
		startURL = opts.StartURL
		region = opts.Region
	}

	fmt.Println()

	// Use pre-configured startURL or prompt
	if startURL == "" {
		startURL = promptInput("? Enter Start URL", "")
		if startURL == "" {
			return nil, fmt.Errorf("start URL is required for IDC login")
		}
	} else {
		fmt.Printf("  Using pre-configured Start URL: %s\n", startURL)
	}

	// Use pre-configured region or prompt
	if region == "" {
		region = promptInput("? Enter Region", defaultIDCRegion)
	} else {
		fmt.Printf("  Using pre-configured Region: %s\n", region)
	}

	provider := normalizeIDCProvider("", startURL)
	if opts != nil && opts.Provider != "" {
		provider = normalizeIDCProvider(opts.Provider, startURL)
	}

	if opts != nil && opts.UseDeviceCode {
		return c.LoginWithIDC(ctx, startURL, region, opts.NoBrowser)
	}
	return c.LoginWithIDCAuthCodeProvider(ctx, startURL, region, provider, opts.NoBrowser)
}

// LoginWithIDCAndOptions performs IDC login with the specified region.
func (c *SSOOIDCClient) LoginWithIDCAndOptions(ctx context.Context, startURL, region string, noBrowser bool) (*KiroTokenData, error) {
	return c.LoginWithIDC(ctx, startURL, region, noBrowser)
}

// RegisterClient registers a new OIDC client with AWS using the default region.
func (c *SSOOIDCClient) RegisterClient(ctx context.Context) (*RegisterClientResponse, error) {
	return c.RegisterClientWithRegion(ctx, defaultIDCRegion)
}

func (c *SSOOIDCClient) StartDeviceAuthorization(ctx context.Context, clientID, clientSecret string) (*StartDeviceAuthResponse, error) {
	return c.StartDeviceAuthorizationWithIDC(ctx, clientID, clientSecret, builderIDStartURL, defaultIDCRegion)
}

// CreateToken polls for the access token after user authorization.
func (c *SSOOIDCClient) CreateToken(ctx context.Context, clientID, clientSecret, deviceCode string) (*CreateTokenResponse, error) {
	return c.CreateTokenWithRegion(ctx, clientID, clientSecret, deviceCode, defaultIDCRegion)
}

// RefreshToken refreshes an access token using the refresh token (default region).
func (c *SSOOIDCClient) RefreshToken(ctx context.Context, clientID, clientSecret, refreshToken string) (*KiroTokenData, error) {
	return c.RefreshTokenWithRegion(ctx, clientID, clientSecret, refreshToken, defaultIDCRegion, "")
}

// deviceCodeFlowConfig holds parameters for the device code authorization flow.
type deviceCodeFlowConfig struct {
	StartURL    string
	Region      string
	AuthMethod  string // "builder-id" or "idc"
	Provider    string // "AWS" or "Enterprise"
	NoBrowser   bool
	HeaderTitle string // Title for the UI banner
}

// performDeviceCodeFlow executes the common device code authorization flow.
func (c *SSOOIDCClient) performDeviceCodeFlow(ctx context.Context, cfg deviceCodeFlowConfig) (*KiroTokenData, error) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════╗")
	fmt.Printf("║       %s          ║\n", cfg.HeaderTitle)
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	// Step 1: Register client
	fmt.Println("\nRegistering client...")
	regResp, err := c.RegisterClientWithRegion(ctx, cfg.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}
	log.Debugf("Client registered: %s", regResp.ClientID)

	// Step 2: Start device authorization
	fmt.Println("Starting device authorization...")
	authResp, err := c.StartDeviceAuthorizationWithIDC(ctx, regResp.ClientID, regResp.ClientSecret, cfg.StartURL, cfg.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to start device auth: %w", err)
	}

	// Step 3: Show user the verification URL
	fmt.Printf("\n")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("  Confirm the following code in the browser:\n")
	fmt.Printf("  Code: %s\n", authResp.UserCode)
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("\n  Open this URL: %s\n\n", authResp.VerificationURIComplete)

	// Open browser
	_ = openBrowserURL(authResp.VerificationURIComplete, cfg.NoBrowser)

	// Step 4: Poll for token
	fmt.Println("Waiting for authorization...")

	interval := pollInterval
	if authResp.Interval > 0 {
		interval = time.Duration(authResp.Interval) * time.Second
	}

	deadline := time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			browser.CloseBrowser()
			return nil, ctx.Err()
		case <-time.After(interval):
			tokenResp, err := c.CreateTokenWithRegion(ctx, regResp.ClientID, regResp.ClientSecret, authResp.DeviceCode, cfg.Region)
			if err != nil {
				if errors.Is(err, ErrAuthorizationPending) {
					fmt.Print(".")
					continue
				}
				if errors.Is(err, ErrSlowDown) {
					interval += 5 * time.Second
					continue
				}
				browser.CloseBrowser()
				return nil, fmt.Errorf("token creation failed: %w", err)
			}

			fmt.Println("\n\n✓ Authorization successful!")

			if err := browser.CloseBrowser(); err != nil {
				log.Debugf("Failed to close browser: %v", err)
			}

			// Step 5: Fetch profile ARN (only for non-BuilderId)
			var profileArn string
			if cfg.AuthMethod != "builder-id" {
				fmt.Println("Fetching profile information...")
				profileArn = c.FetchProfileArn(ctx, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken)
			}

			// Fetch user email
			email := FetchUserEmailWithFallback(ctx, c.cfg, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken, cfg.AuthMethod)
			if email != "" {
				fmt.Printf("  Logged in as: %s\n", email)
			}

			expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

			return &KiroTokenData{
				AccessToken:  tokenResp.AccessToken,
				RefreshToken: tokenResp.RefreshToken,
				ProfileArn:   profileArn,
				ExpiresAt:    expiresAt.Format(time.RFC3339),
				AuthMethod:   cfg.AuthMethod,
				Provider:     cfg.Provider,
				ClientID:     regResp.ClientID,
				ClientSecret: regResp.ClientSecret,
				ClientIDHash: ComputeIDCClientIDHash(cfg.StartURL),
				Email:        email,
				StartURL:     cfg.StartURL,
				Region:       cfg.Region,
			}, nil
		}
	}

	if err := browser.CloseBrowser(); err != nil {
		log.Debugf("Failed to close browser on timeout: %v", err)
	}
	return nil, fmt.Errorf("authorization timed out")
}

// LoginWithBuilderID performs the full device code flow for AWS Builder ID.
func (c *SSOOIDCClient) LoginWithBuilderID(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	return c.performDeviceCodeFlow(ctx, deviceCodeFlowConfig{
		StartURL:    builderIDStartURL,
		Region:      defaultIDCRegion,
		AuthMethod:  "builder-id",
		Provider:    "AWS",
		NoBrowser:   noBrowser,
		HeaderTitle: "Kiro Authentication (AWS Builder ID)",
	})
}

// FetchUserEmail retrieves the user's email from AWS SSO OIDC userinfo endpoint.
// Falls back to JWT parsing if userinfo fails.
func (c *SSOOIDCClient) FetchUserEmail(ctx context.Context, accessToken string) string {
	// Method 1: Try userinfo endpoint (standard OIDC)
	email := c.tryUserInfoEndpoint(ctx, accessToken)
	if email != "" {
		return email
	}

	// Method 2: Fallback to JWT parsing
	return ExtractEmailFromJWT(accessToken)
}

// tryUserInfoEndpoint attempts to get user info from AWS SSO OIDC userinfo endpoint.
func (c *SSOOIDCClient) tryUserInfoEndpoint(ctx context.Context, accessToken string) string {
	override := c.getOIDCEndpointOverride()
	userinfoURL := ssoOIDCEndpoint + "/userinfo"
	if override.UserinfoURL != "" {
		userinfoURL = override.UserinfoURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Debugf("userinfo request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := readResponseBody(resp)
		log.Debugf("userinfo endpoint returned status %d: %s", resp.StatusCode, string(respBody))
		return ""
	}

	respBody, err := readResponseBody(resp)
	if err != nil {
		return ""
	}

	log.Debugf("userinfo response: %s", string(respBody))

	var userInfo struct {
		Email             string `json:"email"`
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}

	if err := json.Unmarshal(respBody, &userInfo); err != nil {
		return ""
	}

	if userInfo.Email != "" {
		return userInfo.Email
	}
	if userInfo.PreferredUsername != "" && strings.Contains(userInfo.PreferredUsername, "@") {
		return userInfo.PreferredUsername
	}
	return ""
}

// FetchProfileArn fetches the profile ARN from ListAvailableProfiles API.
// This is used to get profileArn for imported accounts that may not have it.
func (c *SSOOIDCClient) FetchProfileArn(ctx context.Context, accessToken, clientID, refreshToken string) string {
	profileArn := c.tryListAvailableProfiles(ctx, accessToken, clientID, refreshToken)
	if profileArn != "" {
		return profileArn
	}
	return c.tryListProfilesLegacy(ctx, accessToken)
}

func (c *SSOOIDCClient) tryListAvailableProfiles(ctx context.Context, accessToken, clientID, refreshToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, GetKiroAPIEndpoint("")+"/ListAvailableProfiles", strings.NewReader("{}"))
	if err != nil {
		return ""
	}

	req.Header.Set("Content-Type", "application/json")
	accountKey := GetAccountKey(clientID, refreshToken)
	setRuntimeHeaders(req, accessToken, accountKey, "")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Debugf("ListAvailableProfiles request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	respBody, _ := readResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		log.Debugf("ListAvailableProfiles failed (status %d): %s", resp.StatusCode, string(respBody))
		return ""
	}

	log.Debugf("ListAvailableProfiles response: %s", string(respBody))

	var result struct {
		Profiles []struct {
			Arn         string `json:"arn"`
			ProfileName string `json:"profileName"`
		} `json:"profiles"`
		NextToken *string `json:"nextToken"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		log.Debugf("ListAvailableProfiles parse error: %v", err)
		return ""
	}

	if len(result.Profiles) > 0 {
		log.Debugf("Found profile: %s (%s)", result.Profiles[0].ProfileName, result.Profiles[0].Arn)
		return result.Profiles[0].Arn
	}

	return ""
}

func (c *SSOOIDCClient) tryListProfilesLegacy(ctx context.Context, accessToken string) string {
	payload := map[string]interface{}{
		"origin": "AI_EDITOR",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return ""
	}

	// Use the legacy CodeWhisperer endpoint for JSON-RPC style requests.
	// The Q endpoint (q.{region}.amazonaws.com) does NOT support x-amz-target headers.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, GetCodeWhispererLegacyEndpoint(""), bytes.NewReader(body))
	if err != nil {
		return ""
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("x-amz-target", "AmazonCodeWhispererService.ListProfiles")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	respBody, _ := readResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		log.Debugf("ListProfiles (legacy) failed (status %d): %s", resp.StatusCode, string(respBody))
		return ""
	}

	log.Debugf("ListProfiles (legacy) response: %s", string(respBody))

	var result struct {
		Profiles []struct {
			Arn string `json:"arn"`
		} `json:"profiles"`
		ProfileArn string `json:"profileArn"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return ""
	}

	if result.ProfileArn != "" {
		return result.ProfileArn
	}

	if len(result.Profiles) > 0 {
		return result.Profiles[0].Arn
	}

	return ""
}

// RegisterClientForAuthCode registers a new OIDC client for authorization code flow (default region).
func (c *SSOOIDCClient) RegisterClientForAuthCode(ctx context.Context, redirectURI string) (*RegisterClientResponse, error) {
	return c.RegisterClientForAuthCodeWithIDC(ctx, redirectURI, builderIDStartURL, defaultIDCRegion)
}

func (c *SSOOIDCClient) RegisterClientForAuthCodeWithIDC(ctx context.Context, redirectURI, issuerUrl, region string) (*RegisterClientResponse, error) {
	endpoint := c.getOIDCEndpointWithOverride(region)

	payload := map[string]interface{}{
		"clientName":   "Kiro IDE",
		"clientType":   "public",
		"scopes":       []string{"codewhisperer:completions", "codewhisperer:analysis", "codewhisperer:conversations", "codewhisperer:transformations", "codewhisperer:taskassist"},
		"grantTypes":   []string{"authorization_code", "refresh_token"},
		"redirectUris": []string{redirectURI},
		"issuerUrl":    issuerUrl,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/client/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	SetOIDCHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("register client for auth code with IDC failed (status %d): %s", resp.StatusCode, string(respBody))
		return nil, fmt.Errorf("register client failed (status %d)", resp.StatusCode)
	}

	var result RegisterClientResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// startAuthCodeCallbackServer starts a local HTTP server for the auth code callback using the shared implementation.
func (c *SSOOIDCClient) startAuthCodeCallbackServer(ctx context.Context, expectedState string) (string, <-chan callbackResult, error) {
	return startCallbackServer(ctx, expectedState, callbackServerConfig{
		// DefaultPort:  authCodeCallbackPort,
		CallbackPath: authCodeCallbackPath,
		Timeout:      10 * time.Minute,
		BindAddr:     "127.0.0.1",
	})
}

// generatePKCEForAuthCode generates PKCE for authorization code flow (delegates to shared implementation).
func generatePKCEForAuthCode() (verifier, challenge string, err error) {
	return generatePKCE()
}

// generateStateForAuthCode generates a random state for authorization code flow (delegates to shared implementation).
func generateStateForAuthCode() (string, error) {
	return generateOAuthState()
}

// CreateTokenWithAuthCode exchanges authorization code for tokens (default region).
func (c *SSOOIDCClient) CreateTokenWithAuthCode(ctx context.Context, clientID, clientSecret, code, codeVerifier, redirectURI string) (*CreateTokenResponse, error) {
	return c.CreateTokenWithAuthCodeAndRegion(ctx, clientID, clientSecret, code, codeVerifier, redirectURI, defaultIDCRegion)
}

func (c *SSOOIDCClient) CreateTokenWithAuthCodeAndRegion(ctx context.Context, clientID, clientSecret, code, codeVerifier, redirectURI, region string) (*CreateTokenResponse, error) {
	endpoint := getOIDCEndpoint(region)

	payload := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"code":         code,
		"codeVerifier": codeVerifier,
		"redirectUri":  redirectURI,
		"grantType":    "authorization_code",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/token", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	SetOIDCHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Debugf("create token with auth code failed (status %d): %s", resp.StatusCode, string(respBody))
		return nil, fmt.Errorf("create token failed (status %d)", resp.StatusCode)
	}

	var result CreateTokenResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// LoginWithBuilderIDAuthCode performs the authorization code flow for AWS Builder ID.
// This provides a better UX than device code flow as it uses automatic browser callback.
func (c *SSOOIDCClient) LoginWithBuilderIDAuthCode(ctx context.Context, noBrowser bool) (*KiroTokenData, error) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║     Kiro Authentication (AWS Builder ID - Auth Code)      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	// Step 1: Generate PKCE and state
	codeVerifier, codeChallenge, err := generatePKCEForAuthCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	state, err := generateStateForAuthCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Step 2: Start callback server
	fmt.Println("\nStarting callback server...")
	redirectURI, resultChan, err := c.startAuthCodeCallbackServer(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	log.Debugf("Callback server started, redirect URI: %s", redirectURI)

	// Step 3: Register client with auth code grant type
	fmt.Println("Registering client...")
	regResp, err := c.RegisterClientForAuthCode(ctx, redirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}
	log.Debugf("Client registered: %s", regResp.ClientID)

	// Step 4: Build authorization URL
	scopes := "codewhisperer:completions,codewhisperer:analysis,codewhisperer:conversations"
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scopes=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		ssoOIDCEndpoint,
		regResp.ClientID,
		redirectURI,
		scopes,
		state,
		codeChallenge,
	)

	// Step 5: Open browser
	fmt.Println("\n════════════════════════════════════════════════════════════")
	fmt.Println("  Opening browser for authentication...")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("\n  URL: %s\n\n", authURL)

	_ = openBrowserURL(authURL, noBrowser)

	fmt.Println("\n  Waiting for authorization callback...")

	// Step 6: Wait for callback
	select {
	case <-ctx.Done():
		browser.CloseBrowser()
		return nil, ctx.Err()
	case <-time.After(10 * time.Minute):
		browser.CloseBrowser()
		return nil, fmt.Errorf("authorization timed out")
	case result := <-resultChan:
		if result.Error != "" {
			browser.CloseBrowser()
			return nil, fmt.Errorf("authorization failed: %s", result.Error)
		}

		fmt.Println("\n✓ Authorization received!")

		// Close browser
		if err := browser.CloseBrowser(); err != nil {
			log.Debugf("Failed to close browser: %v", err)
		}

		// Step 7: Exchange code for tokens
		fmt.Println("Exchanging code for tokens...")
		tokenResp, err := c.CreateTokenWithAuthCode(ctx, regResp.ClientID, regResp.ClientSecret, result.Code, codeVerifier, redirectURI)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
		}

		fmt.Println("\n✓ Authentication successful!")

		// Fetch user email (tries CodeWhisperer API first, then userinfo endpoint, then JWT parsing)
		email := FetchUserEmailWithFallback(ctx, c.cfg, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken, "idc")
		if email != "" {
			fmt.Printf("  Logged in as: %s\n", email)
		}

		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

		return &KiroTokenData{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			ProfileArn:   "", // Builder ID has no profile
			ExpiresAt:    expiresAt.Format(time.RFC3339),
			AuthMethod:   "builder-id",
			Provider:     "AWS",
			ClientID:     regResp.ClientID,
			ClientSecret: regResp.ClientSecret,
			Email:        email,
			Region:       defaultIDCRegion,
		}, nil
	}
}

func (c *SSOOIDCClient) LoginWithIDCAuthCode(ctx context.Context, startURL, region string, noBrowser bool) (*KiroTokenData, error) {
	return c.LoginWithIDCAuthCodeProvider(ctx, startURL, region, normalizeIDCProvider("", startURL), noBrowser)
}

func (c *SSOOIDCClient) LoginWithIDCAuthCodeProvider(ctx context.Context, startURL, region, provider string, noBrowser bool, onAuthURLReady ...func(string)) (*KiroTokenData, error) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║     Kiro Authentication (AWS IDC - Auth Code)             ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	if region == "" {
		region = defaultIDCRegion
	}
	provider = normalizeIDCProvider(provider, startURL)
	startURL = resolveIDCStartURL(provider, startURL)

	codeVerifier, codeChallenge, err := generatePKCEForAuthCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	state, err := generateStateForAuthCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	fmt.Println("\nStarting callback server...")
	redirectURI, resultChan, err := c.startAuthCodeCallbackServer(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	log.Debugf("Callback server started, redirect URI: %s", redirectURI)

	fmt.Println("Registering client...")
	regResp, err := c.RegisterClientForAuthCodeWithIDC(ctx, redirectURI, startURL, region)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}
	log.Debugf("Client registered: %s", regResp.ClientID)

	endpoint := getOIDCEndpoint(region)
	scopes := "codewhisperer:completions,codewhisperer:analysis,codewhisperer:conversations,codewhisperer:transformations,codewhisperer:taskassist"
	authURL := buildAuthorizationURL(endpoint, regResp.ClientID, redirectURI, scopes, state, codeChallenge)

	fmt.Println("\n════════════════════════════════════════════════════════════")
	fmt.Println("  Opening browser for authentication...")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("\n  URL: %s\n\n", authURL)

	_ = openBrowserURL(authURL, noBrowser)

	// Notify caller of the auth URL (used by CLI flow for browser redirect).
	if len(onAuthURLReady) > 0 && onAuthURLReady[0] != nil {
		onAuthURLReady[0](authURL)
	}

	fmt.Println("\n  Waiting for authorization callback...")

	select {
	case <-ctx.Done():
		browser.CloseBrowser()
		return nil, ctx.Err()
	case <-time.After(10 * time.Minute):
		browser.CloseBrowser()
		return nil, fmt.Errorf("authorization timed out")
	case result := <-resultChan:
		if result.Error != "" {
			browser.CloseBrowser()
			return nil, fmt.Errorf("authorization failed: %s", result.Error)
		}

		fmt.Println("\n✓ Authorization received!")

		if err := browser.CloseBrowser(); err != nil {
			log.Debugf("Failed to close browser: %v", err)
		}

		fmt.Println("Exchanging code for tokens...")
		tokenResp, err := c.CreateTokenWithAuthCodeAndRegion(ctx, regResp.ClientID, regResp.ClientSecret, result.Code, codeVerifier, redirectURI, region)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
		}

		fmt.Println("\n✓ Authentication successful!")

		var profileArn string
		if provider != "BuilderId" {
			fmt.Println("Fetching profile information...")
			profileArn = c.FetchProfileArn(ctx, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken)
		}

		email := FetchUserEmailWithFallback(ctx, c.cfg, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken, "idc")
		if email != "" {
			fmt.Printf("  Logged in as: %s\n", email)
		}

		expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

		return &KiroTokenData{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			ProfileArn:   profileArn,
			ExpiresAt:    expiresAt.Format(time.RFC3339),
			AuthMethod:   "idc",
			Provider:     provider,
			ClientID:     regResp.ClientID,
			ClientSecret: regResp.ClientSecret,
			ClientIDHash: ComputeIDCClientIDHash(startURL),
			Email:        email,
			StartURL:     startURL,
			Region:       region,
		}, nil
	}
}

func buildAuthorizationURL(endpoint, clientID, redirectURI, scopes, state, codeChallenge string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scopes", scopes)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	return fmt.Sprintf("%s/authorize?%s", endpoint, params.Encode())
}

func normalizeIDCProvider(provider, startURL string) string {
	provider = strings.TrimSpace(provider)
	switch {
	case strings.EqualFold(provider, "BuilderId"), strings.EqualFold(provider, "builder-id"), strings.EqualFold(provider, "builder_id"):
		return "BuilderId"
	case strings.EqualFold(provider, "Enterprise"), strings.EqualFold(provider, "idc"):
		return "Enterprise"
	case strings.TrimSpace(startURL) == "" || strings.TrimSpace(startURL) == builderIDStartURL:
		return "BuilderId"
	default:
		return "Enterprise"
	}
}

func resolveIDCStartURL(provider, startURL string) string {
	startURL = strings.TrimSpace(startURL)
	if startURL != "" {
		return startURL
	}
	if strings.EqualFold(provider, "Enterprise") {
		return enterpriseStartURL
	}
	return builderIDStartURL
}

func ComputeIDCClientIDHash(startURL string) string {
	normalizedURL := strings.TrimSpace(startURL)
	normalizedURL = strings.TrimRight(normalizedURL, "/")
	payload, err := json.Marshal(map[string]string{"startUrl": normalizedURL})
	if err != nil {
		return ""
	}
	sum := sha1.Sum(payload)
	return hex.EncodeToString(sum[:])
}
