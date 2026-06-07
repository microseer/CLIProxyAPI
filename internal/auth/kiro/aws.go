// Package kiro provides authentication functionality for AWS CodeWhisperer (Kiro) API.
// It includes interfaces and implementations for token storage and authentication methods.
package kiro

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// PKCECodes holds PKCE verification codes for OAuth2 PKCE flow
type PKCECodes struct {
	// CodeVerifier is the cryptographically random string used to correlate
	// the authorization request to the token request
	CodeVerifier string `json:"code_verifier"`
	// CodeChallenge is the SHA256 hash of the code verifier, base64url-encoded
	CodeChallenge string `json:"code_challenge"`
}

// KiroTokenData holds OAuth token information from AWS CodeWhisperer (Kiro)
type KiroTokenData struct {
	// AccessToken is the OAuth2 access token for API access
	AccessToken string `json:"accessToken"`
	// RefreshToken is used to obtain new access tokens
	RefreshToken string `json:"refreshToken"`
	// ProfileArn is the AWS CodeWhisperer profile ARN
	ProfileArn string `json:"profileArn"`
	// ExpiresAt is the timestamp when the token expires
	ExpiresAt string `json:"expiresAt"`
	// AuthMethod indicates the authentication method used (e.g., "builder-id", "social", "idc")
	AuthMethod string `json:"authMethod"`
	// Provider indicates the OAuth provider (e.g., "AWS", "Google", "Enterprise")
	Provider string `json:"provider"`
	// ClientID is the OIDC client ID (needed for token refresh)
	ClientID string `json:"clientId,omitempty"`
	// ClientSecret is the OIDC client secret (needed for token refresh)
	ClientSecret string `json:"clientSecret,omitempty"`
	// ClientIDHash is the hash of client ID used to locate device registration file
	// (Enterprise Kiro IDE stores clientId/clientSecret in ~/.aws/sso/cache/{clientIdHash}.json)
	ClientIDHash string `json:"clientIdHash,omitempty"`
	// Email is the user's email address (used for file naming)
	Email string `json:"email,omitempty"`
	// StartURL is the IDC/Identity Center start URL (only for IDC auth method)
	StartURL string `json:"startUrl,omitempty"`
	// Region is the OIDC region for IDC login and token refresh
	Region string `json:"region,omitempty"`
}

// KiroAuthBundle aggregates authentication data after OAuth flow completion
type KiroAuthBundle struct {
	// TokenData contains the OAuth tokens from the authentication flow
	TokenData KiroTokenData `json:"token_data"`
	// LastRefresh is the timestamp of the last token refresh
	LastRefresh string `json:"last_refresh"`
}

// KiroUsageInfo represents usage information from CodeWhisperer API
type KiroUsageInfo struct {
	// SubscriptionTitle is the subscription plan name (e.g., "KIRO FREE")
	SubscriptionTitle string `json:"subscription_title"`
	// CurrentUsage is the current credit usage
	CurrentUsage float64 `json:"current_usage"`
	// UsageLimit is the maximum credit limit
	UsageLimit float64 `json:"usage_limit"`
	// NextReset is the timestamp of the next usage reset
	NextReset string `json:"next_reset"`
}

// KiroModel represents a model available through the CodeWhisperer API
type KiroModel struct {
	// ModelID is the unique identifier for the model
	ModelID string `json:"modelId"`
	// ModelName is the human-readable name
	ModelName string `json:"modelName"`
	// Description is the model description
	Description string `json:"description"`
	// RateMultiplier is the credit multiplier for this model
	RateMultiplier float64 `json:"rateMultiplier"`
	// RateUnit is the unit for rate calculation (e.g., "credit")
	RateUnit string `json:"rateUnit"`
	// MaxInputTokens is the maximum input token limit
	MaxInputTokens int `json:"maxInputTokens,omitempty"`
}

// KiroIDETokenFile is the default path to Kiro IDE's token file
const KiroIDETokenFile = ".aws/sso/cache/kiro-auth-token.json"

// Default retry configuration for file reading
const (
	defaultTokenReadMaxAttempts = 10                    // Maximum retry attempts
	defaultTokenReadBaseDelay   = 50 * time.Millisecond // Base delay between retries
)

// JWTClaims represents the claims we care about from a JWT token.
// JWT tokens from Kiro/AWS contain user information in the payload.
type JWTClaims struct {
	Email         string `json:"email,omitempty"`
	Sub           string `json:"sub,omitempty"`
	PreferredUser string `json:"preferred_username,omitempty"`
	Name          string `json:"name,omitempty"`
	Iss           string `json:"iss,omitempty"`
}

// ExtractEmailFromJWT extracts the user's email from a JWT access token.
// JWT tokens typically have format: header.payload.signature
// The payload is base64url-encoded JSON containing user claims.
func ExtractEmailFromJWT(accessToken string) string {
	if accessToken == "" {
		return ""
	}

	// JWT format: header.payload.signature
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return ""
	}

	// Decode the payload (second part)
	payload := parts[1]

	// Add padding if needed (base64url requires padding)
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try RawURLEncoding (no padding)
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}

	var claims JWTClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}

	// Return email if available
	if claims.Email != "" {
		return claims.Email
	}

	// Fallback to preferred_username (some providers use this)
	if claims.PreferredUser != "" && strings.Contains(claims.PreferredUser, "@") {
		return claims.PreferredUser
	}

	// Fallback to sub if it looks like an email
	if claims.Sub != "" && strings.Contains(claims.Sub, "@") {
		return claims.Sub
	}

	return ""
}

// SanitizeEmailForFilename sanitizes an email address for use in a filename.
// Replaces special characters with underscores and prevents path traversal attacks.
// Also handles URL-encoded characters to prevent encoded path traversal attempts.
func SanitizeEmailForFilename(email string) string {
	if email == "" {
		return ""
	}

	result := email

	// First, handle URL-encoded path traversal attempts (%2F, %2E, %5C, etc.)
	// This prevents encoded characters from bypassing the sanitization.
	// Note: We replace % last to catch any remaining encodings including double-encoding (%252F)
	result = strings.ReplaceAll(result, "%2F", "_") // /
	result = strings.ReplaceAll(result, "%2f", "_")
	result = strings.ReplaceAll(result, "%5C", "_") // \
	result = strings.ReplaceAll(result, "%5c", "_")
	result = strings.ReplaceAll(result, "%2E", "_") // .
	result = strings.ReplaceAll(result, "%2e", "_")
	result = strings.ReplaceAll(result, "%00", "_") // null byte
	result = strings.ReplaceAll(result, "%", "_")   // Catch remaining % to prevent double-encoding attacks

	// Replace characters that are problematic in filenames
	// Keep @ and . in middle but replace other special characters
	for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " ", "\x00"} {
		result = strings.ReplaceAll(result, char, "_")
	}

	// Prevent path traversal: replace leading dots in each path component
	// This handles cases like "../../../etc/passwd" → "_.._.._.._etc_passwd"
	parts := strings.Split(result, "_")
	for i, part := range parts {
		for strings.HasPrefix(part, ".") {
			part = "_" + part[1:]
		}
		parts[i] = part
	}
	result = strings.Join(parts, "_")

	return result
}

// ExtractIDCIdentifier extracts a unique identifier from IDC startUrl.
// Examples:
//   - "https://d-1234567890.awsapps.com/start" -> "d-1234567890"
//   - "https://my-company.awsapps.com/start" -> "my-company"
//   - "https://acme-corp.awsapps.com/start" -> "acme-corp"
func ExtractIDCIdentifier(startURL string) string {
	if startURL == "" {
		return ""
	}

	// Remove protocol prefix
	url := strings.TrimPrefix(startURL, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Extract subdomain (first part before the first dot)
	// Format: {identifier}.awsapps.com/start
	parts := strings.Split(url, ".")
	if len(parts) > 0 && parts[0] != "" {
		identifier := parts[0]
		// Sanitize for filename safety
		identifier = strings.ReplaceAll(identifier, "/", "_")
		identifier = strings.ReplaceAll(identifier, "\\", "_")
		identifier = strings.ReplaceAll(identifier, ":", "_")
		return identifier
	}

	return ""
}

// GenerateTokenFileName generates a unique filename for token storage.
// Priority: email > startUrl identifier (for IDC) > authMethod only
// Email is unique, so no sequence suffix needed. Sequence is only added
// when email is unavailable to prevent filename collisions.
// Format: kiro-{authMethod}-{identifier}[-{seq}].json
func GenerateTokenFileName(tokenData *KiroTokenData) string {
	authMethod := tokenData.AuthMethod
	if authMethod == "" {
		authMethod = "unknown"
	}

	// Priority 1: Use email if available (no sequence needed, email is unique)
	if tokenData.Email != "" {
		// Sanitize email for filename (replace @ and . with -)
		sanitizedEmail := tokenData.Email
		sanitizedEmail = strings.ReplaceAll(sanitizedEmail, "@", "-")
		sanitizedEmail = strings.ReplaceAll(sanitizedEmail, ".", "-")
		return fmt.Sprintf("kiro-%s-%s.json", authMethod, sanitizedEmail)
	}

	// Generate sequence only when email is unavailable
	seq := time.Now().UnixNano() % 100000

	// Priority 2: For IDC, use startUrl identifier with sequence
	if authMethod == "idc" && tokenData.StartURL != "" {
		identifier := ExtractIDCIdentifier(tokenData.StartURL)
		if identifier != "" {
			return fmt.Sprintf("kiro-%s-%s-%05d.json", authMethod, identifier, seq)
		}
	}

	// Priority 3: Fallback to authMethod only with sequence
	return fmt.Sprintf("kiro-%s-%05d.json", authMethod, seq)
}

// DefaultKiroRegion is the fallback region when none is specified.
const DefaultKiroRegion = "us-east-1"

const (
	KiroOriginAIEditor = "AI_EDITOR"
	KiroOriginCLI      = "KIRO_CLI"
)

func IsKiroCLIAuthMethod(authMethod string) bool {
	return strings.EqualFold(strings.TrimSpace(authMethod), "kiro-cli")
}

func OriginForAuthMethod(authMethod string) string {
	if IsKiroCLIAuthMethod(authMethod) {
		return KiroOriginCLI
	}
	return KiroOriginAIEditor
}

// GetCodeWhispererLegacyEndpoint returns the legacy CodeWhisperer JSON-RPC endpoint.
// This endpoint supports JSON-RPC style requests with x-amz-target headers.
// The Q endpoint (q.{region}.amazonaws.com) does NOT support JSON-RPC style.
func GetCodeWhispererLegacyEndpoint(region string) string {
	if region == "" {
		region = DefaultKiroRegion
	}
	return "https://codewhisperer." + region + ".amazonaws.com"
}

// ProfileARN represents a parsed AWS CodeWhisperer profile ARN.
// ARN format: arn:partition:service:region:account-id:resource-type/resource-id
// Example: arn:aws:codewhisperer:us-east-1:123456789012:profile/ABCDEFGHIJKL
type ProfileARN struct {
	// Raw is the original ARN string
	Raw string
	// Partition is the AWS partition (aws)
	Partition string
	// Service is the AWS service name (codewhisperer)
	Service string
	// Region is the AWS region (us-east-1, ap-southeast-1, etc.)
	Region string
	// AccountID is the AWS account ID
	AccountID string
	// ResourceType is the resource type (profile)
	ResourceType string
	// ResourceID is the resource identifier (e.g., ABCDEFGHIJKL)
	ResourceID string
}

// ParseProfileARN parses an AWS ARN string into a ProfileARN struct.
// Returns nil if the ARN is empty, invalid, or not a codewhisperer ARN.
func ParseProfileARN(arn string) *ProfileARN {
	if arn == "" {
		return nil
	}
	// ARN format: arn:partition:service:region:account-id:resource
	// Minimum 6 parts separated by ":"
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		log.Warnf("invalid ARN format: %s", arn)
		return nil
	}
	// Validate ARN prefix
	if parts[0] != "arn" {
		return nil
	}
	// Validate partition
	partition := parts[1]
	if partition == "" {
		return nil
	}
	// Validate service is codewhisperer
	service := parts[2]
	if service != "codewhisperer" {
		return nil
	}
	// Validate region format (must contain "-")
	region := parts[3]
	if region == "" || !strings.Contains(region, "-") {
		return nil
	}
	// Account ID
	accountID := parts[4]

	// Parse resource (format: resource-type/resource-id)
	// Join remaining parts in case resource contains ":"
	resource := strings.Join(parts[5:], ":")
	resourceType := ""
	resourceID := ""
	if idx := strings.Index(resource, "/"); idx > 0 {
		resourceType = resource[:idx]
		resourceID = resource[idx+1:]
	} else {
		resourceType = resource
	}

	return &ProfileARN{
		Raw:          arn,
		Partition:    partition,
		Service:      service,
		Region:       region,
		AccountID:    accountID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}

// GetKiroAPIEndpoint returns the Q API endpoint for the specified region.
// If region is empty, defaults to us-east-1.
func GetKiroAPIEndpoint(region string) string {
	if region == "" {
		region = DefaultKiroRegion
	}
	return "https://q." + region + ".amazonaws.com"
}

// GetKiroAPIEndpointFromProfileArn extracts region from profileArn and returns the endpoint.
// Returns default us-east-1 endpoint if region cannot be extracted.
func GetKiroAPIEndpointFromProfileArn(profileArn string) string {
	region := ExtractRegionFromProfileArn(profileArn)
	return GetKiroAPIEndpoint(region)
}

// ExtractRegionFromProfileArn extracts the AWS region from a ProfileARN string.
// Returns empty string if ARN is invalid or region cannot be extracted.
func ExtractRegionFromProfileArn(profileArn string) string {
	parsed := ParseProfileARN(profileArn)
	if parsed == nil {
		return ""
	}
	return parsed.Region
}

// ExtractRegionFromMetadata extracts API region from auth metadata.
// Priority: api_region > profile_arn > DefaultKiroRegion
func ExtractRegionFromMetadata(metadata map[string]interface{}) string {
	if metadata == nil {
		return DefaultKiroRegion
	}

	// Priority 1: Explicit api_region override
	if r, ok := metadata["api_region"].(string); ok && r != "" {
		return r
	}

	// Priority 2: Extract from ProfileARN
	if profileArn, ok := metadata["profile_arn"].(string); ok && profileArn != "" {
		if region := ExtractRegionFromProfileArn(profileArn); region != "" {
			return region
		}
	}

	return DefaultKiroRegion
}

func buildURL(endpoint, path string, queryParams map[string]string) string {
	fullURL := fmt.Sprintf("%s/%s", endpoint, path)
	if len(queryParams) > 0 {
		values := url.Values{}
		for key, value := range queryParams {
			if value == "" {
				continue
			}
			values.Set(key, value)
		}
		if encoded := values.Encode(); encoded != "" {
			fullURL = fullURL + "?" + encoded
		}
	}
	return fullURL
}
