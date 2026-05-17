package config

import "strings"

// OAuthEndpointConfig holds optional endpoint URL overrides for OAuth providers.
// Empty fields fall back to the provider's built-in defaults.
type OAuthEndpointConfig struct {
	ApiBaseURL         string `yaml:"api-base-url,omitempty" json:"api-base-url,omitempty"`
	AuthorizeURL       string `yaml:"authorize-url,omitempty" json:"authorize-url,omitempty"`
	TokenURL           string `yaml:"token-url,omitempty" json:"token-url,omitempty"`
	RefreshURL         string `yaml:"refresh-url,omitempty" json:"refresh-url,omitempty"`
	UserinfoURL        string `yaml:"userinfo-url,omitempty" json:"userinfo-url,omitempty"`
	DeviceAuthorizeURL string `yaml:"device-authorize-url,omitempty" json:"device-authorize-url,omitempty"`
}

// ApplyDefaults returns a copy of c with any empty fields filled from defaults.
func (c *OAuthEndpointConfig) ApplyDefaults(defaults OAuthEndpointConfig) OAuthEndpointConfig {
	result := *c
	if result.ApiBaseURL == "" {
		result.ApiBaseURL = defaults.ApiBaseURL
	}
	if result.AuthorizeURL == "" {
		result.AuthorizeURL = defaults.AuthorizeURL
	}
	if result.TokenURL == "" {
		result.TokenURL = defaults.TokenURL
	}
	if result.RefreshURL == "" {
		result.RefreshURL = defaults.RefreshURL
	}
	if result.UserinfoURL == "" {
		result.UserinfoURL = defaults.UserinfoURL
	}
	if result.DeviceAuthorizeURL == "" {
		result.DeviceAuthorizeURL = defaults.DeviceAuthorizeURL
	}
	return result
}

// KiroFingerprintConfig defines a fixed fingerprint for Kiro requests.
// When configured, all Kiro requests use this fingerprint instead of random generation.
// Empty fields fall back to random selection from built-in pools.
type KiroFingerprintConfig struct {
	OIDCSDKVersion      string `yaml:"oidc-sdk-version,omitempty" json:"oidc-sdk-version,omitempty"`
	RuntimeSDKVersion   string `yaml:"runtime-sdk-version,omitempty" json:"runtime-sdk-version,omitempty"`
	StreamingSDKVersion string `yaml:"streaming-sdk-version,omitempty" json:"streaming-sdk-version,omitempty"`
	OSType              string `yaml:"os-type,omitempty" json:"os-type,omitempty"`
	OSVersion           string `yaml:"os-version,omitempty" json:"os-version,omitempty"`
	NodeVersion         string `yaml:"node-version,omitempty" json:"node-version,omitempty"`
	KiroVersion         string `yaml:"kiro-version,omitempty" json:"kiro-version,omitempty"`
	KiroHash            string `yaml:"kiro-hash,omitempty" json:"kiro-hash,omitempty"`
}

// GetOAuthEndpointOverride returns any endpoint override configured for the given provider.
// Returns an empty OAuthEndpointConfig if no override is set.
func (cfg *Config) GetOAuthEndpointOverride(provider string) OAuthEndpointConfig {
	if cfg == nil {
		return OAuthEndpointConfig{}
	}
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	if cfg.OAuthEndpointOverrides != nil {
		if ep, ok := cfg.OAuthEndpointOverrides[normalizedProvider]; ok {
			return ep
		}
	}
	return OAuthEndpointConfig{}
}

// NormalizeOAuthEndpointOverrides normalizes provider keys and trims whitespace from URLs.
func (cfg *Config) NormalizeOAuthEndpointOverrides() {
	if cfg == nil || len(cfg.OAuthEndpointOverrides) == 0 {
		return
	}
	normalized := make(map[string]OAuthEndpointConfig, len(cfg.OAuthEndpointOverrides))
	for provider, ep := range cfg.OAuthEndpointOverrides {
		normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
		if normalizedProvider == "" {
			continue
		}
		ep.ApiBaseURL = strings.TrimSpace(ep.ApiBaseURL)
		ep.AuthorizeURL = strings.TrimSpace(ep.AuthorizeURL)
		ep.TokenURL = strings.TrimSpace(ep.TokenURL)
		ep.RefreshURL = strings.TrimSpace(ep.RefreshURL)
		ep.UserinfoURL = strings.TrimSpace(ep.UserinfoURL)
		ep.DeviceAuthorizeURL = strings.TrimSpace(ep.DeviceAuthorizeURL)
		normalized[normalizedProvider] = ep
	}
	cfg.OAuthEndpointOverrides = normalized
}
