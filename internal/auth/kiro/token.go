package kiro

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// KiroTokenStorage holds the persistent token data for Kiro authentication.
type KiroTokenStorage struct {
	// Type is the provider type for management UI recognition (must be "kiro")
	Type string `json:"type"`
	// LastRefresh is the timestamp of the last token refresh
	LastRefresh string `json:"last_refresh"`
	// KiroTokenData holds the core token data (embedded for reduced duplication)
	*KiroTokenData
}

// SaveTokenToFile persists the token storage to the specified file path.
func (s *KiroTokenStorage) SaveTokenToFile(authFilePath string) error {
	dir := filepath.Dir(authFilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token storage: %w", err)
	}

	if err := os.WriteFile(authFilePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// ToTokenData returns the embedded KiroTokenData.
func (s *KiroTokenStorage) ToTokenData() *KiroTokenData {
	if s.KiroTokenData == nil {
		return &KiroTokenData{}
	}
	return s.KiroTokenData
}
