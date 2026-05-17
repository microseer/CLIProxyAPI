package cmd

import (
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	log "github.com/sirupsen/logrus"
)

// DoKiroCLILogin triggers the native Kiro CLI OAuth flow and saves the resulting token.
// This uses Kiro's own OAuth endpoints with the Kiro CLI User-Agent for fingerprinting.
//
// Parameters:
//   - cfg: The application configuration
//   - options: Login options including NoBrowser flag
func DoKiroCLILogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	manager := newAuthManager()
	authenticator := sdkAuth.NewKiroAuthenticator()
	record, err := authenticator.LoginWithCLI(context.Background(), cfg, &sdkAuth.LoginOptions{
		NoBrowser: options.NoBrowser,
		Metadata:  map[string]string{},
		Prompt:    options.Prompt,
	})
	if err != nil {
		log.Errorf("Kiro CLI authentication failed: %v", err)
		fmt.Println("\nTroubleshooting:")
		fmt.Println("1. Complete the browser login flow")
		fmt.Println("2. Ensure callback port 3128 is available")
		fmt.Println("3. If callback fails, try logging in via Kiro IDE and importing the token")
		return
	}

	savedPath, err := manager.SaveAuth(record, cfg)
	if err != nil {
		log.Errorf("Failed to save auth: %v", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	if record != nil && record.Label != "" {
		fmt.Printf("Authenticated as %s\n", record.Label)
	}
	fmt.Println("Kiro CLI authentication successful!")
}
