// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// Package providers imports all available DNS providers
package providers

import (
	"dns-companion/pkg/dns/providers/cloudflare"
	"dns-companion/pkg/log"

	"fmt"
)

// ProviderInfo contains metadata about a DNS provider
type ProviderInfo struct {
	Name           string
	Description    string
	Capabilities   []string
	RequiredFields []string
}

// GetProviderInfo returns metadata about available DNS providers
func GetProviderInfo() map[string]ProviderInfo {
	return map[string]ProviderInfo{
		"cloudflare": {
			Name:           "cloudflare",
			Description:    "Cloudflare DNS provider",
			Capabilities:   []string{"A", "AAAA", "CNAME", "TXT"},
			RequiredFields: []string{"api_token", "zone_id"},
		},
		// Add other providers here as they're implemented
	}
}

// ValidateProviderExists checks if a DNS provider is available
func ValidateProviderExists(providerName string) error {
	providers := GetProviderInfo()
	if _, exists := providers[providerName]; !exists {
		available := make([]string, 0, len(providers))
		for name := range providers {
			available = append(available, name)
		}
		return fmt.Errorf("unknown DNS provider '%s'. Available providers: %v", providerName, available)
	}
	return nil
}

// RegisterProviders registers all DNS providers
func RegisterProviders() {
	log.Debug("[dns/providers] Registering DNS providers")

	// Register all available providers
	cloudflare.Register()

	log.Debug("[dns/providers] DNS provider registration complete")
}

// RegisterAllProviders registers all DNS providers (alias for RegisterProviders)
func RegisterAllProviders() {
	RegisterProviders()
}
