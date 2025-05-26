// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// Package providers imports all available DNS providers
package providers

import (
	"dns-companion/pkg/dns/providers/cloudflare"
	hosts "dns-companion/pkg/dns/providers/hosts"
)

// RegisterProviders registers all DNS providers
func RegisterProviders() {
	// Register all available providers
	cloudflare.Register()
	hosts.Register()
}

// RegisterAllProviders registers all DNS providers
func RegisterAllProviders() {
	hosts.Register()
	// Register other providers here as needed
}

// Import the provider packages here to ensure they're included in the build
// But register them explicitly through RegisterProviders()
