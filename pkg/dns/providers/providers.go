// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3

// Package providers imports all available DNS providers
package providers

import (
	"container-dns-companion/pkg/dns/providers/cloudflare"
	"container-dns-companion/pkg/dns/providers/route53"
)

// RegisterProviders registers all DNS providers
func RegisterProviders() {
	// Register all available providers
	cloudflare.Register()
	route53.Register()
}

// Import the provider packages here to ensure they're included in the build
// But register them explicitly through RegisterProviders()
