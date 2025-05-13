// Package providers imports all poll provider implementations
package providers

import (
	// Import all provider implementations so they are registered
	_ "container-dns-companion/pkg/poll/providers/docker"  // Register Docker provider
	_ "container-dns-companion/pkg/poll/providers/traefik" // Register Traefik provider
)

// This file imports all provider packages so they can self-register
// No need to call Register() functions manually
