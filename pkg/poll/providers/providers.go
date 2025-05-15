// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3

// Package providers imports all poll provider implementations
package providers

import (
	_ "container-dns-companion/pkg/poll/providers/docker"  // Register Docker provider
	_ "container-dns-companion/pkg/poll/providers/traefik" // Register Traefik provider
)
