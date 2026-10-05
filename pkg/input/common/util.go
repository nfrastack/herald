// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"encoding/json"
	"fmt"
	"herald/pkg/config"
	"herald/pkg/util"
	"strings"
)

// BuildLogPrefix returns a standardized log prefix for poll providers
func BuildLogPrefix(providerType, profileName string) string {
	if profileName == "" {
		return fmt.Sprintf("[input/%s]", providerType)
	}
	return fmt.Sprintf("[input/%s/%s]", providerType, profileName)
}

// ReadFileValue reads a value from a file if it starts with "file://",
// reads from environment variable if it starts with "env://",
// otherwise returns the original value
func ReadFileValue(value string) string {
	return util.ReadSecretValue(value)
}

// ParseDomainList parses a domain list option into a deduplicated slice.
func ParseDomainList(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}

	// JSON array first (handles ["a", "b"]).
	if strings.HasPrefix(trimmed, "[") {
		var arr []string
		if err := json.Unmarshal([]byte(trimmed), &arr); err == nil {
			return dedupeDomains(arr)
		}
		// Fall through to manual parsing for Go style [a b] / [a, b].
		trimmed = strings.TrimPrefix(strings.TrimSuffix(trimmed, "]"), "[")
	}

	// Split on commas and whitespace.
	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	return dedupeDomains(parts)
}

func dedupeDomains(domains []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, d := range domains {
		d = strings.TrimSpace(strings.Trim(d, `"'`))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ExtractDomainAndSubdomain extracts domain config key and subdomain from a hostname
// It matches the hostname against configured domains and returns the config key
func ExtractDomainAndSubdomain(hostname string) (domainKey, subdomain string) {
	if hostname == "" {
		return "", ""
	}

	// Remove trailing dot if present
	hostname = strings.TrimSuffix(hostname, ".")

	// Split into parts
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		// Not enough parts to have a domain, return as-is
		return hostname, ""
	}

	// For a hostname like "api.example.com":
	// - We need to find which domain config matches "example.com"
	// - And return the config key (e.g., "example_com_cf") plus subdomain "api"

	// Try different combinations starting from the most specific
	for i := 0; i < len(parts)-1; i++ {
		potentialDomain := strings.Join(parts[i:], ".")
		potentialSubdomain := ""
		if i > 0 {
			potentialSubdomain = strings.Join(parts[:i], ".")
		}

		// Look for a domain config that matches this domain name
		if configKey := findDomainConfigKey(potentialDomain); configKey != "" {
			return configKey, potentialSubdomain
		}
	}

	// If no match found, return the full hostname and empty subdomain
	return hostname, ""
}

// findDomainConfigKey finds the domain config key for a given domain name
func findDomainConfigKey(domainName string) string {
	if config.GlobalConfig.Domains == nil {
		return ""
	}

	// Look through all domain configs to find one with matching name
	for configKey, domainConfig := range config.GlobalConfig.Domains {
		if domainConfig.Name == domainName {
			return configKey
		}
	}

	return ""
}
