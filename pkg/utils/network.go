// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"dns-companion/pkg/log"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// ResolveListenAddresses resolves listen patterns to actual IP addresses
func ResolveListenAddresses(patterns []string, port string) ([]string, error) {
	if len(patterns) == 0 {
		// Default to all interfaces
		return []string{":" + port}, nil
	}

	var addresses []string
	var includedInterfaces []string
	var excludedInterfaces []string

	// Separate inclusion and exclusion patterns
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "!") {
			excludedInterfaces = append(excludedInterfaces, strings.TrimPrefix(pattern, "!"))
		} else {
			includedInterfaces = append(includedInterfaces, pattern)
		}
	}

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// If no inclusion patterns, start with all interfaces
	if len(includedInterfaces) == 0 {
		for _, iface := range interfaces {
			if shouldIncludeInterface(iface.Name, []string{"*"}, excludedInterfaces) {
				addrs := getInterfaceAddresses(iface)
				for _, addr := range addrs {
					addresses = append(addresses, addr+":"+port)
				}
			}
		}
	} else {
		// Process inclusion patterns
		for _, pattern := range includedInterfaces {
			// Check if it's already an IP address
			if ip := net.ParseIP(pattern); ip != nil {
				addresses = append(addresses, pattern+":"+port)
				log.Debug("[network] Added explicit IP address: %s:%s", pattern, port)
				continue
			}

			// Check if it's a special keyword
			if pattern == "all" || pattern == "*" {
				for _, iface := range interfaces {
					if shouldIncludeInterface(iface.Name, []string{"*"}, excludedInterfaces) {
						addrs := getInterfaceAddresses(iface)
						for _, addr := range addrs {
							addresses = append(addresses, addr+":"+port)
						}
					}
				}
				continue
			}

			// Pattern matching for interface names
			for _, iface := range interfaces {
				if shouldIncludeInterface(iface.Name, []string{pattern}, excludedInterfaces) {
					addrs := getInterfaceAddresses(iface)
					for _, addr := range addrs {
						addresses = append(addresses, addr+":"+port)
						log.Debug("[network] Added interface %s (%s:%s)", iface.Name, addr, port)
					}
				}
			}
		}
	}

	// Remove duplicates
	addresses = removeDuplicateAddresses(addresses)

	if len(addresses) == 0 {
		return []string{":" + port}, fmt.Errorf("no matching interfaces found for patterns %v, falling back to all interfaces", patterns)
	}

	log.Info("[network] Resolved %d listen addresses from patterns %v", len(addresses), patterns)
	for _, addr := range addresses {
		log.Debug("[network] Will listen on: %s", addr)
	}

	return addresses, nil
}

// ResolveListenAddressesQuiet resolves listen patterns without logging (for when caller will log)
func ResolveListenAddressesQuiet(patterns []string, port string) ([]string, error) {
	if len(patterns) == 0 {
		// Default to all interfaces
		return []string{":" + port}, nil
	}

	var addresses []string
	var includedInterfaces []string
	var excludedInterfaces []string

	// Separate inclusion and exclusion patterns
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "!") {
			excludedInterfaces = append(excludedInterfaces, strings.TrimPrefix(pattern, "!"))
		} else {
			includedInterfaces = append(includedInterfaces, pattern)
		}
	}

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// If no inclusion patterns, start with all interfaces
	if len(includedInterfaces) == 0 {
		for _, iface := range interfaces {
			if shouldIncludeInterface(iface.Name, []string{"*"}, excludedInterfaces) {
				addrs := getInterfaceAddresses(iface)
				for _, addr := range addrs {
					addresses = append(addresses, addr+":"+port)
				}
			}
		}
	} else {
		// Process inclusion patterns
		for _, pattern := range includedInterfaces {
			// Check if it's already an IP address
			if ip := net.ParseIP(pattern); ip != nil {
				addresses = append(addresses, pattern+":"+port)
				continue
			}

			// Check if it's a special keyword
			if pattern == "all" || pattern == "*" {
				for _, iface := range interfaces {
					if shouldIncludeInterface(iface.Name, []string{"*"}, excludedInterfaces) {
						addrs := getInterfaceAddresses(iface)
						for _, addr := range addrs {
							addresses = append(addresses, addr+":"+port)
						}
					}
				}
				continue
			}

			// Pattern matching for interface names
			for _, iface := range interfaces {
				if shouldIncludeInterface(iface.Name, []string{pattern}, excludedInterfaces) {
					addrs := getInterfaceAddresses(iface)
					for _, addr := range addrs {
						addresses = append(addresses, addr+":"+port)
					}
				}
			}
		}
	}

	// Remove duplicates
	addresses = removeDuplicateAddresses(addresses)

	if len(addresses) == 0 {
		return []string{":" + port}, fmt.Errorf("no matching interfaces found for patterns %v, falling back to all interfaces", patterns)
	}

	// No logging in quiet version - caller will handle logging
	return addresses, nil
}

// shouldIncludeInterface determines if an interface should be included based on patterns
func shouldIncludeInterface(interfaceName string, includePatterns, excludePatterns []string) bool {
	// Check exclusion patterns first
	for _, pattern := range excludePatterns {
		if matchesPattern(interfaceName, pattern) {
			log.Trace("[network] Interface %s excluded by pattern !%s", interfaceName, pattern)
			return false
		}
	}

	// Check inclusion patterns
	for _, pattern := range includePatterns {
		if matchesPattern(interfaceName, pattern) {
			log.Trace("[network] Interface %s included by pattern %s", interfaceName, pattern)
			return true
		}
	}

	return false
}

// matchesPattern checks if a string matches a wildcard pattern
func matchesPattern(str, pattern string) bool {
	if pattern == "*" {
		return true
	}

	// Use filepath.Match for glob-style pattern matching
	matched, err := filepath.Match(pattern, str)
	if err != nil {
		log.Warn("[network] Invalid pattern '%s': %v", pattern, err)
		return false
	}

	return matched
}

// getInterfaceAddresses gets all IPv4 addresses for an interface
func getInterfaceAddresses(iface net.Interface) []string {
	var addresses []string

	// Skip interfaces that are down or loopback (unless explicitly requested)
	if iface.Flags&net.FlagUp == 0 {
		log.Trace("[network] Skipping interface %s (down)", iface.Name)
		return addresses
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Warn("[network] Failed to get addresses for interface %s: %v", iface.Name, err)
		return addresses
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			// Only include IPv4 addresses for now
			if ip := ipNet.IP.To4(); ip != nil {
				addresses = append(addresses, ip.String())
				log.Trace("[network] Found IPv4 address %s on interface %s", ip.String(), iface.Name)
			}
		}
	}

	return addresses
}

// removeDuplicateAddresses removes duplicate addresses from the slice
func removeDuplicateAddresses(addresses []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, addr := range addresses {
		if !seen[addr] {
			seen[addr] = true
			unique = append(unique, addr)
		}
	}

	return unique
}

// ValidateListenPatterns validates listen patterns before using them
func ValidateListenPatterns(patterns []string) error {
	for _, pattern := range patterns {
		// Remove negation prefix for validation
		cleanPattern := strings.TrimPrefix(pattern, "!")

		// Check if it's an IP address
		if ip := net.ParseIP(cleanPattern); ip != nil {
			continue
		}

		// Check if it's a valid pattern
		if cleanPattern == "all" || cleanPattern == "*" {
			continue
		}

		// Validate glob pattern
		_, err := filepath.Match(cleanPattern, "test")
		if err != nil {
			return fmt.Errorf("invalid pattern '%s': %w", pattern, err)
		}
	}

	return nil
}