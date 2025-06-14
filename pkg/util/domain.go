// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package util

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// NormalizeDomainKey replaces dots with underscores for config key matching
func NormalizeDomainKey(domain string) string {
	return strings.ReplaceAll(domain, ".", "_")
}

// ExtractHostsFromRule extracts all hostnames from a rule string (used by Docker, Traefik, etc.)
func ExtractHostsFromRule(rule string) []string {
	var hostnames []string
	// Regex to match Host(`...`), Host('...'), or Host("...")
	re := regexp.MustCompile(`Host\(\s*['"` + "`" + `](.*?)['"` + "`" + `]\s*\)`)
	matches := re.FindAllStringSubmatch(rule, -1)
	for _, match := range matches {
		if len(match) > 1 {
			hosts := strings.Split(match[1], ",")
			for _, h := range hosts {
				h = strings.TrimSpace(h)
				h = strings.Trim(h, "'\"` ")
				if h != "" {
					hostnames = append(hostnames, h)
				}
			}
		}
	}
	return hostnames
}

// GetMapKeys returns a slice of all keys in a map for debugging purposes
func GetMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// GetMapKeysGeneric returns a slice of all keys in a map[string]interface{} for debugging purposes
func GetMapKeysGeneric(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// GetProfileNameFromOptions extracts a profile name from a map of options
// in a consistent manner, checking multiple possible keys
func GetProfileNameFromOptions(options map[string]string, defaultName string) string {
	// First check for the dedicated profile_name field
	profileName := options["profile_name"]

	// If not available, try to get the profile name from the "name" field
	if profileName == "" {
		profileName = options["name"]
	}

	if profileName == "" {
		profileName = options["profile"]
	}

	// If still not available, use the provided default
	if profileName == "" {
		profileName = defaultName
	}

	return profileName
}

// MaskSensitiveValue masks a sensitive string value for safe logging.
// It preserves some characters from the beginning and end of the string
// to aid in identification, while masking the middle part.
// For very short strings (less than 6 chars), it simply returns "****".
func MaskSensitiveValue(value string) string {
	if value == "" {
		return ""
	}

	// For very short strings, just return ****
	if len(value) < 6 {
		return "****"
	}

	// For longer strings, keep some characters at beginning and end
	visiblePrefix := 2
	visibleSuffix := 2

	// For longer strings, show a bit more
	if len(value) > 12 {
		visiblePrefix = 3
		visibleSuffix = 3
	}

	// Ensure we don't show more than half the string
	if visiblePrefix+visibleSuffix > len(value)/2 {
		visiblePrefix = 2
		visibleSuffix = 2
	}

	prefix := value[:visiblePrefix]
	suffix := value[len(value)-visibleSuffix:]
	masked := strings.Repeat("*", len(value)-visiblePrefix-visibleSuffix)

	return fmt.Sprintf("%s%s%s", prefix, masked, suffix)
}

// IsSensitiveKey determines if a configuration key likely contains sensitive information
// that should be masked in logs.
func IsSensitiveKey(key string) bool {
	sensitiveKeywords := []string{
		"api_email",
		"api_key",
		"api_user",
		"apikey",
		"auth_pass",
		"auth_token",
		"auth",
		"code",
		"cred",
		"credential",
		"key",
		"pass",
		"password",
		"secret",
		"token",
		"username",
		"user",
	}

	lowerKey := strings.ToLower(key)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerKey, keyword) {
			// Special case for keys that have "auth" but are not sensitive
			if keyword == "auth" && (strings.Contains(lowerKey, "author") ||
				strings.Contains(lowerKey, "oath") ||
				strings.HasSuffix(lowerKey, "auth_user")) {
				continue
			}
			return true
		}
	}
	return false
}

// MaskSensitiveOptions creates a copy of an options map with sensitive values masked
func MaskSensitiveOptions(options map[string]string) map[string]string {
	if options == nil {
		return nil
	}

	masked := make(map[string]string, len(options))
	for k, v := range options {
		if IsSensitiveKey(k) {
			masked[k] = MaskSensitiveValue(v)
		} else {
			masked[k] = v
		}
	}
	return masked
}

// MaskSensitiveMapRecursive returns a copy of the map with sensitive values masked,
// recursively masking nested maps as well
func MaskSensitiveMapRecursive(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}

	masked := make(map[string]interface{}, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			if sv, ok := v.(string); ok {
				masked[k] = MaskSensitiveValue(sv)
			} else {
				masked[k] = "****"
			}
		} else if subMap, ok := v.(map[string]interface{}); ok {
			masked[k] = MaskSensitiveMapRecursive(subMap)
		} else {
			masked[k] = v
		}
	}
	return masked
}

// ValidateListenPatterns validates network interface patterns
func ValidateListenPatterns(patterns []string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			return fmt.Errorf("empty listen pattern")
		}
		// Add basic validation - in real implementation this would be more comprehensive
		if strings.Contains(pattern, "..") {
			return fmt.Errorf("invalid pattern: %s", pattern)
		}
	}
	return nil
}

// resolveInterfacePatterns resolves wildcard interface patterns to actual IP addresses
func resolveInterfacePatterns(pattern, port string) ([]string, error) {
	var addresses []string

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	// Convert pattern to regex (simple wildcard support)
	regexPattern := strings.ReplaceAll(pattern, "*", ".*")
	regex, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return nil, fmt.Errorf("invalid pattern '%s': %w", pattern, err)
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Check if interface name matches pattern
		if !regex.MatchString(iface.Name) {
			continue
		}

		// Get IP addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				// Only IPv4 addresses for now
				if ipNet.IP.To4() != nil {
					resolvedAddr := fmt.Sprintf("%s:%s", ipNet.IP.String(), port)
					addresses = append(addresses, resolvedAddr)
				}
			}
		}
	}

	if len(addresses) == 0 {
		// List available interfaces for debugging
		var ifaceNames []string
		for _, iface := range interfaces {
			ifaceNames = append(ifaceNames, iface.Name)
		}
		return nil, fmt.Errorf("no interfaces matched pattern '%s' (available: %s)", pattern, strings.Join(ifaceNames, ", "))
	}

	return addresses, nil
}

// ResolveListenAddressesQuiet resolves listen address patterns to actual addresses
func ResolveListenAddressesQuiet(patterns []string, port string) ([]string, error) {
	addresses := []string{}

	for _, pattern := range patterns {
		// Handle explicit IP:port - DO NOT add port if already specified
		if strings.Contains(pattern, ":") {
			addresses = append(addresses, pattern)
			continue
		}

		// Handle wildcard patterns that need interface resolution
		if strings.Contains(pattern, "*") {
			resolved, err := resolveInterfacePatterns(pattern, port)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve interface pattern '%s': %w", pattern, err)
			}
			addresses = append(addresses, resolved...)
			continue
		}

		// Simple patterns
		if pattern == "all" {
			addresses = append(addresses, ":"+port)
		} else if pattern == "localhost" {
			addresses = append(addresses, "127.0.0.1:"+port)
		} else {
			addresses = append(addresses, pattern+":"+port)
		}
	}

	// Default to all interfaces if no patterns specified
	if len(addresses) == 0 {
		addresses = append(addresses, ":"+port)
	}

	return addresses, nil
}
