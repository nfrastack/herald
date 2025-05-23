// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (


	"fmt"
	"strings"
)

// MaskSensitiveValue masks a sensitive string value for safe logging.
// It preserves some characters from the beginning and end of the string
// to aid in identification, while masking the middle part.
// For very short strings (less than 6 chars), it simply returns "[REDACTED]".
func MaskSensitiveValue(value string) string {
	if value == "" {
		return ""
	}

	// For very short strings, just return [REDACTED]
	if len(value) < 6 {
		return "[REDACTED]"
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
		"password", "pass", "secret", "key", "token", "auth", "cred",
		"apikey", "api_key", "auth_pass", "auth_token",
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
				masked[k] = "[REDACTED]"
			}
		} else if subMap, ok := v.(map[string]interface{}); ok {
			masked[k] = MaskSensitiveMapRecursive(subMap)
		} else {
			masked[k] = v
		}
	}
	return masked
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

	// If not available, try "profile" field
	if profileName == "" {
		profileName = options["profile"]
	}

	// If still not available, check for poller-specific field
	if profileName == "" {
		profileName = options["_poll_profile"]
	}

	// If still not available, check for dns-specific field
	if profileName == "" {
		profileName = options["_dns_profile"]
	}

	// If still not available, use the provided default
	if profileName == "" {
		profileName = defaultName
	}

	return profileName
}