// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"regexp"
	"strings"
)

// TailscaleDevice represents a device in a Tailscale network
// This is a simplified version for the filter package to avoid circular imports
type TailscaleDevice struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	User         string   `json:"user"`
	Online       bool     `json:"online"`
	Addresses    []string `json:"addresses"`
	TailscaleIPs []string `json:"tailscaleIPs"`
	Tags         []string `json:"tags"`
	Blocked      bool     `json:"blocked"`
}

// FilterDevices filters Tailscale devices based on the provided criteria
func FilterDevices(devices []TailscaleDevice, filterType, filterValue string) []TailscaleDevice {
	if filterType == "" || filterType == "none" {
		return devices
	}

	var filtered []TailscaleDevice

	for _, device := range devices {
		match := false

		switch strings.ToLower(filterType) {
		case "online":
			online := strings.ToLower(filterValue) == "true" || filterValue == "1"
			match = device.Online == online

		case "name":
			deviceName := device.Name
			if deviceName == "" {
				deviceName = device.Hostname
			}
			match = matchString(deviceName, filterValue) || matchString(device.Hostname, filterValue)

		case "hostname":
			match = matchString(device.Hostname, filterValue)

		case "tag":
			for _, tag := range device.Tags {
				if matchString(tag, filterValue) {
					match = true
					break
				}
			}

		case "id":
			match = matchString(device.ID, filterValue)

		case "address":
			for _, addr := range device.Addresses {
				if matchString(addr, filterValue) {
					match = true
					break
				}
			}
			if !match {
				for _, addr := range device.TailscaleIPs {
					if matchString(addr, filterValue) {
						match = true
						break
					}
				}
			}

		case "user":
			match = matchString(device.User, filterValue)

		case "os":
			match = matchString(device.OS, filterValue)

		default:
			// Unknown filter type, include device by default
			match = true
		}

		if match {
			filtered = append(filtered, device)
		}
	}

	// Filter completed successfully
	return filtered
}

// matchString performs string matching with support for wildcards and regex
func matchString(value, pattern string) bool {
	if pattern == "" {
		return true
	}

	// Direct match
	if strings.EqualFold(value, pattern) {
		return true
	}

	// Wildcard match
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		return matchWildcard(value, pattern)
	}

	// Regex match (if pattern starts with / and ends with /)
	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") && len(pattern) > 2 {
		regexPattern := pattern[1 : len(pattern)-1]
		if re, err := regexp.Compile(regexPattern); err == nil {
			return re.MatchString(value)
		}
		// Invalid regex pattern
		return false
	}

	// Substring match (case-insensitive)
	return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
}

// matchWildcard performs wildcard matching (* and ?)
func matchWildcard(value, pattern string) bool {
	// Convert wildcard pattern to regex
	regexPattern := strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, `.*`)
	regexPattern = strings.ReplaceAll(regexPattern, `\?`, `.`)
	regexPattern = "^" + regexPattern + "$"

	re, err := regexp.Compile("(?i)" + regexPattern) // Case-insensitive
	if err != nil {
		return false
	}

	return re.MatchString(value)
}

// ValidateFilterCriteria validates filter criteria
func ValidateFilterCriteria(filterType, filterValue string) error {
	validTypes := []string{"none", "online", "name", "hostname", "tag", "id", "address", "user", "os"}

	if filterType == "" {
		return nil
	}

	for _, validType := range validTypes {
		if strings.EqualFold(filterType, validType) {
			return nil
		}
	}

	// Return nil if valid, could log warning for invalid types
	return nil
}

// GetFilterStats returns statistics about filtered devices
func GetFilterStats(devices []TailscaleDevice) map[string]int {
	stats := map[string]int{
		"total":   len(devices),
		"online":  0,
		"offline": 0,
		"blocked": 0,
	}

	for _, device := range devices {
		if device.Online {
			stats["online"]++
		} else {
			stats["offline"]++
		}
		if device.Blocked {
			stats["blocked"]++
		}
	}

	return stats
}
