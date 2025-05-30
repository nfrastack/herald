// filepath: /home/dave/src/gh/dns-companion/pkg/poll/providers/tailscale/filter.go
// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"
	"strings"
)

// MatchTailscaleFilter checks if a Tailscale device matches a pollCommon.Filter
func MatchTailscaleFilter(filter pollCommon.Filter, device TailscaleDevice) bool {
	switch filter.Type {
	case pollCommon.FilterTypeNone:
		return true

	case pollCommon.FilterTypeName:
		return matchNameFilter(filter.Value, device)

	case pollCommon.FilterTypeTag:
		return matchTagFilter(filter.Value, device)

	case pollCommon.FilterTypeOnline:
		return matchOnlineFilter(filter.Value, device)

	case pollCommon.FilterTypeOS:
		return matchOSFilter(filter.Value, device)

	case pollCommon.FilterTypeUser:
		return matchUserFilter(filter.Value, device)

	default:
		return false
	}
}

// EvaluateTailscaleFilters applies a FilterConfig to a Tailscale device
func EvaluateTailscaleFilters(fc pollCommon.FilterConfig, device TailscaleDevice) bool {
	return fc.Evaluate(device, func(f pollCommon.Filter, entry any) bool {
		d, ok := entry.(TailscaleDevice)
		if !ok {
			return false
		}
		return MatchTailscaleFilter(f, d)
	})
}

func matchNameFilter(filterValue string, device TailscaleDevice) bool {
	// Check both Name and Hostname fields
	deviceName := device.Name
	if deviceName == "" {
		deviceName = device.Hostname
	}

	// Check for wildcard matches
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		match1 := pollCommon.WildcardMatch(filterValue, deviceName)
		match2 := pollCommon.WildcardMatch(filterValue, device.Hostname)
		return match1 || match2
	}

	// Direct comparison (case-insensitive)
	filterLower := strings.ToLower(filterValue)
	return strings.Contains(strings.ToLower(deviceName), filterLower) ||
		strings.Contains(strings.ToLower(device.Hostname), filterLower)
}

func matchTagFilter(filterValue string, device TailscaleDevice) bool {
	for _, tag := range device.Tags {
		// Direct match
		if strings.EqualFold(tag, filterValue) {
			return true
		}

		// Wildcard match
		if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
			match := pollCommon.WildcardMatch(filterValue, tag)
			if match {
				return true
			}
		}

		// Substring match (case-insensitive)
		if strings.Contains(strings.ToLower(tag), strings.ToLower(filterValue)) {
			return true
		}
	}
	return false
}

func matchOnlineFilter(filterValue string, device TailscaleDevice) bool {
	// Convert filter value to boolean
	online := strings.ToLower(filterValue) == "true" || filterValue == "1"
	return device.Online == online
}

func matchOSFilter(filterValue string, device TailscaleDevice) bool {
	// Wildcard match
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		match := pollCommon.WildcardMatch(filterValue, device.OS)
		return match
	}

	// Case-insensitive substring match
	return strings.Contains(strings.ToLower(device.OS), strings.ToLower(filterValue))
}

func matchUserFilter(filterValue string, device TailscaleDevice) bool {
	// Wildcard match
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		match := pollCommon.WildcardMatch(filterValue, device.User)
		return match
	}

	// Case-insensitive substring match
	return strings.Contains(strings.ToLower(device.User), strings.ToLower(filterValue))
}