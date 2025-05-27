// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
)

// MatchDockerFilter checks if a container matches a pollCommon.Filter
func MatchDockerFilter(filter pollCommon.Filter, container types.ContainerJSON) bool {
	// Handle all filter types
	switch filter.Type {
	case pollCommon.FilterTypeNone:
		return true
	case pollCommon.FilterTypeLabel:
		return matchLabelFilter(filter.Value, container)
	case pollCommon.FilterTypeName:
		return matchNameFilter(filter.Value, container)
	case pollCommon.FilterTypeNetwork:
		return matchNetworkFilter(filter.Value, container)
	case pollCommon.FilterTypeImage:
		return matchImageFilter(filter.Value, container)
	// For service and health, use pollCommon logic if needed in the future
	default:
		return false
	}
}

// EvaluateDockerFilters applies a FilterConfig to a Docker container
func EvaluateDockerFilters(fc pollCommon.FilterConfig, container types.ContainerJSON) bool {
	return fc.Evaluate(container, func(f pollCommon.Filter, entry any) bool {
		c, ok := entry.(types.ContainerJSON)
		if !ok {
			return false
		}
		return MatchDockerFilter(f, c)
	})
}

// matchLabelFilter checks if a container matches a label filter
func matchLabelFilter(filterValue string, container types.ContainerJSON) bool {
	// Filter value can be either "label" or "label=value"
	parts := strings.SplitN(filterValue, "=", 2)
	labelName := parts[0]

	// Check if the label exists
	labelValue, hasLabel := container.Config.Labels[labelName]
	if !hasLabel {
		return false
	}

	// If we're just checking for label existence
	if len(parts) == 1 {
		return true
	}

	// Check if the label value matches
	labelPattern := parts[1]

	// Check for wildcard matches
	if strings.Contains(labelPattern, "*") {
		// Convert glob pattern to regex
		regexPattern := "^" + strings.Replace(strings.Replace(regexp.QuoteMeta(labelPattern), "\\*", ".*", -1), "\\?", ".", -1) + "$"
		match, err := regexp.MatchString(regexPattern, labelValue)
		if err != nil {
			// In case of regex error, just do a direct compare
			return labelValue == labelPattern
		}
		return match
	}

	// Direct comparison
	return labelValue == labelPattern
}

// matchNameFilter checks if a container matches a name filter
func matchNameFilter(filterValue string, container types.ContainerJSON) bool {
	// Clean container name (remove leading slash)
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// Check for wildcard matches
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		matched, err := filepath.Match(filterValue, containerName)
		if err != nil {
			// If pattern is invalid, fall back to direct comparison
			return containerName == filterValue
		}
		return matched
	}

	// Direct comparison
	return containerName == filterValue
}

// matchNetworkFilter checks if a container belongs to a specific network
func matchNetworkFilter(filterValue string, container types.ContainerJSON) bool {
	// Check each network the container is connected to
	for networkName := range container.NetworkSettings.Networks {
		// Direct name match
		if networkName == filterValue {
			return true
		}

		// Wildcard match
		if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
			matched, err := filepath.Match(filterValue, networkName)
			if err != nil {
				continue // Invalid pattern, try next network
			}
			if matched {
				return true
			}
		}
	}
	return false
}

// matchImageFilter checks if a container's image matches the filter
func matchImageFilter(filterValue string, container types.ContainerJSON) bool {
	// Get container image name
	imageName := container.Config.Image

	// Check for direct match
	if imageName == filterValue {
		return true
	}

	// Check for wildcard match
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		matched, err := filepath.Match(filterValue, imageName)
		if err != nil {
			// If pattern is invalid, fall back to direct comparison
			return imageName == filterValue
		}
		return matched
	}

	return false
}
