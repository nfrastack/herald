// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	pollCommon "dns-companion/pkg/poll/providers/common"

	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
)

// matchFilter checks if a container matches a single filter
func matchFilter(filter pollCommon.Filter, container types.ContainerJSON) bool {
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

	case pollCommon.FilterTypeService:
		return matchServiceFilter(filter.Value, container)

	case pollCommon.FilterTypeHealth:
		return matchHealthFilter(filter.Value, container)

	default:
		// Unknown filter type, don't match
		return false
	}
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

// matchServiceFilter checks if a container belongs to a specific service (Swarm)
func matchServiceFilter(filterValue string, container types.ContainerJSON) bool {
	// Check for Docker Swarm service labels
	serviceName, hasServiceName := container.Config.Labels["com.docker.swarm.service.name"]
	if !hasServiceName {
		return false
	}

	// Check for direct match
	if serviceName == filterValue {
		return true
	}

	// Check for wildcard match
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		matched, err := filepath.Match(filterValue, serviceName)
		if err != nil {
			// If pattern is invalid, fall back to direct comparison
			return serviceName == filterValue
		}
		return matched
	}

	return false
}

// matchHealthFilter checks if a container's health status matches the filter
func matchHealthFilter(filterValue string, container types.ContainerJSON) bool {
	if container.State == nil {
		return false
	}

	// If container has no health check, return true only if filter value is "none"
	if container.State.Health == nil {
		return strings.ToLower(filterValue) == "none"
	}

	// Check health status
	healthStatus := container.State.Health.Status
	return strings.ToLower(healthStatus) == strings.ToLower(filterValue)
}
