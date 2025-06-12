// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"path/filepath"
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
		return matchLabelFilterWithConditions(filter.Conditions, container)
	case pollCommon.FilterTypeName:
		return matchNameFilterWithConditions(filter.Conditions, container)
	case pollCommon.FilterTypeNetwork:
		return matchNetworkFilterWithConditions(filter.Conditions, container)
	case pollCommon.FilterTypeImage:
		return matchImageFilterWithConditions(filter.Conditions, container)
	default:
		return false
	}
}

// EvaluateDockerFilters applies a FilterConfig to a Docker container
func EvaluateDockerFilters(fc pollCommon.FilterConfig, container types.ContainerJSON) bool {
	// Get container name for debug logging
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	result := fc.Evaluate(container, func(f pollCommon.Filter, entry any) bool {
		c, ok := entry.(types.ContainerJSON)
		if !ok {
			return false
		}
		return MatchDockerFilter(f, c)
	})

	return result
}

// matchLabelFilterWithConditions checks if a container matches a label filter using the conditions array format
func matchLabelFilterWithConditions(conditions []pollCommon.FilterCondition, container types.ContainerJSON) bool {
	if len(conditions) == 0 {
		return true
	}

	var result bool
	for i, condition := range conditions {
		var match bool

		if condition.Key != "" {
			// Check if the label exists and optionally matches a value
			labelValue, hasLabel := container.Config.Labels[condition.Key]
			if !hasLabel {
				match = false
			} else if condition.Value == "" {
				// Just checking for label existence
				match = true
			} else {
				// Check if the label value matches
				match = matchStringValue(labelValue, condition.Value)
			}
		}

		// Apply logic for combining results
		if i == 0 {
			result = match
		} else {
			logic := strings.ToLower(condition.Logic)
			if logic == "or" {
				result = result || match
			} else { // default to "and"
				result = result && match
			}
		}
	}

	return result
}

// matchNameFilterWithConditions checks if a container matches a name filter using the conditions array format
func matchNameFilterWithConditions(conditions []pollCommon.FilterCondition, container types.ContainerJSON) bool {
	if len(conditions) == 0 {
		return true
	}

	// Clean container name (remove leading slash)
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	var result bool
	for i, condition := range conditions {
		var match bool

		if condition.Value != "" {
			match = matchStringValue(containerName, condition.Value)
		}

		// Apply logic for combining results
		if i == 0 {
			result = match
		} else {
			logic := strings.ToLower(condition.Logic)
			if logic == "or" {
				result = result || match
			} else { // default to "and"
				result = result && match
			}
		}
	}

	return result
}

// matchNetworkFilterWithConditions checks if a container belongs to networks using the conditions array format
func matchNetworkFilterWithConditions(conditions []pollCommon.FilterCondition, container types.ContainerJSON) bool {
	if len(conditions) == 0 {
		return true
	}

	var result bool
	for i, condition := range conditions {
		var match bool

		if condition.Value != "" {
			// Check each network the container is connected to
			for networkName := range container.NetworkSettings.Networks {
				if matchStringValue(networkName, condition.Value) {
					match = true
					break
				}
			}
		}

		// Apply logic for combining results
		if i == 0 {
			result = match
		} else {
			logic := strings.ToLower(condition.Logic)
			if logic == "or" {
				result = result || match
			} else { // default to "and"
				result = result && match
			}
		}
	}

	return result
}

// matchImageFilterWithConditions checks if a container's image matches using the conditions array format
func matchImageFilterWithConditions(conditions []pollCommon.FilterCondition, container types.ContainerJSON) bool {
	if len(conditions) == 0 {
		return true
	}

	imageName := container.Config.Image

	var result bool
	for i, condition := range conditions {
		var match bool

		if condition.Value != "" {
			match = matchStringValue(imageName, condition.Value)
		}

		// Apply logic for combining results
		if i == 0 {
			result = match
		} else {
			logic := strings.ToLower(condition.Logic)
			if logic == "or" {
				result = result || match
			} else { // default to "and"
				result = result && match
			}
		}
	}

	return result
}

// matchStringValue handles wildcard and direct string matching
func matchStringValue(actual, pattern string) bool {
	// Check for wildcard matches
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		matched, err := filepath.Match(pattern, actual)
		if err != nil {
			// If pattern is invalid, fall back to direct comparison
			return actual == pattern
		}
		return matched
	}

	// Direct comparison
	return actual == pattern
}
