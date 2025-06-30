// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"herald/pkg/log"

	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// FilterType represents the type of filter to apply
type FilterType string

// Filter operation types
const (
	FilterOperationAND = "AND"
	FilterOperationOR  = "OR"
	FilterOperationNOT = "NOT"
)

// Generic filter types (extend as needed for other providers)
const (
	FilterTypeNone       FilterType = "none"
	FilterTypeLabel      FilterType = "label"
	FilterTypeName       FilterType = "name"
	FilterTypeNetwork    FilterType = "network"
	FilterTypeImage      FilterType = "image"
	FilterTypeService    FilterType = "service"
	FilterTypeHealth     FilterType = "health"
	FilterTypeProvider   FilterType = "provider"
	FilterTypeEntrypoint FilterType = "entrypoint"
	FilterTypeStatus     FilterType = "status"
	FilterTypeRule       FilterType = "rule"
	FilterTypeTag        FilterType = "tag"
	FilterTypeOnline     FilterType = "online"
	FilterTypeOS         FilterType = "os"
	FilterTypeUser       FilterType = "user"
)

// Filter defines a generic filter
// (can be used for containers, routers, etc.)
type Filter struct {
	Type       FilterType        // Type of filter
	Value      string            // Filter value for simple filters
	Operation  string            // AND, OR, NOT (defaults to AND)
	Negate     bool              // Invert the filter result
	Conditions []FilterCondition // Filter conditions
}

// FilterCondition represents individual filter criteria in the modern format
type FilterCondition struct {
	Key   string `yaml:"key" mapstructure:"key"`
	Value string `yaml:"value" mapstructure:"value"`
	Logic string `yaml:"logic" mapstructure:"logic"` // and, or (defaults to and)
}

type FilterConfig struct {
	Filters []Filter
}

func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Filters: []Filter{{Type: FilterTypeNone, Value: ""}},
	}
}

// NewFilterFromStructuredOptions creates a FilterConfig from structured options
// This supports the new format where options contain a 'filter' array
func NewFilterFromStructuredOptions(options map[string]interface{}, logger *log.ScopedLogger) (FilterConfig, error) {
	logger.Debug("NewFilterFromStructuredOptions called with: %+v", options)

	// Check for new structured filter format
	if filterInterface, exists := options["filter"]; exists {
		logger.Debug("Found filter interface: %+v (type: %T)", filterInterface, filterInterface)

		// Handle JSON string case - which is what we're getting
		if filterStr, ok := filterInterface.(string); ok {

			// Parse the JSON string into []interface{}
			var filterArray []interface{}
			if err := json.Unmarshal([]byte(filterStr), &filterArray); err != nil {
				logger.Error("Failed to parse filter JSON string: %v", err)
				return DefaultFilterConfig(), fmt.Errorf("invalid filter JSON: %v", err)
			}

			logger.Debug("Successfully parsed JSON string into %d filter items", len(filterArray))

			var filterMaps []map[string]interface{}
			for i, item := range filterArray {
				logger.Debug("Processing parsed filter item %d: %+v (type: %T)", i, item, item)

				if filterMap, ok := item.(map[string]interface{}); ok {
					logger.Debug("Item %d is a map: %+v", i, filterMap)
					filterMaps = append(filterMaps, filterMap)
				} else {
					logger.Warn("Item %d is not a map, skipping", i)
				}
			}

			if len(filterMaps) > 0 {
				logger.Debug("Calling ParseFilterFromYAML with %d filter maps from JSON", len(filterMaps))
				result, err := ParseFilterFromYAML(filterMaps, logger)
				logger.Debug("ParseFilterFromYAML returned: %+v, error: %v", result, err)
				return result, err
			}
		}

		// Handle []interface{} case - original structured case
		if filterArray, ok := filterInterface.([]interface{}); ok {
			logger.Debug("Filter is []interface{} with %d elements", len(filterArray))

			var filterMaps []map[string]interface{}
			for i, item := range filterArray {
				logger.Debug("Processing filter array item %d: %+v (type: %T)", i, item, item)

				if filterMap, ok := item.(map[string]interface{}); ok {
					logger.Debug("Item %d is a map: %+v", i, filterMap)
					filterMaps = append(filterMaps, filterMap)
				} else {
					logger.Warn("Item %d is not a map, skipping", i)
				}
			}

			if len(filterMaps) > 0 {
				logger.Debug("Calling ParseFilterFromYAML with %d filter maps", len(filterMaps))
				result, err := ParseFilterFromYAML(filterMaps, logger)
				logger.Debug("ParseFilterFromYAML returned: %+v, error: %v", result, err)
				return result, err
			}
		}

		switch filterArray := filterInterface.(type) {
		case []map[string]interface{}:
			return ParseFilterFromYAML(filterArray, logger)
		}
	}

	// No filter configuration found
	logger.Debug("No filter configuration found, returning default")
	return DefaultFilterConfig(), nil
}

// ParseFilterFromYAML parses the filter configuration format
// filter:
//   - type: label
//     conditions:
//   - key: traefik.proxy.visibility
//     value: internal
//   - key: another.key
//     value: another_value
//     logic: or
func ParseFilterFromYAML(filterConfigs []map[string]interface{}, logger *log.ScopedLogger) (FilterConfig, error) {
	logger.Debug("ParseFilterFromYAML called with %d filter configs: %+v", len(filterConfigs), filterConfigs)

	config := FilterConfig{}

	for i, filterMap := range filterConfigs {
		logger.Debug("Processing filter config %d: %+v", i, filterMap)

		filter := Filter{
			Operation: FilterOperationAND,
			Negate:    false,
		}

		// Parse type
		if filterType, ok := filterMap["type"].(string); ok {
			filter.Type = FilterType(filterType)
			logger.Debug("Filter %d type set to: %s", i, filterType)
		} else {
			logger.Error("Filter %d missing required 'type' field", i)
			return config, fmt.Errorf("filter type is required")
		}

		// Parse operation (optional, defaults to AND)
		if operation, ok := filterMap["operation"].(string); ok {
			filter.Operation = strings.ToUpper(operation)
			logger.Debug("Filter %d operation set to: %s", i, filter.Operation)
		}

		// Parse negate (optional, defaults to false)
		if negate, ok := filterMap["negate"].(bool); ok {
			filter.Negate = negate
			logger.Debug("Filter %d negate set to: %t", i, negate)
		}

		// Parse conditions array (new format)
		if conditionsInterface, ok := filterMap["conditions"]; ok {
			logger.Debug("Filter %d has conditions: %+v (type: %T)", i, conditionsInterface, conditionsInterface)

			switch conditionsArray := conditionsInterface.(type) {
			case []interface{}:
				logger.Debug("Filter %d conditions is []interface{} with %d items", i, len(conditionsArray))
				for j, conditionItem := range conditionsArray {
					logger.Debug("Processing condition %d: %+v", j, conditionItem)

					if conditionMap, ok := conditionItem.(map[string]interface{}); ok {
						filterCondition := FilterCondition{}

						if key, ok := conditionMap["key"].(string); ok {
							filterCondition.Key = key
							logger.Debug("Condition %d key: %s", j, key)
						}
						if value, ok := conditionMap["value"].(string); ok {
							filterCondition.Value = value
							logger.Debug("Condition %d value: %s", j, value)
						}
						if logic, ok := conditionMap["logic"].(string); ok {
							filterCondition.Logic = strings.ToLower(logic)
							logger.Debug("Condition %d logic: %s", j, filterCondition.Logic)
						} else {
							filterCondition.Logic = "and" // default
							logger.Debug("Condition %d using default logic: and", j)
						}

						filter.Conditions = append(filter.Conditions, filterCondition)
						logger.Debug("Added condition %d to filter %d: %+v", j, i, filterCondition)
					}
				}
			case []map[string]interface{}:
				logger.Debug("Filter %d conditions is []map[string]interface{} with %d items", i, len(conditionsArray))
				for j, conditionMap := range conditionsArray {
					filterCondition := FilterCondition{}

					if key, ok := conditionMap["key"].(string); ok {
						filterCondition.Key = key
					}
					if value, ok := conditionMap["value"].(string); ok {
						filterCondition.Value = value
					}
					if logic, ok := conditionMap["logic"].(string); ok {
						filterCondition.Logic = strings.ToLower(logic)
					} else {
						filterCondition.Logic = "and" // default
					}

					filter.Conditions = append(filter.Conditions, filterCondition)
					logger.Debug("Added condition %d to filter %d: %+v", j, i, filterCondition)
				}
			}
		} else {
			logger.Debug("Filter %d has no conditions", i)
		}

		config.Filters = append(config.Filters, filter)
		logger.Debug("Added filter %d to config: Type=%s, Operation=%s, Negate=%t, Conditions=%d",
			i, filter.Type, filter.Operation, filter.Negate, len(filter.Conditions))
	}

	logger.Debug("ParseFilterFromYAML returning config with %d filters: %+v", len(config.Filters), config.Filters)
	return config, nil
}

// Generic multi-filter evaluation logic (AND/OR/NOT/Negate)
func (fc FilterConfig) Evaluate(entry any, matchFunc func(Filter, any) bool) bool {
	if len(fc.Filters) == 0 || (len(fc.Filters) == 1 && fc.Filters[0].Type == FilterTypeNone) {
		return true
	}
	var result bool
	for i, filter := range fc.Filters {
		// Skip filters with no type set or type "none"
		if filter.Type == FilterTypeNone || filter.Type == "" {
			continue
		}

		match := matchFunc(filter, entry)
		if filter.Negate {
			match = !match
		}
		if i == 0 {
			result = match
			continue
		}
		switch filter.Operation {
		case FilterOperationAND:
			result = result && match
		case FilterOperationOR:
			result = result || match
		case FilterOperationNOT:
			result = result && !match
		default:
			result = result && match
		}
	}
	return result
}

// Generic helpers for wildcard/regex matching
func WildcardMatch(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		return value == pattern
	}
	return matched
}

func RegexMatch(pattern, value string) bool {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return value == pattern
	}
	return matched
}

// Provider-specific match functions (to be passed to Evaluate)
// e.g., for Docker: func matchDockerFilter(filter Filter, entry any) bool { ... }
// e.g., for Traefik: func matchTraefikFilter(filter Filter, entry any) bool { ... }

// FilterEntries applies a filter function to a slice of entries and returns the filtered result.
func FilterEntries[T any](entries []T, filterFunc func(T) bool) []T {
	var filtered []T
	for _, entry := range entries {
		if filterFunc(entry) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// FilterByHostname returns only entries matching the given hostname
func FilterByHostname[T interface{ GetHostname() string }](entries []T, hostname string) []T {
	return FilterEntries(entries, func(e T) bool { return e.GetHostname() == hostname })
}

// FilterByRecordType returns only entries matching the given record type
func FilterByRecordType[T interface{ GetRecordType() string }](entries []T, recordType string) []T {
	return FilterEntries(entries, func(e T) bool { return e.GetRecordType() == recordType })
}

// FilterByLabel returns only entries with a label key/value (for Docker/Traefik, if applicable)
func FilterByLabel(entries []map[string]string, key, value string) []map[string]string {
	var filtered []map[string]string
	for _, entry := range entries {
		if v, ok := entry[key]; ok && v == value {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
