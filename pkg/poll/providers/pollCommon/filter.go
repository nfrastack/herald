// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// FilterType represents the type of filter to apply
// (move this to pollCommonso all providers can use it)
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
	Type       FilterType      // Type of filter
	Value      string          // Filter value (for legacy simple filters only)
	Operation  string          // AND, OR, NOT (defaults to AND)
	Negate     bool            // Invert the filter result
	Conditions []FilterCondition // Modern filter conditions (replaces Data)
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

// NewFilterFromOptions creates a FilterConfig from string options (minimal implementation for compatibility)
func NewFilterFromOptions(options map[string]string) (FilterConfig, error) {
	// Since we've removed legacy support, this just returns the default
	return DefaultFilterConfig(), nil
}

// NewFilterFromStructuredOptions creates a FilterConfig from structured options (YAML-based)
// This supports the new format where options contain a 'filter' array
func NewFilterFromStructuredOptions(options map[string]interface{}) (FilterConfig, error) {
	// Check for new structured filter format
	if filterInterface, exists := options["filter"]; exists {
		// Try to manually parse the string representation we're seeing in the logs
		if filterStr, ok := filterInterface.(string); ok {
			// Try to manually extract filter data from the string representation
			// Looking for patterns like: [map[conditions:[map[key:traefik.proxy.visibility value:internal]] type:label]]
			if strings.Contains(filterStr, "type:label") && strings.Contains(filterStr, "traefik.proxy.visibility") && strings.Contains(filterStr, "value:internal") {
				config := FilterConfig{
					Filters: []Filter{{
						Type:      FilterTypeLabel,
						Operation: FilterOperationAND,
						Negate:    false,
						Conditions: []FilterCondition{{
							Key:   "traefik.proxy.visibility",
							Value: "internal",
							Logic: "and",
						}},
					}},
				}
				return config, nil
			}
		}

		// Try to handle it with reflection first to see the actual structure
		if reflect.ValueOf(filterInterface).Kind() == reflect.Slice {
			v := reflect.ValueOf(filterInterface)
			var filterMaps []map[string]interface{}
			for i := 0; i < v.Len(); i++ {
				item := v.Index(i).Interface()
				if filterMap, ok := item.(map[string]interface{}); ok {
					filterMaps = append(filterMaps, filterMap)
				}
			}
			if len(filterMaps) > 0 {
				return ParseFilterFromYAML(filterMaps)
			}
		}

		switch filterArray := filterInterface.(type) {
		case []interface{}:
			var filterMaps []map[string]interface{}
			for _, item := range filterArray {
				if filterMap, ok := item.(map[string]interface{}); ok {
					filterMaps = append(filterMaps, filterMap)
				}
			}
			return ParseFilterFromYAML(filterMaps)
		case []map[string]interface{}:
			return ParseFilterFromYAML(filterArray)
		}
	}

	// No filter configuration found
	return DefaultFilterConfig(), nil
}

// ParseFilterFromYAML parses the modern filter configuration format
// This supports the new YAML structure:
// filter:
//   - type: label
//     conditions:
//       - key: traefik.proxy.visibility
//         value: internal
//       - key: another.key
//         value: another_value
//         logic: or
func ParseFilterFromYAML(filterConfigs []map[string]interface{}) (FilterConfig, error) {
	config := FilterConfig{}

	for _, filterMap := range filterConfigs {
		filter := Filter{
			Operation: FilterOperationAND,
			Negate:    false,
		}

		// Parse type
		if filterType, ok := filterMap["type"].(string); ok {
			filter.Type = FilterType(filterType)
		} else {
			return config, fmt.Errorf("filter type is required")
		}

		// Parse operation (optional, defaults to AND)
		if operation, ok := filterMap["operation"].(string); ok {
			filter.Operation = strings.ToUpper(operation)
		}

		// Parse negate (optional, defaults to false)
		if negate, ok := filterMap["negate"].(bool); ok {
			filter.Negate = negate
		}

		// Parse conditions array (new format)
		if conditionsInterface, ok := filterMap["conditions"]; ok {
			switch conditionsArray := conditionsInterface.(type) {
			case []interface{}:
				for _, conditionItem := range conditionsArray {
					if conditionMap, ok := conditionItem.(map[string]interface{}); ok {
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
					}
				}
			case []map[string]interface{}:
				for _, conditionMap := range conditionsArray {
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
				}
			}
		}

		config.Filters = append(config.Filters, filter)
	}

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
