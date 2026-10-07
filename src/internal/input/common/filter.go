// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"github.com/nfrastack/herald/internal/log"

	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type FilterType string

const (
	FilterOperationAND = "AND"
	FilterOperationOR  = "OR"
	FilterOperationNOT = "NOT"
)

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

type Filter struct {
	Type       FilterType        // Type of filter
	Value      string            // Filter value for simple filters
	Operation  string            // AND, OR, NOT (defaults to AND)
	Negate     bool              // Invert the filter result
	Conditions []FilterCondition // Filter conditions
}

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

func NewFilterFromStructuredOptions(options map[string]interface{}, logger *log.ScopedLogger) (FilterConfig, error) {
	logger.With("action", "input.filter").Debug("called with: %+v", options)

	if filterInterface, exists := options["filter"]; exists {
		logger.With("action", "input.filter").Debug("filter interface: %+v (type: %T)", filterInterface, filterInterface)

		if filterStr, ok := filterInterface.(string); ok {

			var filterArray []interface{}
			if err := json.Unmarshal([]byte(filterStr), &filterArray); err != nil {
				logger.With("action", "input.filter").Error("filter JSON string: %v", err)
				return DefaultFilterConfig(), fmt.Errorf("invalid filter JSON: %v", err)
			}

			logger.With("action", "input.filter").Debug("JSON string into %d filter items", len(filterArray))

			var filterMaps []map[string]interface{}
			for i, item := range filterArray {
				logger.With("action", "input.filter").Debug("parsed filter item %d: %+v (type: %T)", i, item, item)

				if filterMap, ok := item.(map[string]interface{}); ok {
					logger.With("action", "input.filter").Debug("item %d is a map: %+v", i, filterMap)
					filterMaps = append(filterMaps, filterMap)
				} else {
					logger.With("action", "input.filter").Warn("item %d is not a map, skipping", i)
				}
			}

			if len(filterMaps) > 0 {
				logger.With("action", "input.filter").Debug("ParseFilterFromYAML with %d filter maps from JSON", len(filterMaps))
				result, err := ParseFilterFromYAML(filterMaps, logger)
				logger.With("action", "input.filter").Debug("returned: %+v, error: %v", result, err)
				return result, err
			}
		}

		if filterArray, ok := filterInterface.([]interface{}); ok {
			logger.With("action", "input.filter").Debug("[]interface{} with %d elements", len(filterArray))

			var filterMaps []map[string]interface{}
			for i, item := range filterArray {
				logger.With("action", "input.filter").Debug("filter array item %d: %+v (type: %T)", i, item, item)

				if filterMap, ok := item.(map[string]interface{}); ok {
					logger.With("action", "input.filter").Debug("item %d is a map: %+v", i, filterMap)
					filterMaps = append(filterMaps, filterMap)
				} else {
					logger.With("action", "input.filter").Warn("item %d is not a map, skipping", i)
				}
			}

			if len(filterMaps) > 0 {
				logger.With("action", "input.filter").Debug("ParseFilterFromYAML with %d filter maps", len(filterMaps))
				result, err := ParseFilterFromYAML(filterMaps, logger)
				logger.With("action", "input.filter").Debug("returned: %+v, error: %v", result, err)
				return result, err
			}
		}

		switch filterArray := filterInterface.(type) {
		case []map[string]interface{}:
			return ParseFilterFromYAML(filterArray, logger)
		}
	}

	logger.With("action", "input.filter").Debug("no filter configuration found, default")
	return DefaultFilterConfig(), nil
}

func ParseFilterFromYAML(filterConfigs []map[string]interface{}, logger *log.ScopedLogger) (FilterConfig, error) {
	logger.With("action", "input.filter").Debug("with %d filter configs: %+v", len(filterConfigs), filterConfigs)

	config := FilterConfig{}

	for i, filterMap := range filterConfigs {
		logger.With("action", "input.filter").Debug("filter config %d: %+v", i, filterMap)

		filter := Filter{
			Operation: FilterOperationAND,
			Negate:    false,
		}

		if filterType, ok := filterMap["type"].(string); ok {
			filter.Type = FilterType(filterType)
			logger.With("action", "input.filter").Debug("%d type: %s", i, filterType)
		} else {
			logger.With("action", "config.error").Error("%d missing required 'type' field", i)
			return config, fmt.Errorf("filter type is required")
		}

		if operation, ok := filterMap["operation"].(string); ok {
			filter.Operation = strings.ToUpper(operation)
			logger.With("action", "input.filter").Debug("%d operation: %s", i, filter.Operation)
		}

		if negate, ok := filterMap["negate"].(bool); ok {
			filter.Negate = negate
			logger.With("action", "input.filter").Debug("%d negate: %t", i, negate)
		}

		if conditionsInterface, ok := filterMap["conditions"]; ok {
			logger.With("action", "input.filter").Debug("%d conditions: %+v (type: %T)", i, conditionsInterface, conditionsInterface)

			switch conditionsArray := conditionsInterface.(type) {
			case []interface{}:
				logger.With("action", "input.filter").Debug("%d conditions is []interface{} with %d items", i, len(conditionsArray))
				for j, conditionItem := range conditionsArray {
					logger.With("action", "input.filter").Debug("condition %d: %+v", j, conditionItem)

					if conditionMap, ok := conditionItem.(map[string]interface{}); ok {
						filterCondition := FilterCondition{}

						if key, ok := conditionMap["key"].(string); ok {
							filterCondition.Key = key
							logger.With("action", "input.filter").Debug("%d key: %s", j, key)
						}
						if value, ok := conditionMap["value"].(string); ok {
							filterCondition.Value = value
							logger.With("action", "input.filter").Debug("%d value: %s", j, value)
						}
						if logic, ok := conditionMap["logic"].(string); ok {
							filterCondition.Logic = strings.ToLower(logic)
							logger.With("action", "input.filter").Debug("%d logic: %s", j, filterCondition.Logic)
						} else {
							filterCondition.Logic = "and" // default
							logger.With("action", "input.filter").Debug("%d default logic: and", j)
						}

						filter.Conditions = append(filter.Conditions, filterCondition)
						logger.With("action", "input.filter").Debug("condition %d to filter %d: %+v", j, i, filterCondition)
					}
				}
			case []map[string]interface{}:
				logger.With("action", "input.filter").Debug("%d conditions is []map[string]interface{} with %d items", i, len(conditionsArray))
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
					logger.With("action", "input.filter").Debug("condition %d to filter %d: %+v", j, i, filterCondition)
				}
			}
		} else {
			logger.With("action", "input.filter").Debug("%d no conditions", i)
		}

		config.Filters = append(config.Filters, filter)
		logger.With("action", "input.filter").Debug("filter %d to config: Type=%s, Operation=%s, Negate=%t, Conditions=%d",
			i, filter.Type, filter.Operation, filter.Negate, len(filter.Conditions))
	}

	logger.With("action", "input.filter").Debug("config with %d filters: %+v", len(config.Filters), config.Filters)
	return config, nil
}

func (fc FilterConfig) Evaluate(entry any, matchFunc func(Filter, any) bool) bool {
	if len(fc.Filters) == 0 || (len(fc.Filters) == 1 && fc.Filters[0].Type == FilterTypeNone) {
		return true
	}
	var result bool
	for i, filter := range fc.Filters {
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

func FilterEntries[T any](entries []T, filterFunc func(T) bool) []T {
	var filtered []T
	for _, entry := range entries {
		if filterFunc(entry) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func FilterByHostname[T interface{ GetHostname() string }](entries []T, hostname string) []T {
	return FilterEntries(entries, func(e T) bool { return e.GetHostname() == hostname })
}

func FilterByRecordType[T interface{ GetRecordType() string }](entries []T, recordType string) []T {
	return FilterEntries(entries, func(e T) bool { return e.GetRecordType() == recordType })
}

func FilterByLabel(entries []map[string]string, key, value string) []map[string]string {
	var filtered []map[string]string
	for _, entry := range entries {
		if v, ok := entry[key]; ok && v == value {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
