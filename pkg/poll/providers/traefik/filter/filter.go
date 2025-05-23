// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"container-dns-companion/pkg/log"

	"fmt"
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
	FilterTypeName       FilterType = "name"
	FilterTypeService    FilterType = "service"
	FilterTypeProvider   FilterType = "provider"
	FilterTypeEntrypoint FilterType = "entrypoint"
	FilterTypeStatus     FilterType = "status"
	FilterTypeRule       FilterType = "rule"
)

type Filter struct {
	Type      FilterType
	Value     string
	Operation string // AND, OR, NOT
	Negate    bool
}

type FilterConfig struct {
	Filters []Filter
}

func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Filters: []Filter{{Type: FilterTypeNone, Value: ""}},
	}
}

// NewFilterFromOptions creates a filter config from options (simple or advanced)
func NewFilterFromOptions(options map[string]string) (FilterConfig, error) {
	filterType, hasFilterType := options["filter_type"]
	filterValue, hasFilterValue := options["filter_value"]
	config := DefaultFilterConfig()
	// Simple filter
	if hasFilterType && filterType != "" {
		if filterType != string(FilterTypeNone) && (!hasFilterValue || filterValue == "") {
			log.Error("[poll/traefik/filter] Missing filter_value for filter_type='%s'. Options: %+v", filterType, options)
			return config, fmt.Errorf("[poll/traefik/filter] filter_value is required when filter_type is not 'none'")
		}
		config.Filters = []Filter{{
			Type:      FilterType(filterType),
			Value:     filterValue,
			Operation: FilterOperationAND,
			Negate:    false,
		}}

		log.Debug("[poll/traefik/filter] Created simple filter: type=%s value=%s", filterType, filterValue)
	}

	// Advanced filters: filter.N.type, filter.N.value, filter.N.operation, filter.N.negate
	const filterPrefix = "filter."
	for key, value := range options {
		if !strings.HasPrefix(key, filterPrefix) {
			continue
		}
		parts := strings.SplitN(key[len(filterPrefix):], ".", 2)
		if len(parts) != 2 {
			continue
		}
		filterProp := parts[1]
		// Find or create filter
		var found bool
		for i := range config.Filters {
			if config.Filters[i].Type == FilterTypeNone {
				config.Filters[i].Type = FilterType(value)
				found = true
				break
			}
		}
		if !found {
			newFilter := Filter{
				Type:      FilterType(value),
				Operation: FilterOperationAND,
				Negate:    false,
			}
			config.Filters = append(config.Filters, newFilter)
		}
		// Set property
		switch filterProp {
		case "type":
			config.Filters[len(config.Filters)-1].Type = FilterType(value)
		case "value":
			config.Filters[len(config.Filters)-1].Value = value
		case "operation":
			config.Filters[len(config.Filters)-1].Operation = strings.ToUpper(value)
		case "negate":
			config.Filters[len(config.Filters)-1].Negate = strings.ToLower(value) == "true"
		}
	}
	return config, nil
}

// ShouldProcessRouter determines if a router should be processed based on the filters
func (fc FilterConfig) ShouldProcessRouter(router map[string]interface{}) (bool, string) {
	if len(fc.Filters) == 0 || (len(fc.Filters) == 1 && fc.Filters[0].Type == FilterTypeNone) {
		return true, ""
	}
	var result bool
	for i, filter := range fc.Filters {
		match := matchFilter(filter, router)
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
	if !result {
		return false, "router did not match filter(s)"
	}
	return true, ""
}

func matchFilter(filter Filter, router map[string]interface{}) bool {
	switch filter.Type {
	case FilterTypeName:
		return matchStringField(filter.Value, router["name"])
	case FilterTypeService:
		return matchStringField(filter.Value, router["service"])
	case FilterTypeProvider:
		return matchStringField(filter.Value, router["provider"])
	case FilterTypeEntrypoint:
		return matchArrayField(filter.Value, router["entryPoints"])
	case FilterTypeStatus:
		return matchStringField(filter.Value, router["status"])
	case FilterTypeRule:
		return matchStringField(filter.Value, router["rule"])
	default:
		return false
	}
}

func matchStringField(pattern string, value interface{}) bool {
	str, ok := value.(string)
	if !ok || str == "" {
		return false
	}
	// Try regex match first
	if re, err := regexp.Compile(pattern); err == nil {
		return re.MatchString(str)
	}
	// Fallback: wildcard support
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		regex := wildcardToRegexp(pattern)
		matched, err := regexp.MatchString(regex, str)
		if err == nil {
			return matched
		}
	}
	// Fallback: exact match
	return str == pattern
}

func matchArrayField(pattern string, value interface{}) bool {
	arr, ok := value.([]interface{})
	if !ok {
		return false
	}
	for _, v := range arr {
		if matchStringField(pattern, v) {
			return true
		}
	}
	return false
}

func wildcardToRegexp(pattern string) string {
	re := regexp.QuoteMeta(pattern)
	re = strings.ReplaceAll(re, "\\*", ".*")
	re = strings.ReplaceAll(re, "\\?", ".")
	return "^" + re + "$"
}