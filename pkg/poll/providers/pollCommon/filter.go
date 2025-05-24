// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"fmt"
	"path/filepath"
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
)

// Filter defines a generic filter
// (can be used for containers, routers, etc.)
type Filter struct {
	Type      FilterType // Type of filter
	Value     string     // Filter value
	Operation string     // AND, OR, NOT (defaults to AND)
	Negate    bool       // Invert the filter result
}

type FilterConfig struct {
	Filters []Filter
}

func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Filters: []Filter{{Type: FilterTypeNone, Value: ""}},
	}
}

func NewFilterFromOptions(options map[string]string) (FilterConfig, error) {
	filterType, hasFilterType := options["filter_type"]
	filterValue, hasFilterValue := options["filter_value"]
	config := DefaultFilterConfig()
	// Simple filter
	if hasFilterType && filterType != "" {
		if filterType != string(FilterTypeNone) && (!hasFilterValue || filterValue == "") {
			return config, fmt.Errorf("filter_value is required when filter_type is not 'none'")
		}
		config.Filters = []Filter{{
			Type:      FilterType(filterType),
			Value:     filterValue,
			Operation: FilterOperationAND,
			Negate:    false,
		}}
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

// Generic multi-filter evaluation logic (AND/OR/NOT/Negate)
func (fc FilterConfig) Evaluate(entry any, matchFunc func(Filter, any) bool) bool {
	if len(fc.Filters) == 0 || (len(fc.Filters) == 1 && fc.Filters[0].Type == FilterTypeNone) {
		return true
	}
	var result bool
	for i, filter := range fc.Filters {
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
