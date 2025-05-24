// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"dns-companion/pkg/log"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"fmt"
	"regexp"
	"strings"
)

type TraefikRouter map[string]interface{}

// NewFilterFromOptions creates a filter config from options (simple or advanced)
func NewFilterFromOptions(options map[string]string) (pollCommon.FilterConfig, error) {
	filterType, hasFilterType := options["filter_type"]
	filterValue, hasFilterValue := options["filter_value"]
	config := pollCommon.DefaultFilterConfig()
	// Simple filter
	if hasFilterType && filterType != "" {
		if filterType != string(pollCommon.FilterTypeNone) && (!hasFilterValue || filterValue == "") {
			log.Error("[poll/traefik/filter] Missing filter_value for filter_type='%s'. Options: %+v", filterType, options)
			return config, fmt.Errorf("[poll/traefik/filter] filter_value is required when filter_type is not 'none'")
		}
		config.Filters = []pollCommon.Filter{{
			Type:      pollCommon.FilterType(filterType),
			Value:     filterValue,
			Operation: pollCommon.FilterOperationAND,
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
			if config.Filters[i].Type == pollCommon.FilterTypeNone {
				config.Filters[i].Type = pollCommon.FilterType(value)
				found = true
				break
			}
		}
		if !found {
			newFilter := pollCommon.Filter{
				Type:      pollCommon.FilterType(value),
				Operation: pollCommon.FilterOperationAND,
				Negate:    false,
			}
			config.Filters = append(config.Filters, newFilter)
		}
		// Set property
		switch filterProp {
		case "type":
			config.Filters[len(config.Filters)-1].Type = pollCommon.FilterType(value)
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
func ShouldProcessRouter(fc pollCommon.FilterConfig, router TraefikRouter) (bool, string) {
	result := fc.Evaluate(router, matchTraefikFilter)
	if !result {
		return false, "router did not match filter(s)"
	}
	return true, ""
}

func matchTraefikFilter(filter pollCommon.Filter, entry any) bool {
	router, ok := entry.(TraefikRouter)
	if !ok {
		return false
	}
	switch filter.Type {
	case pollCommon.FilterTypeName:
		return matchStringField(filter.Value, router["name"])
	case pollCommon.FilterTypeService:
		return matchStringField(filter.Value, router["service"])
	case pollCommon.FilterTypeProvider:
		return matchStringField(filter.Value, router["provider"])
	case pollCommon.FilterTypeEntrypoint:
		return matchArrayField(filter.Value, router["entryPoints"])
	case pollCommon.FilterTypeStatus:
		return matchStringField(filter.Value, router["status"])
	case pollCommon.FilterTypeRule:
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
