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

const defaultLogPrefix = "[poll/traefik/filter]"

// NewFilterFromOptions creates a filter config from options (simple or advanced)
func NewFilterFromOptions(options map[string]string) (pollCommon.FilterConfig, error) {
	filterType, hasFilterType := options["filter_type"]
	filterValue, hasFilterValue := options["filter_value"]
	config := pollCommon.DefaultFilterConfig()
	// Simple filter
	if hasFilterType && filterType != "" {
		if filterType != string(pollCommon.FilterTypeNone) && (!hasFilterValue || filterValue == "") {
			log.Error("%s Missing filter_value for filter_type='%s'. Options: %+v", defaultLogPrefix, filterType, options)
			return config, fmt.Errorf("%s filter_value is required when filter_type is not 'none'", defaultLogPrefix)
		}
		config.Filters = []pollCommon.Filter{{
			Type:      pollCommon.FilterType(filterType),
			Value:     filterValue,
			Operation: pollCommon.FilterOperationAND,
			Negate:    false,
		}}

		log.Debug("%s Created simple filter: type=%s value=%s", defaultLogPrefix, filterType, filterValue)
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
	routerName := ""
	if name, ok := router["name"].(string); ok {
		routerName = name
	}

	log.Debug("[traefik/filter] Evaluating router '%s' against %d filters", routerName, len(fc.Filters))

	result := fc.Evaluate(router, matchTraefikFilter)
	if !result {
		log.Debug("[traefik/filter] Router '%s' did not match filter criteria", routerName)
		return false, "router did not match filter(s)"
	}

	log.Debug("[traefik/filter] Router '%s' matched filter criteria", routerName)
	return true, ""
}

func matchTraefikFilter(filter pollCommon.Filter, entry any) bool {
	router, ok := entry.(TraefikRouter)
	if !ok {
		log.Debug("[traefik/filter] Entry is not a TraefikRouter")
		return false
	}

	routerName := ""
	if name, ok := router["name"].(string); ok {
		routerName = name
	}

	log.Debug("[traefik/filter] Matching router '%s' against filter: Type=%s, Conditions=%d",
		routerName, filter.Type, len(filter.Conditions))

	// Handle modern conditions array format
	if len(filter.Conditions) > 0 {
		result := matchTraefikFilterWithConditions(filter.Conditions, filter.Type, router)
		log.Debug("[traefik/filter] Conditions match result for router '%s': %v", routerName, result)
		return result
	}

	// Handle legacy Value format (fallback)
	var result bool
	switch filter.Type {
	case pollCommon.FilterTypeName:
		result = matchStringField(filter.Value, router["name"])
	case pollCommon.FilterTypeService:
		result = matchStringField(filter.Value, router["service"])
	case pollCommon.FilterTypeProvider:
		result = matchStringField(filter.Value, router["provider"])
	case pollCommon.FilterTypeEntrypoint:
		result = matchArrayField(filter.Value, router["entryPoints"])
	case pollCommon.FilterTypeStatus:
		result = matchStringField(filter.Value, router["status"])
	case pollCommon.FilterTypeRule:
		result = matchStringField(filter.Value, router["rule"])
	default:
		result = false
	}

	log.Debug("[traefik/filter] Legacy filter match result for router '%s': %v", routerName, result)
	return result
}

// matchTraefikFilterWithConditions handles the modern conditions array format
func matchTraefikFilterWithConditions(conditions []pollCommon.FilterCondition, filterType pollCommon.FilterType, router TraefikRouter) bool {
	if len(conditions) == 0 {
		return true
	}

	var result bool
	for i, condition := range conditions {
		var match bool

		// Apply the condition based on filter type
		switch filterType {
		case pollCommon.FilterTypeName:
			match = matchStringField(condition.Value, router["name"])
		case pollCommon.FilterTypeService:
			match = matchStringField(condition.Value, router["service"])
		case pollCommon.FilterTypeProvider:
			match = matchStringField(condition.Value, router["provider"])
		case pollCommon.FilterTypeEntrypoint:
			match = matchArrayField(condition.Value, router["entryPoints"])
		case pollCommon.FilterTypeStatus:
			match = matchStringField(condition.Value, router["status"])
		case pollCommon.FilterTypeRule:
			match = matchStringField(condition.Value, router["rule"])
		default:
			match = false
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

func matchStringField(pattern string, value interface{}) bool {
	str, ok := value.(string)
	if !ok || str == "" {
		log.Debug("[traefik/filter] matchStringField: value is not a string or empty, pattern='%s', value=%v", pattern, value)
		return false
	}

	log.Debug("[traefik/filter] matchStringField: pattern='%s', value='%s'", pattern, str)

	// Try regex match first
	if re, err := regexp.Compile(pattern); err == nil {
		result := re.MatchString(str)
		log.Debug("[traefik/filter] Regex match result: %v", result)
		return result
	} else {
		log.Debug("[traefik/filter] Failed to compile regex pattern '%s': %v", pattern, err)
	}

	// Fallback: wildcard support
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		regex := wildcardToRegexp(pattern)
		matched, err := regexp.MatchString(regex, str)
		if err == nil {
			log.Debug("[traefik/filter] Wildcard match result: %v", matched)
			return matched
		} else {
			log.Debug("[traefik/filter] Failed wildcard match: %v", err)
		}
	}

	// Fallback: exact match
	exactMatch := str == pattern
	log.Debug("[traefik/filter] Exact match result: %v", exactMatch)
	return exactMatch
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
