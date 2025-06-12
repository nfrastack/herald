// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package filter

import (
	"dns-companion/pkg/log"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"regexp"
	"strings"
)

type TraefikRouter map[string]interface{}

const defaultLogPrefix = "[poll/traefik/filter]"

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

	// Handle conditions array format only
	switch filter.Type {
	case pollCommon.FilterTypeName:
		for _, condition := range filter.Conditions {
			if !matchStringField(condition.Value, router["name"]) {
				return false
			}
		}
		return true
	case pollCommon.FilterTypeService:
		for _, condition := range filter.Conditions {
			if !matchStringField(condition.Value, router["service"]) {
				return false
			}
		}
		return true
	case pollCommon.FilterTypeProvider:
		for _, condition := range filter.Conditions {
			if !matchStringField(condition.Value, router["provider"]) {
				return false
			}
		}
		return true
	case pollCommon.FilterTypeEntrypoint:
		for _, condition := range filter.Conditions {
			if !matchArrayField(condition.Value, router["entryPoints"]) {
				return false
			}
		}
		return true
	case pollCommon.FilterTypeStatus:
		for _, condition := range filter.Conditions {
			if !matchStringField(condition.Value, router["status"]) {
				return false
			}
		}
		return true
	case pollCommon.FilterTypeRule:
		for _, condition := range filter.Conditions {
			if !matchStringField(condition.Value, router["rule"]) {
				return false
			}
		}
		return true
	default:
		return true
	}
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
