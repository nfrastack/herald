package config

import (
	"strconv"
	"strings"
)

// EnvToInt converts an environment variable to an integer with a default value
func EnvToInt(key string, defaultValue int) int {
	value := GetCachedEnvVar(key, "")
	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return intValue
}

// EnvToBool converts an environment variable to a boolean with a default value
func EnvToBool(key string, defaultValue bool) bool {
	value := strings.ToLower(GetCachedEnvVar(key, ""))
	if value == "" {
		return defaultValue
	}

	return value == "true" || value == "yes" || value == "1" || value == "on"
}

// EnvToString gets an environment variable as a string with a default value
// Uses the cache for better performance
func EnvToString(key string, defaultValue string) string {
	return GetCachedEnvVar(key, defaultValue)
}
