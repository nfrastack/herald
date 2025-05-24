// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"dns-companion/pkg/utils"

	"fmt"
)

// BuildLogPrefix returns a standardized log prefix for poll providers
func BuildLogPrefix(providerType, profileName string) string {
	if profileName == "" || profileName == providerType {
		return fmt.Sprintf("[poll/%s]", providerType)
	}
	return fmt.Sprintf("[poll/%s/%s]", providerType, profileName)
}

// GetOptionOrEnv returns the value from options[key], or from the environment variable envVar, or fallback if both are empty
func GetOptionOrEnv(options map[string]string, key, envVar, fallback string) string {
	if v, ok := options[key]; ok && v != "" {
		return v
	}
	if envVar != "" {
		if v := GetEnv(envVar); v != "" {
			return v
		}
	}
	return fallback
}

// GetEnv is a helper to get an environment variable (for use in GetOptionOrEnv)
func GetEnv(key string) string {
	return utils.GetEnvDefault(key, "")
}
