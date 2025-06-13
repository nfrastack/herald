// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"dns-companion/pkg/utils"

	"fmt"
	"os"
	"strings"
)

// BuildLogPrefix returns a standardized log prefix for poll providers
func BuildLogPrefix(providerType, profileName string) string {
	if profileName == "" {
		return fmt.Sprintf("[poll/%s]", providerType)
	}
	return fmt.Sprintf("[poll/%s/%s]", providerType, profileName)
}

// GetOptionOrEnv returns the value from options[key], or from the environment variable envVar, or fallback if both are empty
// Also supports file:// references for reading values from files
func GetOptionOrEnv(options map[string]string, key, envVar, fallback string) string {
	var value string

	// First check options map
	if v, ok := options[key]; ok && v != "" {
		value = v
	} else if envVar != "" {
		// Then check environment variable
		if v := GetEnv(envVar); v != "" {
			value = v
		}
	}

	// If still empty, use fallback
	if value == "" {
		value = fallback
	}

	// Check if the value is a file reference and resolve it
	if strings.HasPrefix(value, "file://") {
		filePath := value[7:] // Remove "file://" prefix

		// Read the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			// Log error but return original value
			return value
		}

		// Trim whitespace and return content
		return strings.TrimSpace(string(content))
	}

	return value
}

// GetEnv is a helper to get an environment variable (for use in GetOptionOrEnv)
func GetEnv(key string) string {
	return utils.GetEnvDefault(key, "")
}
