// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package util

import (
	"os"
	"strings"
)

// ReadSecretValue reads a value from a file if it starts with "file://",
// reads from environment variable if it starts with "env://",
// otherwise returns the original value
func ReadSecretValue(value string) string {
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

	// Check if the value is an environment variable reference
	if strings.HasPrefix(value, "env://") {
		envVar := value[6:] // Remove "env://" prefix

		// Read the environment variable
		if envValue := os.Getenv(envVar); envValue != "" {
			return envValue
		}

		// If environment variable doesn't exist, return original value
		return value
	}

	return value
}
