// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package util

import (
	"os"
	"strings"
)

func ReadSecretValue(value string) string {
	if strings.HasPrefix(value, "file://") {
		filePath := value[7:] // Remove "file://" prefix

		content, err := os.ReadFile(filePath)
		if err != nil {
			return value
		}

		return strings.TrimSpace(string(content))
	}

	if strings.HasPrefix(value, "env://") {
		envVar := value[6:] // Remove "env://" prefix

		if envValue := os.Getenv(envVar); envValue != "" {
			return envValue
		}

		return value
	}

	return value
}
