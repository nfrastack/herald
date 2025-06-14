// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"herald/pkg/log"
)

// CreateScopedLogger creates a scoped logger for poll providers using common logic
func CreateScopedLogger(providerType, profileName string, options map[string]string) *log.ScopedLogger {
	logLevel := options["log_level"] // Get provider-specific log level
	logPrefix := BuildLogPrefix(providerType, profileName)

	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		scopedLogger.Info("Provider log_level set to: '%s'", logLevel)
	}

	return scopedLogger
}
