// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"github.com/nfrastack/herald/internal/log"
)

func CreateScopedLogger(providerType, profileName string, options map[string]string) *log.ScopedLogger {
	logLevel := options["log_level"] // Get provider-specific log level
	logPrefix := BuildLogPrefix(providerType, profileName)

	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		scopedLogger.With("action", "provider.init").Info("log_level set to: '%s'", logLevel)
	}

	return scopedLogger
}
