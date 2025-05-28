// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package log

import (
	"fmt"
	"time"
)

// ScopedLogger provides logging with provider-specific log levels
type ScopedLogger struct {
	prefix   string
	logLevel string
}

// NewScopedLogger creates a new scoped logger with provider-specific log level
func NewScopedLogger(prefix, logLevel string) *ScopedLogger {
	return &ScopedLogger{
		prefix:   prefix,
		logLevel: logLevel,
	}
}

// shouldLog checks if the message should be logged based on provider log level
func (s *ScopedLogger) shouldLog(level string) bool {
	if s.logLevel == "" {
		return true // Use global log level - let the global logger decide
	}

	// Define log level hierarchy (lower number = higher priority)
	levels := map[string]int{
		"error":   0,
		"warn":    1,
		"info":    2,
		"verbose": 3,
		"debug":   4,
		"trace":   5,
	}

	providerLevel, providerExists := levels[s.logLevel]
	messageLevel, messageExists := levels[level]

	if !providerExists || !messageExists {
		return true // Default to allowing if levels not found
	}

	return messageLevel <= providerLevel
}

// formatScopedMessage formats a message with proper timestamp if enabled
func (s *ScopedLogger) formatScopedMessage(level, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)

	// Use the same timestamp setting as the global logger
	if GetTimestampsEnabled() {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("%s   *%s %s\n", timestamp, level, message)
	} else {
		fmt.Printf("  *%s %s\n", level, message)
	}
}

// Scoped logging methods
func (s *ScopedLogger) Trace(format string, args ...interface{}) {
	if s.shouldLog("trace") {
		s.formatScopedMessage("TRACE", format, args...)
	}
}

func (s *ScopedLogger) Debug(format string, args ...interface{}) {
	if s.shouldLog("debug") {
		s.formatScopedMessage("DEBUG", format, args...)
	}
}

func (s *ScopedLogger) Verbose(format string, args ...interface{}) {
	if s.shouldLog("verbose") {
		// Always use normal global logging for VERBOSE
		// Only TRACE and DEBUG should bypass global filtering
		Verbose(format, args...)
	}
}

func (s *ScopedLogger) Info(format string, args ...interface{}) {
	if s.shouldLog("info") {
		// Always use normal global logging for INFO
		Info(format, args...)
	}
}

func (s *ScopedLogger) Warn(format string, args ...interface{}) {
	if s.shouldLog("warn") {
		// Always use normal global logging for WARN
		Warn(format, args...)
	}
}

func (s *ScopedLogger) Error(format string, args ...interface{}) {
	if s.shouldLog("error") {
		// Always use normal global logging for ERROR
		Error(format, args...)
	}
}
