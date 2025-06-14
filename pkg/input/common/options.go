// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"os"
	"strings"
	"time"
)

type PollProviderOptions struct {
	Interval           time.Duration
	ProcessExisting    bool
	RecordRemoveOnStop bool
	Name               string
}

func ParsePollProviderOptions(options map[string]string, defaults PollProviderOptions) PollProviderOptions {
	parsed := defaults
	if v, ok := options["interval"]; ok && v != "" {
		intervalStr := v
		if _, err := time.ParseDuration(intervalStr); err != nil {
			if _, err2 := time.ParseDuration(intervalStr + "s"); err2 == nil {
				intervalStr = intervalStr + "s"
			}
		}
		if d, err := time.ParseDuration(intervalStr); err == nil {
			parsed.Interval = d
		}
	}
	if v, ok := options["process_existing"]; ok {
		parsed.ProcessExisting = strings.ToLower(v) == "true" || v == "1"
	}
	if v, ok := options["record_remove_on_stop"]; ok {
		parsed.RecordRemoveOnStop = strings.ToLower(v) == "true" || v == "1"
	}
	if v, ok := options["name"]; ok && v != "" {
		parsed.Name = v
	}
	return parsed
}

// GetOptionOrEnv gets a configuration option or falls back to environment variable
// Only supports global environment variables: DRY_RUN, CONFIG_FILE, LOG_LEVEL, LOG_TIMESTAMPS
// Also supports file:// and env:// references for reading values from files or environment variables
func GetOptionOrEnv(options map[string]string, key, envKey, defaultValue string) string {
	var value string

	if val, exists := options[key]; exists && val != "" {
		value = val
	} else {
		// Only allow specific global environment variables
		allowedEnvVars := map[string]bool{
			"DRY_RUN":        true,
			"LOG_LEVEL":      true,
			"LOG_TIMESTAMPS": true,
		}

		if allowedEnvVars[envKey] {
			if envVal := os.Getenv(envKey); envVal != "" {
				value = envVal
			}
		}
	}

	// If still empty, use default
	if value == "" {
		value = defaultValue
	}

	// Support file:// and env:// references - use ReadFileValue for this functionality
	value = ReadFileValue(value)

	return value
}
