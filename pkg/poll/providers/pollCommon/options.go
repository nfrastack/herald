// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
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
