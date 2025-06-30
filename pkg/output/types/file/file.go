// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"fmt"
	"herald/pkg/log"
	"herald/pkg/output/types/common"
	"strings"
	"time"
)

// expandTags replaces template tags in s with values from domain, profile, etc.
func expandTags(s, domain, profile string) string {
	domainUnderscore := strings.ReplaceAll(domain, ".", "_")
	now := time.Now().Format("20060102-150405") // yyyymmdd-hhmmss
	replacer := strings.NewReplacer(
		"%domain%", domain,
		"%domain_underscore%", domainUnderscore,
		"%date%", now,
		"%profile%", profile,
	)
	return replacer.Replace(s)
}

// OutputFormat defines the interface to avoid import cycle
type OutputFormat = common.OutputFormat

// FileOutput implements OutputFormat for file-based outputs (zone, hosts, json, yaml)
type FileOutput struct {
	format     string
	underlying OutputFormat
}

// NewFileOutput creates a new file output instance that delegates to specific format implementations
func NewFileOutput(profileName string, config map[string]interface{}) (OutputFormat, error) {
	format, ok := config["format"].(string)
	if !ok || format == "" {
		log.Error("[output/file] Missing or invalid 'format' field in config: %+v", config)
		return nil, fmt.Errorf("file output requires 'format' field")
	}

	log.Debug("[output/file] Creating file output '%s' (format: %s) with config: %+v", profileName, format, config)

	// Validate format and delegate to specific implementations
	switch format {
	case "json":
		return NewJSONFormat(profileName, config)
	case "yaml":
		return NewYAMLFormat(profileName, config)
	case "zone":
		if domain, ok := config["domain"].(string); ok && domain != "" {
			return NewZoneFormat(profileName, domain, config)
		} else {
			return nil, fmt.Errorf("zone output requires 'domain' field in config")
		}
	case "hosts":
		// For hosts, pass both domain and profileName
		if domain, ok := config["domain"].(string); ok && domain != "" {
			return NewHostsFormat(domain, profileName, config)
		} else {
			return nil, fmt.Errorf("hosts output requires 'domain' field in config")
		}
	default:
		return nil, fmt.Errorf("unsupported file format '%s', must be one of: json, yaml, zone, hosts", format)
	}
}

// NewProvider creates a new file output provider
func NewProvider(name string, config map[string]interface{}) (OutputFormat, error) {
	log.Debug("[output/file] NewProvider called with name='%s', config: %+v", name, config)
	return NewFileOutput(name, config)
}

// init does nothing - registration is handled by the main output package
func init() {
	log.Debug("[output/file] File output types loaded")
}
