// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/log"

	"fmt"
)

// OutputFormat defines the interface to avoid import cycle
type OutputFormat interface {
	GetName() string
	WriteRecord(domain, hostname, target, recordType string, ttl int) error
	WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error
	RemoveRecord(domain, hostname, recordType string) error
	Sync() error
}

// FileOutput implements OutputFormat for file-based outputs (zone, hosts, json, yaml)
type FileOutput struct {
	format     string
	underlying OutputFormat
}

// NewFileOutput creates a new file output instance that delegates to specific format implementations
func NewFileOutput(profileName string, config map[string]interface{}) (OutputFormat, error) {
	log.Debug("[output/file] Creating file output '%s' with config: %+v", profileName, config)

	format, ok := config["format"].(string)
	if !ok || format == "" {
		log.Error("[output/file] Missing or invalid 'format' field in config: %+v", config)
		return nil, fmt.Errorf("file output requires 'format' field")
	}

	log.Debug("[output/file] Using format: %s", format)

	// Validate format and delegate to specific implementations
	switch format {
	case "json":
		return NewJSONFormat(profileName, config)
	case "yaml":
		return NewYAMLFormat(profileName, config)
	case "zone":
		return NewZoneFormat(profileName, config)
	case "hosts":
		return NewHostsFormat(profileName, config)
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
