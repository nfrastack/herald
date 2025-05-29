// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package formats

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"
	"dns-companion/pkg/output/formats/outputCommon"

	"encoding/json"
)

// JSONFormat implements OutputFormat for JSON export
type JSONFormat struct {
	*outputCommon.CommonFormat
	logger *log.ScopedLogger
}

// NewJSONFormat creates a new JSON format instance
func NewJSONFormat(domain string, config map[string]interface{}) (output.OutputFormat, error) {
	common, err := outputCommon.NewCommonFormat(domain, "json", config)
	if err != nil {
		return nil, err
	}

	// Create scoped logger using common helper
	scopedLogger := outputCommon.AddScopedLogging(nil, "json", domain, config)

	format := &JSONFormat{
		CommonFormat: common,
		logger:       scopedLogger,
	}

	// Load existing export if it exists
	if err := format.LoadExistingData(json.Unmarshal); err != nil {
		format.logger.Warn("Failed to load existing JSON export for domain %s: %v", domain, err)
	}

	return format, nil
}

// GetName returns the format name
func (j *JSONFormat) GetName() string {
	return "json"
}

// Sync writes the JSON export to disk
func (j *JSONFormat) Sync() error {
	return j.SyncWithSerializer(j.serializeJSON)
}

// serializeJSON handles JSON-specific serialization
func (j *JSONFormat) serializeJSON(export *outputCommon.ExportData) ([]byte, error) {
	// Use simple JSON marshalling with indentation
	return json.MarshalIndent(export, "", "  ")
}

// init registers this format
func init() {
	output.RegisterFormat("json", NewJSONFormat)
}
