// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/log"
	"herald/pkg/output"
	"herald/pkg/output/common"

	"encoding/json"
)

// JSONFormat implements OutputFormat for JSON export
type JSONFormat struct {
	*common.CommonFormat
	logger *log.ScopedLogger
}

// NewJSONFormat creates a new JSON format instance
func NewJSONFormat(profileName string, config map[string]interface{}) (output.OutputFormat, error) {
	commonFormat, err := common.NewCommonFormat(profileName, "json", config)
	if err != nil {
		return nil, err
	}

	// Create scoped logger using common helper
	scopedLogger := common.AddScopedLogging(nil, "json", profileName, config)

	format := &JSONFormat{
		CommonFormat: commonFormat,
		logger:       scopedLogger,
	}

	// Load existing export if it exists
	if err := format.LoadExistingData(json.Unmarshal); err != nil {
		format.logger.Warn("Failed to load existing JSON export for domain %s: %v", profileName, err)
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
func (j *JSONFormat) serializeJSON(export *common.ExportData) ([]byte, error) {
	// Use simple JSON marshalling with indentation
	return json.MarshalIndent(export, "", "  ")
}
