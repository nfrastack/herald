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
}

// NewJSONFormat creates a new JSON format instance
func NewJSONFormat(domain string, config map[string]interface{}) (output.OutputFormat, error) {
	common, err := outputCommon.NewCommonFormat(domain, "json", config)
	if err != nil {
		return nil, err
	}

	format := &JSONFormat{
		CommonFormat: common,
	}

	// Load existing export if it exists
	if err := format.LoadExistingData(json.Unmarshal); err != nil {
		log.Warn("%s Failed to load existing export: %v", format.GetLogPrefix(), err)
	}

	return format, nil
}

// GetName returns the format name
func (j *JSONFormat) GetName() string {
	return "json"
}

// Sync writes the JSON export to disk
func (j *JSONFormat) Sync() error {
	err := j.SyncWithSerializer(j.serializeJSON)
	if err == nil {
		j.Lock()
		recordCount := j.GetRecordCount() // Use public method instead of direct field access
		j.Unlock()
		log.Debug("%s Generated export for 1 domain with %d records: %s", j.GetLogPrefix(), recordCount, j.GetFilePath())
	}
	return err
}

// serializeJSON handles JSON-specific serialization
func (j *JSONFormat) serializeJSON(export *outputCommon.ExportData) ([]byte, error) {
	return json.MarshalIndent(export, "", "  ")
}

// init registers this format
func init() {
	output.RegisterFormat("json", NewJSONFormat)
}
