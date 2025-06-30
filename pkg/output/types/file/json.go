// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/log"
	"herald/pkg/output/common"

	"encoding/json"
)

// JSONFormat implements OutputFormat for JSON export
type JSONFormat struct {
	*common.CommonFormat
	logger *log.ScopedLogger
}

// NewJSONFormat creates a new JSON format instance
func NewJSONFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
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
	err := j.CommonFormat.SyncWithSerializer(j.serializeJSON)
	if err != nil {
		j.logger.Error("Sync FAILED for domain=%s, profile=%s, file=%s: %v", j.GetDomain(), j.GetProfile(), j.GetFilePath(), err)
	}
	return err
}

// serializeJSON handles JSON-specific serialization
func (j *JSONFormat) serializeJSON(domain string, export *common.ExportData) ([]byte, error) {
	// Use simple JSON marshalling with indentation
	return json.MarshalIndent(export, "", "  ")
}

// GetFilePath returns the expanded file path for this JSON file
func (j *JSONFormat) GetFilePath() string {
	path := "export_%domain_underscore%.json" // default fallback
	if j.CommonFormat != nil && j.CommonFormat.GetConfig() != nil {
		if p, ok := j.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTags(path, j.CommonFormat.GetDomain(), j.CommonFormat.GetProfile())
}

// WriteRecordWithSource writes or updates a DNS record with source information
func (j *JSONFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	j.logger.Debug("WriteRecordWithSource called: domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", domain, hostname, target, recordType, ttl, source)
	defer func() {
		j.logger.Debug("WriteRecordWithSource finished: domain=%s, hostname=%s, type=%s", domain, hostname, recordType)
	}()
	return j.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
}

// Records returns the total number of records for logging
func (j *JSONFormat) Records() int {
	export := j.GetExportData()
	if export.Domains == nil {
		return 0
	}
	n := 0
	for _, d := range export.Domains {
		n += len(d.Records)
	}
	return n
}
