// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/log"
	"herald/pkg/output/common"

	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLFormat implements OutputFormat for YAML export
type YAMLFormat struct {
	*common.CommonFormat
}

// NewYAMLFormat creates a new YAML format instance
func NewYAMLFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
	commonFormat, err := common.NewCommonFormat(profileName, "yaml", config)
	if err != nil {
		return nil, err
	}

	format := &YAMLFormat{
		CommonFormat: commonFormat,
	}

	// Load existing export if it exists
	if err := format.LoadExistingData(yaml.Unmarshal); err != nil {
		log.Warn("%s Failed to load existing export: %v", format.GetLogPrefix(), err)
	}

	return format, nil
}

// GetName returns the format name
func (y *YAMLFormat) GetName() string {
	return "yaml"
}

// Sync writes the YAML export to disk
func (y *YAMLFormat) Sync() error {
	err := y.CommonFormat.SyncWithSerializer(y.serializeYAML)
	if err != nil {
		log.Error("[output/yaml] Sync FAILED for domain=%s, profile=%s, file=%s: %v", y.GetDomain(), y.GetProfile(), y.GetFilePath(), err)
	}
	return err
}

// serializeYAML handles YAML-specific serialization
func (y *YAMLFormat) serializeYAML(domain string, export *common.ExportData) ([]byte, error) {
	var buf strings.Builder
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

	err := encoder.Encode(export)
	encoder.Close()
	if err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

// GetFilePath returns the expanded file path for this YAML file
func (y *YAMLFormat) GetFilePath() string {
	path := "export_%domain_underscore%.yaml" // default fallback
	if y.CommonFormat != nil && y.CommonFormat.GetConfig() != nil {
		if p, ok := y.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTags(path, y.CommonFormat.GetDomain(), y.CommonFormat.GetProfile())
}

// WriteRecordWithSource writes or updates a DNS record with source information
func (y *YAMLFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	log.Debug("[output/yaml] WriteRecordWithSource called: domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", domain, hostname, target, recordType, ttl, source)
	defer func() {
		log.Debug("[output/yaml] WriteRecordWithSource finished: domain=%s, hostname=%s, type=%s", domain, hostname, recordType)
	}()
	return y.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
}

// Records returns the total number of records for logging
func (y *YAMLFormat) Records() int {
	export := y.GetExportData()
	if export.Domains == nil {
		return 0
	}
	n := 0
	for _, d := range export.Domains {
		n += len(d.Records)
	}
	return n
}
