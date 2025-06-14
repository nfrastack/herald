// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/log"
	"herald/pkg/output"
	"herald/pkg/output/common"

	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLFormat implements OutputFormat for YAML export
type YAMLFormat struct {
	*common.CommonFormat
}

// NewYAMLFormat creates a new YAML format instance
func NewYAMLFormat(profileName string, config map[string]interface{}) (output.OutputFormat, error) {
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
	err := y.SyncWithSerializer(y.serializeYAML)
	if err == nil {
		y.Lock()
		recordCount := y.GetRecordCount()
		y.Unlock()
		log.Debug("%s Generated export for 1 domain with %d records: %s", y.GetLogPrefix(), recordCount, y.GetFilePath())
	}
	return err
}

// serializeYAML handles YAML-specific serialization
func (y *YAMLFormat) serializeYAML(export *common.ExportData) ([]byte, error) {
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
