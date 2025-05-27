// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package formats

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"
	"dns-companion/pkg/output/formats/outputCommon"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLFormat implements OutputFormat for YAML export
type YAMLFormat struct {
	*outputCommon.CommonFormat
}

// NewYAMLFormat creates a new YAML format instance
func NewYAMLFormat(domain string, config map[string]interface{}) (output.OutputFormat, error) {
	common, err := outputCommon.NewCommonFormat(domain, "yaml", config)
	if err != nil {
		return nil, err
	}

	format := &YAMLFormat{
		CommonFormat: common,
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
	return y.SyncWithSerializer(y.serializeYAML)
}

// serializeYAML handles YAML-specific serialization
func (y *YAMLFormat) serializeYAML(export *outputCommon.ExportData) ([]byte, error) {
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

// init registers this format
func init() {
	output.RegisterFormat("yaml", NewYAMLFormat)
}
