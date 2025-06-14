// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package parsers

import (
	"herald/pkg/input/common"

	"fmt"

	"gopkg.in/yaml.v3"
)

// ParseStructuredYAML parses the structured YAML format and returns FileRecords
func ParseStructuredYAML(data []byte) ([]common.FileRecord, error) {
	var file StructuredFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse structured YAML: %w", err)
	}

	return convertStructuredToFileRecords(file)
}
