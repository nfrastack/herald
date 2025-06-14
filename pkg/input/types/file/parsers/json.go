// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package parsers

import (
	"herald/pkg/input/common"

	"encoding/json"
	"fmt"
)

// ParseStructuredJSON parses the structured JSON format and returns FileRecords
func ParseStructuredJSON(data []byte) ([]common.FileRecord, error) {
	var file StructuredFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse structured JSON: %w", err)
	}

	return convertStructuredToFileRecords(file)
}
