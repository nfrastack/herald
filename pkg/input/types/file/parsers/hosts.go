// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package parsers

import (
	"bufio"
	"herald/pkg/input/common"
	"net"
	"strings"
)

// ParseHostsFile parses a hosts file and returns FileRecords (A/AAAA only)
func ParseHostsFile(data []byte) ([]common.FileRecord, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var records []common.FileRecord
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Remove inline comment
		commentIdx := strings.Index(line, "#")
		if commentIdx >= 0 {
			line = strings.TrimSpace(line[:commentIdx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		host := fields[1]
		recordType := ""
		if net.ParseIP(ip) == nil {
			continue
		}
		if strings.Contains(ip, ":") {
			recordType = "AAAA"
		} else {
			recordType = "A"
		}
		records = append(records, common.FileRecord{
			Host:   host,
			Type:   recordType,
			Target: ip,
			TTL:    120,
		})
	}
	return records, scanner.Err()
}
