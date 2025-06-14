// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package parsers

import (
	"bufio"
	"herald/pkg/input/common"
	"strconv"
	"strings"
)

// ParseZoneFile parses a DNS zone file and returns FileRecords (A/AAAA/CNAME only)
func ParseZoneFile(data []byte) ([]common.FileRecord, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var records []common.FileRecord
	origin := ""
	defaultTTL := 120

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "$ORIGIN") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				origin = strings.TrimSuffix(parts[1], ".")
			}
			continue
		}
		// Remove inline comment
		commentIdx := strings.Index(line, ";")
		if commentIdx >= 0 {
			line = strings.TrimSpace(line[:commentIdx])
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Try to parse: [name] [ttl] [class] [type] [target]
		name := fields[0]
		ttl := defaultTTL
		classIdx := 1
		if t, err := strconv.Atoi(fields[1]); err == nil {
			ttl = t
			classIdx = 2
		}
		if len(fields) <= classIdx+2 {
			continue
		}
		class := fields[classIdx]
		recordType := fields[classIdx+1]
		target := fields[classIdx+2]
		if class != "IN" {
			continue
		}
		fqdn := name
		if fqdn == "@" {
			fqdn = origin
		} else if origin != "" && !strings.HasSuffix(fqdn, "."+origin) && fqdn != origin {
			fqdn = fqdn + "." + origin
		}
		switch recordType {
		case "A", "AAAA", "CNAME":
			records = append(records, common.FileRecord{
				Host:   fqdn,
				Type:   recordType,
				Target: target,
				TTL:    ttl,
			})
		}
	}
	return records, scanner.Err()
}
