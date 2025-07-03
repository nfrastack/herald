// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/output/common"

	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ZoneFormat implements OutputFormat for DNS zone files
type ZoneFormat struct {
	*common.CommonFormat
	soaRaw     map[string]interface{} // store raw SOA config for per-domain expansion
	nsRaw      []string               // store raw NS config for per-domain expansion
	strictSync bool                   // if true, blank records not present in new data
}

// SOARecord represents anSOA record configuration
type SOARecord struct {
	PrimaryNS  string
	AdminEmail string
	Serial     string
	Refresh    int
	Retry      int
	Expire     int
	Minimum    int
}

// NewZoneFormat creates a new zone format instance
func NewZoneFormat(profileName, domain string, config map[string]interface{}) (OutputFormat, error) {
	commonFormat, err := common.NewCommonFormat(profileName, "zone", config)
	if err != nil {
		return nil, err
	}

	strictSync := false
	if v, ok := config["strict_sync"]; ok {
		if b, ok := v.(bool); ok {
			strictSync = b
		}
	}

	format := &ZoneFormat{
		CommonFormat: commonFormat,
		strictSync:   strictSync,
	}

	if err := format.parseSOAConfig(config); err != nil {
		return nil, fmt.Errorf("failed to parse SOA config: %v", err)
	}

	if err := format.parseNSConfig(config); err != nil {
		return nil, fmt.Errorf("failed to parse NS config: %v", err)
	}

	return format, nil
}

// parseSOAConfig parses SOA record configuration and stores raw values
func (z *ZoneFormat) parseSOAConfig(config map[string]interface{}) error {
	soaConfig, ok := config["soa"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("soa configuration is required")
	}
	z.soaRaw = soaConfig
	return nil
}

// parseNSConfig parses NS record configuration and stores raw values
func (z *ZoneFormat) parseNSConfig(config map[string]interface{}) error {
	nsRecordsInterface, ok := config["ns_records"]
	if !ok {
		return fmt.Errorf("ns_records configuration is required")
	}

	nsRecordsSlice, ok := nsRecordsInterface.([]interface{})
	if !ok {
		return fmt.Errorf("ns_records must be a list")
	}

	z.nsRaw = make([]string, 0, len(nsRecordsSlice))
	for _, ns := range nsRecordsSlice {
		nsString, ok := ns.(string)
		if !ok {
			return fmt.Errorf("ns_records entries must be strings")
		}
		z.nsRaw = append(z.nsRaw, nsString)
	}
	return nil
}

// GetName returns the format name
func (z *ZoneFormat) GetName() string {
	return "zone"
}

// GetFilePath returns the expanded file path for this zone file
func (z *ZoneFormat) GetFilePath() string {
	path := "zone_%domain_underscore%.zone" // default fallback
	if z.CommonFormat != nil && z.CommonFormat.GetConfig() != nil {
		if p, ok := z.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTags(path, z.CommonFormat.GetDomain(), z.CommonFormat.GetProfile())
}

// Sync writes the zone file to disk
func (z *ZoneFormat) Sync() error {
	export := z.GetExportData()
	profile := z.CommonFormat.GetProfile()
	if export != nil && export.Domains != nil {
		domainKeys := make([]string, 0, len(export.Domains))
		for k := range export.Domains {
			domainKeys = append(domainKeys, k)
		}
		z.GetLogger().Debug("Available domains in export: %v", domainKeys)
		for domain := range export.Domains {
			// Save the original domain
			origDomain := z.CommonFormat.GetDomain()
			// Temporarily set the domain for correct file path expansion
			z.CommonFormat.SetDomain(domain)
			filePath := z.GetFilePath()
			z.GetLogger().Debug("Syncing domain=%s for profile=%s, file=%s", domain, profile, filePath)

			if !z.strictSync {
				// Non-strict: Load existing records from file, merge with in-memory, only remove if explicitly removed
				// (Assume a LoadExistingDataFromFile method exists or implement a simple loader)
				_ = z.loadAndMergeExistingRecords(domain, filePath)
			}

			err := z.CommonFormat.SyncWithSerializer(func(_ string, e *common.ExportData) ([]byte, error) {
				return z.serializeZone(domain, e)
			})
			// Restore the original domain
			z.CommonFormat.SetDomain(origDomain)
			if err != nil {
				z.GetLogger().Error("Sync FAILED for domain=%s, profile=%s, file=%s: %v", domain, profile, filePath, err)
				return err
			}
		}
		return nil
	}
	z.GetLogger().Info("No domains present in export data, not overwriting zone file %s", z.GetFilePath())
	return nil
}

// loadAndMergeExistingRecords loads existing records from the zone file and merges them into the in-memory export, unless they were explicitly removed
func (z *ZoneFormat) loadAndMergeExistingRecords(domain, filePath string) error {
	export := z.GetExportData()
	if export == nil || export.Domains == nil {
		return nil
	}
	domainData, ok := export.Domains[domain]
	if !ok || domainData == nil {
		return nil
	}

	// Build a set of existing in-memory records for fast lookup
	type recKey struct{ Hostname, Type, Target string }
	existing := make(map[recKey]struct{})
	for _, r := range domainData.Records {
		existing[recKey{r.Hostname, r.Type, r.Target}] = struct{}{}
	}

	f, err := os.Open(filePath)
	if err != nil {
		// If file doesn't exist, nothing to merge
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	zoneRecordRe := regexp.MustCompile(`^([^;\s][^\s]*)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)$`)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$ORIGIN") {
			continue
		}
		if strings.Contains(line, "SOA") || strings.Contains(line, "NS") {
			continue // skip SOA/NS
		}
		m := zoneRecordRe.FindStringSubmatch(line)
		if len(m) < 5 {
			continue
		}
		name := strings.TrimSuffix(m[1], ".")
		ttl := m[2]
		recType := m[3]
		target := m[4]
		// Only merge A, AAAA, CNAME, TXT, MX, SRV, etc. (skip SOA/NS)
		if recType == "SOA" || recType == "NS" {
			continue
		}
		// Convert name to relative if possible
		if name == domain {
			name = "@"
		}
		key := recKey{name, recType, target}
		if _, found := existing[key]; found {
			continue // already present in memory
		}
		// Parse TTL as int
		ttlInt := 300 // default
		if parsed, err := strconv.Atoi(ttl); err == nil {
			ttlInt = parsed
		}
		// Add to in-memory records
		domainData.Records = append(domainData.Records, &common.BaseRecord{
			Hostname:  name,
			Type:      recType,
			Target:    target,
			TTL:       uint32(ttlInt),
			CreatedAt: time.Now().UTC(),
		})
	}
	return scanner.Err()
}

// serializeZone handles zone-specific serialization
func (z *ZoneFormat) serializeZone(domain string, export *common.ExportData) ([]byte, error) {
	content := z.generateZoneFileContent(domain, export)
	return []byte(content), nil
}

// WriteOrUpdateRecordWithSource adds or updates a record in the file and memory
func (z *ZoneFormat) WriteOrUpdateRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	// Update in-memory (sets CreatedAt if new)
	_ = z.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
	return z.SyncDomain(domain)
}

// RemoveRecordFromFile removes a record from the file and memory, but only rewrites the file if a record was actually removed
func (z *ZoneFormat) RemoveRecordFromFile(domain, hostname, recordType string) error {
	export := z.GetExportData()
	d, ok := export.Domains[domain]
	if !ok || d == nil || len(d.Records) == 0 {
		return nil // nothing to remove
	}
	before := len(d.Records)
	_ = z.RemoveRecord(domain, hostname, recordType)
	after := len(d.Records)
	if after < before {
		return z.SyncDomain(domain)
	}
	return nil
}

// SyncDomain writes the zone file for a specific domain, updating only SOA serial and managed records, preserving unrelated/manual lines.
func (z *ZoneFormat) SyncDomain(domain string) error {
	filePath := z.GetFilePath()
	export := z.GetExportData()

	// Read the existing file into memory
	var lines []string
	if f, err := os.Open(filePath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		f.Close()
	}

	// Prepare managed records (as a map for fast lookup)
	domainData, ok := export.Domains[domain]
	if !ok || domainData == nil {
		return nil
	}
	recordMap := make(map[string]struct{})
	var managedLines []string
	for _, record := range domainData.Records {
		name := record.Hostname
		if name == "" || name == "@" {
			name = domain
		}
		key := fmt.Sprintf("%s|%s|%s", name, record.Type, record.Target)
		recordMap[key] = struct{}{}
		comment := ""
		if !record.CreatedAt.IsZero() {
			comment = fmt.Sprintf("; created_at: %s input: %s", record.CreatedAt.Format(time.RFC3339), record.Source)
		} else {
			comment = fmt.Sprintf("; input: %s", record.Source)
		}
		managedLines = append(managedLines, fmt.Sprintf("%-20s %-6d %-4s %-5s %s  %s",
			name, record.TTL, "IN", record.Type, record.Target, comment))
	}

	// Find and increment the SOA serial
	soaSerialRe := regexp.MustCompile(`^\s*([0-9]{10,})\s*;\s*Serial`)
	serial := ""
	serialLineIdx := -1
	for i, line := range lines {
		if soaSerialRe.MatchString(line) {
			m := soaSerialRe.FindStringSubmatch(line)
			if len(m) > 1 {
				serial = m[1]
				serialLineIdx = i
				break
			}
		}
	}
	newSerial := serial
	if serial != "" {
		today := time.Now().Format("20060102")
		if strings.HasPrefix(serial, today) {
			inc, err := strconv.Atoi(serial[8:])
			if err == nil {
				newSerial = fmt.Sprintf("%s%02d", today, inc+1)
			}
		} else {
			newSerial = fmt.Sprintf("%s01", today)
		}
	} else {
		// No serial found, generate a new one
		newSerial = generateSerialFromFile(filePath)
	}

	// Rewrite lines, updating SOA serial and managed records, preserving others
	var out []string
	zoneRecordRe := regexp.MustCompile(`^([^;\s][^\s]*)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)$`)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if i == serialLineIdx {
			// Replace SOA serial
			out = append(out, fmt.Sprintf("                              %-12s ; Serial", newSerial))
			continue
		}
		m := zoneRecordRe.FindStringSubmatch(line)
		if len(m) >= 5 {
			name := strings.TrimSuffix(m[1], ".")
			recType := m[3]
			target := m[4]
			if recType != "SOA" && recType != "NS" {
				key := fmt.Sprintf("%s|%s|%s", name, recType, target)
				if _, found := recordMap[key]; found {
					// This is a managed record, skip (will be replaced below)
					continue
				}
			}
		}
		out = append(out, line)
	}
	// Append all managed records at the end of the file
	if len(managedLines) > 0 {
		out = append(out, managedLines...)
	}
	// Write back only if changed
	newContent := strings.Join(out, "\n") + "\n"
	oldContent := strings.Join(lines, "\n") + "\n"
	if newContent != oldContent {
		return os.WriteFile(filePath, []byte(newContent), 0644)
	}
	return nil
}

// generateZoneFileContent creates the zone file content
func (z *ZoneFormat) generateZoneFileContent(domainName string, export *common.ExportData) string {
	var content strings.Builder

	// Add last-updated timestamp at the top
	content.WriteString(fmt.Sprintf("; Last-updated: %s\n", time.Now().Format(time.RFC3339)))

	// Get the domain data for this domain
	domain, ok := export.Domains[domainName]
	if !ok {
		return "; No records for domain " + domainName + "\n"
	}

	profile := z.CommonFormat.GetProfile()

	// Expand SOA config for this domain
	soaRaw := z.soaRaw
	primaryNS := "ns1." + domainName
	adminEmail := "admin@" + domainName
	serial := "auto"
	refresh := 3600
	retry := 900
	expire := 604800
	minimum := 300
	if soaRaw != nil {
		if v, ok := soaRaw["primary_ns"].(string); ok {
			primaryNS = expandTags(v, domainName, profile)
		}
		if v, ok := soaRaw["admin_email"].(string); ok {
			adminEmail = expandTags(v, domainName, profile)
		}
		if v, ok := soaRaw["serial"].(string); ok {
			serial = v
		}
		if v, ok := soaRaw["refresh"].(int); ok {
			refresh = v
		}
		if v, ok := soaRaw["retry"].(int); ok {
			retry = v
		}
		if v, ok := soaRaw["expire"].(int); ok {
			expire = v
		}
		if v, ok := soaRaw["minimum"].(int); ok {
			minimum = v
		}
	}
	adminEmail = strings.ReplaceAll(adminEmail, "@", ".")
	if serial == "auto" {
		filePath := z.GetFilePath()
		serial = generateSerialFromFile(filePath)
	}

	// Expand NS records for this domain
	nsRecords := make([]string, 0, len(z.nsRaw))
	for _, ns := range z.nsRaw {
		nsRecords = append(nsRecords, expandTags(ns, domainName, profile))
	}

	// Header comment with tag expansion
	header := expandTags("; Zone file for %domain%\n; Generated by herald at %date%\n\n", domainName, profile)
	content.WriteString(header)

	// Origin
	content.WriteString(fmt.Sprintf("$ORIGIN %s.\n\n", domainName))

	// SOA Record
	content.WriteString(fmt.Sprintf("%-20s IN    SOA    %s. %s. (\n", domainName+".", primaryNS, adminEmail))
	content.WriteString(fmt.Sprintf("                              %-12s ; Serial\n", serial))
	content.WriteString(fmt.Sprintf("                              %-12d ; Refresh\n", refresh))
	content.WriteString(fmt.Sprintf("                              %-12d ; Retry\n", retry))
	content.WriteString(fmt.Sprintf("                              %-12d ; Expire\n", expire))
	content.WriteString(fmt.Sprintf("                              %-12d ; Minimum\n", minimum))
	content.WriteString("                              )\n\n")

	// NS Records
	content.WriteString("; NS Records\n")
	for _, ns := range nsRecords {
		content.WriteString(fmt.Sprintf("%-20s IN    NS     %s.\n", domainName+".", ns))
	}
	content.WriteString("\n")

	// DNS Records
	content.WriteString("; DNS Records managed by herald\n")

	if domain != nil && len(domain.Records) > 0 {
		// Sort records by name for consistent output
		sort.Slice(domain.Records, func(i, j int) bool {
			if domain.Records[i].Hostname == domain.Records[j].Hostname {
				return domain.Records[i].Type < domain.Records[j].Type
			}
			return domain.Records[i].Hostname < domain.Records[j].Hostname
		})

		// Find max width for record fields to align comments
		maxRecordLen := 0
		var recordLines []string
		for _, record := range domain.Records {
			name := record.Hostname
			if name == "" || name == "@" {
				name = domainName + "."
			}
			recordStr := fmt.Sprintf("%-20s %-6d %-4s %-5s %s",
				name, record.TTL, "IN", record.Type, record.Target)
			if len(recordStr) > maxRecordLen {
				maxRecordLen = len(recordStr)
			}
			recordLines = append(recordLines, recordStr)
		}
		// Write records with aligned comments
		for i, record := range domain.Records {
			comment := ""
			if !record.CreatedAt.IsZero() {
				comment = fmt.Sprintf("; created_at: %s input: %s", record.CreatedAt.Format(time.RFC3339), record.Source)
			} else {
				comment = fmt.Sprintf("; input: %s", record.Source)
			}
			line := recordLines[i] + strings.Repeat(" ", maxRecordLen-len(recordLines[i])+2) + comment
			content.WriteString(line + "\n")
		}
	} else {
		content.WriteString("; No records\n")
	}

	return content.String()
}

// generateSerial generates a serial number in the format YYYYMMDDii, where ii is an incrementing integer for the day.
func generateSerialFromFile(filePath string) string {
	today := time.Now().Format("20060102")
	maxInc := 0

	// Try to read the current serial from the file
	f, err := os.Open(filePath)
	if err == nil {
		scanner := bufio.NewScanner(f)
		serialRe := regexp.MustCompile(`(?m)^\s*([0-9]{10,})\s*;\s*Serial`)
		for scanner.Scan() {
			line := scanner.Text()
			m := serialRe.FindStringSubmatch(line)
			if len(m) > 1 {
				serial := m[1]
				if len(serial) >= 10 && strings.HasPrefix(serial, today) {
					inc, err := strconv.Atoi(serial[8:])
					if err == nil && inc > maxInc {
						maxInc = inc
					}
				}
			}
		}
		f.Close()
	}
	// Increment for this update
	newInc := maxInc + 1
	return fmt.Sprintf("%s%02d", today, newInc)
}

// WriteRecordWithSource writes or updates a DNS record with source information
func (z *ZoneFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	z.GetLogger().Debug("WriteRecordWithSource called: domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", domain, hostname, target, recordType, ttl, source)
	defer func() {
		z.GetLogger().Debug("WriteRecordWithSource finished: domain=%s, hostname=%s, type=%s", domain, hostname, recordType)
	}()
	return z.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
}

func (z *ZoneFormat) Records() int {
	export := z.GetExportData()
	if export.Domains == nil {
		return 0
	}
	n := 0
	for _, d := range export.Domains {
		n += len(d.Records)
	}
	return n
}

// ClearRecords removes all records for a given domain from the export data
func (z *ZoneFormat) ClearRecords(domain string) {
	export := z.GetExportData()
	if export.Domains != nil {
		if d, ok := export.Domains[domain]; ok && d != nil {
			d.Records = nil
		}
	}
}
