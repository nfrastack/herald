// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"bufio"
	"fmt"
	"herald/pkg/output/common"
	"os"
	"sort"
	"strings"
	"time"
)

// ZoneFormat implements OutputFormat for DNS zone files
type ZoneFormat struct {
	*common.CommonFormat
	soaRaw map[string]interface{} // store raw SOA config for per-domain expansion
	nsRaw  []string               // store raw NS config for per-domain expansion
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

	format := &ZoneFormat{
		CommonFormat: commonFormat,
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

// GetFilePath returns the expanded file path for this zone file for a given domain
func (z *ZoneFormat) GetFilePath(domain string) string {
	path := "zone_%domain_underscore%.zone" // default fallback
	if z.CommonFormat != nil && z.CommonFormat.GetConfig() != nil {
		if p, ok := z.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTagsWithUnderscore(path, domain, z.CommonFormat.GetProfile())
}

// ReloadFromDisk parses the zone file and updates in-memory export data
func (z *ZoneFormat) ReloadFromDisk(domain string) error {
	filePath := z.GetFilePath(domain)
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No file to reload
		}
		return err
	}
	defer file.Close()

	export := z.GetExportData()
	if export.Domains == nil {
		export.Domains = make(map[string]*common.BaseDomain)
	}
	if _, ok := export.Domains[domain]; !ok {
		export.Domains[domain] = &common.BaseDomain{Records: []*common.BaseRecord{}}
	}
	d := export.Domains[domain]
	d.Records = []*common.BaseRecord{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Try to parse: name ttl IN type target
		name := fields[0]
		// skip SOA/NS
		if fields[3] == "SOA" || fields[3] == "NS" {
			continue
		}
		ttl := uint32(60)
		typeStr := fields[3]
		target := fields[4]
		hostname := name
		if strings.HasSuffix(hostname, "."+domain+".") {
			hostname = strings.TrimSuffix(hostname, "."+domain+".")
		} else if name == domain+"." {
			hostname = "@"
		}
		d.Records = append(d.Records, &common.BaseRecord{
			Hostname: hostname,
			Type:     typeStr,
			Target:   target,
			TTL:      ttl,
			Source:   "manual", // unknown source
		})
	}
	return scanner.Err()
}

// WriteOrUpdateRecordWithSource adds or updates a record in the file and memory
func (z *ZoneFormat) WriteOrUpdateRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	if err := z.ReloadFromDisk(domain); err != nil {
		return err
	}
	// Update in-memory
	_ = z.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
	// Increment SOA serial on any update
	z.incrementSOASerial(domain)
	// Now update file: for now, rewrite whole file (TODO: optimize to update line)
	return z.SyncDomain(domain)
}

// RemoveRecordFromFile removes a record from the file and memory, but only rewrites the file if a record was actually removed
func (z *ZoneFormat) RemoveRecordFromFile(domain, hostname, recordType string) error {
	if err := z.ReloadFromDisk(domain); err != nil {
		return err
	}
	export := z.GetExportData()
	d, ok := export.Domains[domain]
	if !ok || d == nil || len(d.Records) == 0 {
		return nil // nothing to remove
	}
	before := len(d.Records)
	_ = z.RemoveRecord(domain, hostname, recordType)
	after := len(d.Records)
	if after < before {
		z.incrementSOASerial(domain)
		return z.SyncDomain(domain) // only rewrite if something was removed
	}
	return nil // do nothing if no record was removed
}

// incrementSOASerial increments the SOA serial for the domain
func (z *ZoneFormat) incrementSOASerial(domain string) {
	if z.soaRaw == nil {
		z.soaRaw = make(map[string]interface{})
	}
	serial, ok := z.soaRaw["serial"].(string)
	if !ok || serial == "auto" {
		z.soaRaw["serial"] = nextSerial(z.soaRaw["serial"])
	} else {
		z.soaRaw["serial"] = nextSerial(serial)
	}
}

// nextSerial returns the next serial number in YYYYMMDDnn format
func nextSerial(current interface{}) string {
	now := time.Now()
	datePrefix := now.Format("20060102")
	if s, ok := current.(string); ok && len(s) >= 10 && strings.HasPrefix(s, datePrefix) {
		// increment nn
		nn := s[8:]
		var n int
		fmt.Sscanf(nn, "%02d", &n)
		if n < 99 {
			n++
			return datePrefix + fmt.Sprintf("%02d", n)
		}
	}
	return datePrefix + "01"
}

// SyncDomain writes the zone file for a specific domain
func (z *ZoneFormat) SyncDomain(domain string) error {
	filePath := z.GetFilePath(domain)
	export := z.GetExportData()
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	content := z.generateZoneFileContent(domain, export)
	_, err = f.WriteString(content)
	return err
}

// SyncAllDomains writes all zone files for all domains
func (z *ZoneFormat) SyncAllDomains() error {
	export := z.GetExportData()
	if export.Domains == nil {
		return nil
	}
	for domain := range export.Domains {
		if err := z.SyncDomain(domain); err != nil {
			return err
		}
	}
	return nil
}

// Sync implements OutputFormat and writes all domains
func (z *ZoneFormat) Sync() error {
	return z.SyncAllDomains()
}

// serializeZone handles zone-specific serialization
func (z *ZoneFormat) serializeZone(domain string, export *common.ExportData) ([]byte, error) {
	content := z.generateZoneFileContent(domain, export)
	return []byte(content), nil
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
		serial = generateSerial()
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

		for _, record := range domain.Records {
			name := record.Hostname
			if name == "" || name == "@" {
				name = domainName + "."
			}
			// Add per-record created timestamp as comment if available
			if !record.CreatedAt.IsZero() {
				content.WriteString(fmt.Sprintf("; created_at: %s\n", record.CreatedAt.Format(time.RFC3339)))
			}
			content.WriteString(fmt.Sprintf("%-20s %-6d %-4s %-5s %s\n",
				name, record.TTL, "IN", record.Type, record.Target))
		}
	} else {
		content.WriteString("; No records\n")
	}

	return content.String()
}

// generateSerial generates an auto-incrementing serial number
func generateSerial() string {
	now := time.Now()
	return fmt.Sprintf("%04d%02d%02d%02d", now.Year(), now.Month(), now.Day(), now.Hour())
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

// RemoveRecords removes records for a given domain matching the provided filter (by source, hostname, type)
func (z *ZoneFormat) RemoveRecords(domain, hostname, recordType, source string) {
	export := z.GetExportData()
	if export.Domains == nil {
		return
	}
	d, ok := export.Domains[domain]
	if !ok || d == nil || len(d.Records) == 0 {
		return
	}
	filtered := make([]*common.BaseRecord, 0, len(d.Records))
	for _, rec := range d.Records {
		if (hostname != "" && rec.Hostname != hostname) ||
			(recordType != "" && rec.Type != recordType) ||
			(source != "" && rec.Source != source) {
			filtered = append(filtered, rec)
		}
	}
	d.Records = filtered
}

// RemoveRecord removes all records for a given domain, hostname, and type (regardless of source)
func (z *ZoneFormat) RemoveRecord(domain, hostname, recordType string) error {
	z.RemoveRecords(domain, hostname, recordType, "")
	return nil
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
