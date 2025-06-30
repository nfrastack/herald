// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/output/common"

	"fmt"
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

// serializeZone handles zone-specific serialization
func (z *ZoneFormat) serializeZone(domain string, export *common.ExportData) ([]byte, error) {
	content := z.generateZoneFileContent(domain, export)
	return []byte(content), nil
}

// generateZoneFileContent creates the zone file content
func (z *ZoneFormat) generateZoneFileContent(domainName string, export *common.ExportData) string {
	var content strings.Builder

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

// ClearRecords removes all records for a given domain from the export data
func (z *ZoneFormat) ClearRecords(domain string) {
	export := z.GetExportData()
	if export.Domains != nil {
		if d, ok := export.Domains[domain]; ok && d != nil {
			d.Records = nil
		}
	}
}
