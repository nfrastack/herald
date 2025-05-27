// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package formats

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"

	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ZoneFormat implements OutputFormat for BIND zone files
type ZoneFormat struct {
	*output.BaseFormat
	domain    string
	records   map[string]*ZoneRecord // key: hostname:type
	config    ZoneConfig
	serialNum uint32
}

// ZoneConfig holds configuration specific to zone files
type ZoneConfig struct {
	SOA       SOAConfig // SOA record configuration
	NSRecords []string  // NS records for the zone
}

// SOAConfig holds SOA record configuration
type SOAConfig struct {
	PrimaryNS  string // Primary nameserver
	AdminEmail string // Admin email (converted to zone format)
	Serial     string // Serial number or "auto"
	Refresh    uint32 // Refresh interval
	Retry      uint32 // Retry interval
	Expire     uint32 // Expire time
	Minimum    uint32 // Minimum TTL
}

// ZoneRecord represents a DNS record in the zone file
type ZoneRecord struct {
	Hostname string
	Type     string
	Target   string
	TTL      uint32
	Source   string // Source that created this record
}

// NewZoneFormat creates a new zone file format instance
func NewZoneFormat(domain string, config map[string]interface{}) (output.OutputFormat, error) {
	base, _, err := output.NewBaseFormat(domain, "zone", config)
	if err != nil {
		return nil, err
	}

	zoneConfig := ZoneConfig{
		SOA: SOAConfig{
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minimum: 300,
		},
	}

	// Parse SOA configuration
	if soaMap, ok := config["soa"].(map[string]interface{}); ok {
		if primaryNS, ok := soaMap["primary_ns"].(string); ok {
			zoneConfig.SOA.PrimaryNS = primaryNS
		}
		if adminEmail, ok := soaMap["admin_email"].(string); ok {
			zoneConfig.SOA.AdminEmail = adminEmail
		}
		if serial, ok := soaMap["serial"].(string); ok {
			zoneConfig.SOA.Serial = serial
		}
		if refresh, ok := soaMap["refresh"].(int); ok {
			zoneConfig.SOA.Refresh = uint32(refresh)
		}
		if retry, ok := soaMap["retry"].(int); ok {
			zoneConfig.SOA.Retry = uint32(retry)
		}
		if expire, ok := soaMap["expire"].(int); ok {
			zoneConfig.SOA.Expire = uint32(expire)
		}
		if minimum, ok := soaMap["minimum"].(int); ok {
			zoneConfig.SOA.Minimum = uint32(minimum)
		}
	}

	// Parse NS records
	if nsRecords, ok := config["ns_records"].([]interface{}); ok {
		for _, ns := range nsRecords {
			if nsStr, ok := ns.(string); ok {
				zoneConfig.NSRecords = append(zoneConfig.NSRecords, nsStr)
			}
		}
	}

	format := &ZoneFormat{
		BaseFormat: base,
		domain:     domain,
		records:    make(map[string]*ZoneRecord),
		config:     zoneConfig,
		serialNum:  generateSerial(),
	}

	log.Debug("%s Initialized zone file format: %s", format.GetLogPrefix(), format.GetFilePath())

	// Create empty file if it doesn't exist, then set ownership
	if err := format.EnsureFileAndSetOwnership(); err != nil {
		log.Warn("%s Failed to ensure file and set ownership: %v", format.GetLogPrefix(), err)
	}

	return format, nil
}

// GetName returns the format name
func (z *ZoneFormat) GetName() string {
	return "zone"
}

// WriteRecord writes or updates a DNS record
func (z *ZoneFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return z.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "dns-companion")
}

// WriteRecordWithSource writes or updates a DNS record with source information
func (z *ZoneFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	z.Lock()
	defer z.Unlock()

	// Normalize hostname for zone file
	if hostname == "@" || hostname == domain {
		hostname = "@"
	} else if len(hostname) > 0 && hostname != "@" {
		// Remove domain suffix if present
		if strings.HasSuffix(hostname, "."+domain) {
			hostname = strings.TrimSuffix(hostname, "."+domain)
		}
	}

	key := fmt.Sprintf("%s:%s", hostname, recordType)

	// Check if record already exists
	existingRecord := z.records[key]
	if existingRecord != nil {
		// Update existing record
		existingRecord.Target = target
		existingRecord.TTL = uint32(ttl)
		existingRecord.Source = source
		log.Verbose("[output/zone/%s] Updated record: %s.%s (%s) -> %s", source, hostname, domain, recordType, target)
	} else {
		// Create new record
		z.records[key] = &ZoneRecord{
			Hostname: hostname,
			Type:     recordType,
			Target:   target,
			TTL:      uint32(ttl),
			Source:   source,
		}
		log.Verbose("[output/zone/%s] Added record: %s.%s (%s) -> %s", source, hostname, domain, recordType, target)
	}

	return nil
}

// RemoveRecord removes a DNS record
func (z *ZoneFormat) RemoveRecord(domain, hostname, recordType string) error {
	z.Lock()
	defer z.Unlock()

	// Normalize hostname
	if hostname == "@" || hostname == domain {
		hostname = "@"
	} else if len(hostname) > 0 && hostname != "@" {
		if strings.HasSuffix(hostname, "."+domain) {
			hostname = strings.TrimSuffix(hostname, "."+domain)
		}
	}

	key := fmt.Sprintf("%s:%s", hostname, recordType)

	if _, exists := z.records[key]; exists {
		delete(z.records, key)
		log.Trace("%s Removed record: %s (%s)", z.GetLogPrefix(), hostname, recordType)
	}

	return nil
}

// Sync writes the zone file to disk
func (z *ZoneFormat) Sync() error {
	z.Lock()
	defer z.Unlock()

	// Create directory if it doesn't exist
	if err := z.EnsureDirectory(); err != nil {
		return err
	}

	// Generate zone file content
	content := z.generateZoneFile()

	// Write to file with proper permissions
	if err := os.WriteFile(z.GetFilePath(), []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write zone file: %v", err)
	}
	log.Trace("%s fsnotify event: Name='%s', Op=WRITE", z.GetLogPrefix(), z.GetFilePath())

	log.Trace("%s fsnotify event: Name='%s', Op=WRITE", z.GetLogPrefix(), z.GetFilePath())
	log.Debug("%s Generated zone file with %d records: %s", z.GetLogPrefix(), len(z.records), z.GetFilePath())
	return nil
}

// generateZoneFile creates the zone file content
func (z *ZoneFormat) generateZoneFile() string {
	var content strings.Builder

	// Zone file header
	content.WriteString(fmt.Sprintf(";\n; Zone file for %s\n", z.domain))
	content.WriteString(fmt.Sprintf("; Generated by dns-companion on %s\n;\n", time.Now().Format(time.RFC3339)))

	// $ORIGIN directive (no more $TTL since each record has its own)
	content.WriteString(fmt.Sprintf("$ORIGIN %s.\n\n", z.domain))

	// SOA record
	content.WriteString(z.generateSOARecord())
	content.WriteString("\n")

	// NS records
	if len(z.config.NSRecords) > 0 {
		content.WriteString("; Name servers\n")
		for _, ns := range z.config.NSRecords {
			content.WriteString(fmt.Sprintf("@\tIN\tNS\t%s.\n", ns))
		}
		content.WriteString("\n")
	}

	// DNS records grouped by type
	content.WriteString("; DNS records\n")
	content.WriteString(z.generateRecordsByType())

	return content.String()
}

// generateSOARecord creates the SOA record
func (z *ZoneFormat) generateSOARecord() string {
	serial := z.getSerial()
	adminEmail := strings.ReplaceAll(z.config.SOA.AdminEmail, "@", ".")

	return fmt.Sprintf(`; SOA record
@	IN	SOA	%s. %s. (
		%-12s	; Serial
		%-12d	; Refresh
		%-12d	; Retry
		%-12d	; Expire
		%-12d	; Minimum
)`,
		z.config.SOA.PrimaryNS,
		adminEmail,
		serial,
		z.config.SOA.Refresh,
		z.config.SOA.Retry,
		z.config.SOA.Expire,
		z.config.SOA.Minimum,
	)
}

// generateRecordsByType creates records grouped by type
func (z *ZoneFormat) generateRecordsByType() string {
	if len(z.records) == 0 {
		return "; No records\n"
	}

	// Group records by type
	recordsByType := make(map[string][]*ZoneRecord)
	for _, record := range z.records {
		recordsByType[record.Type] = append(recordsByType[record.Type], record)
	}

	// Sort types for consistent output
	var types []string
	for recordType := range recordsByType {
		types = append(types, recordType)
	}
	sort.Strings(types)

	var content strings.Builder
	for _, recordType := range types {
		records := recordsByType[recordType]

		// Sort records within type by hostname
		sort.Slice(records, func(i, j int) bool {
			return records[i].Hostname < records[j].Hostname
		})

		content.WriteString(fmt.Sprintf("; %s records\n", recordType))
		for _, record := range records {
			if record.Source != "" && record.Source != "dns-companion" {
				content.WriteString(fmt.Sprintf("%s\t%d\tIN\t%s\t%s\t; source: %s\n",
					record.Hostname, record.TTL, record.Type, record.Target, record.Source))
			} else {
				content.WriteString(fmt.Sprintf("%s\t%d\tIN\t%s\t%s\n",
					record.Hostname, record.TTL, record.Type, record.Target))
			}
		}
		content.WriteString("\n")
	}

	return content.String()
}

// getSerial returns the serial number for the SOA record
func (z *ZoneFormat) getSerial() string {
	if z.config.SOA.Serial == "auto" {
		return strconv.FormatUint(uint64(z.serialNum), 10)
	}
	return z.config.SOA.Serial
}

// generateSerial creates an auto-incrementing serial number in YYYYMMDDNN format
func generateSerial() uint32 {
	now := time.Now()
	dateStr := now.Format("20060102")

	increment := uint32(now.Hour()*100 + now.Minute())
	if increment > 99 {
		increment = increment % 100
	}

	dateNum, _ := strconv.ParseUint(dateStr, 10, 32)
	return uint32(dateNum)*100 + increment
}

// init registers this format
func init() {
	// Import output package to register this format
	output.RegisterFormat("zone", NewZoneFormat)
}
