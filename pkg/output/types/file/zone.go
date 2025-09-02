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
	"sync"
	"time"
)

// Track which domains have been loaded from files to avoid repeated loading
var (
	loadedZoneDomains = make(map[string]bool)
	loadedZoneMutex   sync.RWMutex
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
	return expandTagsWithUnderscore(path, z.CommonFormat.GetDomain(), z.CommonFormat.GetProfile())
}

// Sync writes the zone file to disk
func (z *ZoneFormat) Sync() error {
	export := z.GetExportData()
	if export != nil && export.Domains != nil {
		for domain := range export.Domains {
			// Save the original domain
			origDomain := z.CommonFormat.GetDomain()
			// Temporarily set the domain for correct file path expansion
			z.CommonFormat.SetDomain(domain)
			err := z.SyncDomain(domain)
			// Restore the original domain
			z.CommonFormat.SetDomain(origDomain)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// WriteOrUpdateRecordWithSource adds or updates a record in the file and memory
func (z *ZoneFormat) WriteOrUpdateRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	// Load existing records from file before making any changes (once per domain)
	loadKey := domain + "|" + z.GetFilePath()
	loadedZoneMutex.RLock()
	loaded := loadedZoneDomains[loadKey]
	loadedZoneMutex.RUnlock()

	if !loaded {
		filePath := z.GetFilePath()
		if fileExists(filePath) {
			z.GetLogger().Debug("Loading existing records from zone file: %s", filePath)
			if err := z.loadManagedRecordsFromFile(domain, filePath); err != nil {
				z.GetLogger().Warn("Failed to load existing records from %s: %v", filePath, err)
			} else {
				z.GetLogger().Debug("Successfully loaded existing records from %s", filePath)
			}
		}

		loadedZoneMutex.Lock()
		loadedZoneDomains[loadKey] = true
		loadedZoneMutex.Unlock()
	}

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

// SyncDomain writes the zone file for a specific domain
func (z *ZoneFormat) SyncDomain(domain string) error {
	filePath := z.GetFilePath()
	z.GetLogger().Trace("SyncDomain: Starting for domain=%s, file=%s", domain, filePath)

	// Generate the complete zone file content
	content, err := z.generateZoneFileContent(domain)
	if err != nil {
		z.GetLogger().Error("SyncDomain: Failed to generate content for domain=%s: %v", domain, err)
		return err
	}

	z.GetLogger().Trace("SyncDomain: Generated content (%d bytes) for domain=%s", len(content), domain)

	// Check if the file exists and compare content
	existingContent, readErr := os.ReadFile(filePath)
	if readErr == nil {
		if string(existingContent) == content {
			z.GetLogger().Trace("SyncDomain: No changes detected for %s, skipping write", filePath)
			return nil // No changes, do not overwrite
		}
	} else if !os.IsNotExist(readErr) {
		z.GetLogger().Error("SyncDomain: Failed to read existing file %s: %v", filePath, readErr)
		// Continue to write new content if file is unreadable for other reasons
	}

	// Write the zone file only if content changed or file does not exist
	err = os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		z.GetLogger().Error("SyncDomain: Failed to write file %s: %v", filePath, err)
	} else {
		z.GetLogger().Trace("SyncDomain: Successfully wrote file %s for domain=%s", filePath, domain)
	}

	return err
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadManagedRecordsFromFile parses the managed records from the zone file and loads them into the in-memory state
func (z *ZoneFormat) loadManagedRecordsFromFile(domain, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inManaged := false
	var records []*common.BaseRecord

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "; Managed Records" {
			inManaged = true
			continue
		}
		if !inManaged {
			continue
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, ";") {
			continue
		}
		// Parse record line: hostname TTL IN TYPE TARGET [; ...]
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue // Need at least hostname, TTL, IN, TYPE, TARGET
		}

		// Handle both formats: with and without comments
		rec := &common.BaseRecord{
			Hostname: fields[0],
			TTL:      uint32(parseTTL(fields[1])),
			Type:     fields[3],
			Target:   fields[4],
			Source:   "manual", // Default source for records without comments
		}

		// Optionally parse source from comment
		if idx := strings.Index(line, "; input: "); idx != -1 {
			source := strings.TrimSpace(line[idx+9:])
			if i := strings.Index(source, " "); i != -1 {
				source = source[:i]
			}
			rec.Source = source
		}
		// Do not overwrite with 'existing' if a source is already set

		// Optionally parse created_at from comment
		if idx := strings.Index(line, "; created_at: "); idx != -1 {
			created := strings.TrimSpace(line[idx+13:])
			if i := strings.Index(created, " "); i != -1 {
				created = created[:i]
			}
			if t, err := time.Parse(time.RFC3339, created); err == nil {
				rec.CreatedAt = t
			}
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	export := z.GetExportData()
	if export.Domains == nil {
		export.Domains = make(map[string]*common.BaseDomain)
	}

	// Use CommonFormat.WriteRecordWithSource to properly merge loaded records
	// This ensures deduplication and proper handling of existing records
	for _, rec := range records {
		if rec.Hostname != "" && rec.Type != "" && rec.Target != "" {
			// Use WriteRecordWithSource to merge, but don't trigger a file sync
			err := z.CommonFormat.WriteRecordWithSource(domain, rec.Hostname, rec.Target, rec.Type, int(rec.TTL), rec.Source)
			if err != nil {
				z.GetLogger().Warn("Failed to merge loaded record %s.%s (%s): %v", rec.Hostname, domain, rec.Type, err)
			}
		}
	}
	return nil
}

// parseTTL parses a TTL string to int
func parseTTL(s string) int {
	ttl, err := strconv.Atoi(s)
	if err != nil {
		return 300
	}
	return ttl
}

// generateZoneFileContent generates the complete zone file content
func (z *ZoneFormat) generateZoneFileContent(domain string) (string, error) {
	var lines []string

	// Add header
	now := time.Now()
	lines = append(lines, fmt.Sprintf("; Last-updated: %s", now.Format(time.RFC3339)))
	lines = append(lines, fmt.Sprintf("; Zone file for %s", domain))
	lines = append(lines, fmt.Sprintf("; Generated by herald at %s", now.Format("20060102-150405")))
	lines = append(lines, "")

	// Add $ORIGIN directive
	lines = append(lines, fmt.Sprintf("$ORIGIN %s.", domain))
	lines = append(lines, "$TTL 300")
	lines = append(lines, "")

	// Generate SOA record
	soa, err := z.generateSOARecord(domain)
	if err != nil {
		return "", err
	}
	lines = append(lines, soa...)
	lines = append(lines, "")

	// Generate NS records
	nsRecords := z.generateNSRecords(domain)
	lines = append(lines, nsRecords...)
	lines = append(lines, "")

	// Generate managed records
	managedRecords := z.generateManagedRecords(domain)
	if len(managedRecords) > 0 {
		lines = append(lines, "; Managed Records")
		lines = append(lines, managedRecords...)
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// generateSOARecord generates SOA record with incremented serial
func (z *ZoneFormat) generateSOARecord(domain string) ([]string, error) {
	// Get current serial and increment it
	currentSerial := z.getCurrentSerial()
	newSerial := z.incrementSerial(currentSerial)
	z.GetLogger().Trace("SOA: Current=%s, New=%s", currentSerial, newSerial)

	// Expand SOA config for this domain
	soa := z.expandSOAConfig(domain)

	// Format admin email for SOA (replace first '@' with '.' and ensure trailing dot)
	adminEmail := strings.Replace(soa.AdminEmail, "@", ".", 1)
	if !strings.HasSuffix(adminEmail, ".") {
		adminEmail += "."
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("%-20s %-6d %-4s %-5s %s %s (", "@", 300, "IN", "SOA", soa.PrimaryNS, adminEmail))
	lines = append(lines, fmt.Sprintf("                              %-12s   ; Serial", newSerial))
	lines = append(lines, fmt.Sprintf("                              %-12d   ; Refresh", soa.Refresh))
	lines = append(lines, fmt.Sprintf("                              %-12d   ; Retry", soa.Retry))
	lines = append(lines, fmt.Sprintf("                              %-12d   ; Expire", soa.Expire))
	lines = append(lines, fmt.Sprintf("                              %-12d   ; Minimum", soa.Minimum))
	lines = append(lines, "                              )")

	return lines, nil
}

// expandSOAConfig expands the SOA configuration for a specific domain
func (z *ZoneFormat) expandSOAConfig(domain string) SOARecord {
	soa := SOARecord{
		PrimaryNS:  "ns1.example.com.",
		AdminEmail: "admin.example.com.",
		Refresh:    3600,
		Retry:      1800,
		Expire:     604800,
		Minimum:    300,
	}

	if z.soaRaw != nil {
		if v, ok := z.soaRaw["primary_ns"].(string); ok {
			soa.PrimaryNS = expandTags(v, domain, z.CommonFormat.GetProfile())
		}
		if v, ok := z.soaRaw["admin_email"].(string); ok {
			soa.AdminEmail = expandTags(v, domain, z.CommonFormat.GetProfile())
		}
		if v, ok := z.soaRaw["refresh"].(int); ok {
			soa.Refresh = v
		}
		if v, ok := z.soaRaw["retry"].(int); ok {
			soa.Retry = v
		}
		if v, ok := z.soaRaw["expire"].(int); ok {
			soa.Expire = v
		}
		if v, ok := z.soaRaw["minimum"].(int); ok {
			soa.Minimum = v
		}
	}

	return soa
}

// getCurrentSerial reads the current serial from the existing zone file
func (z *ZoneFormat) getCurrentSerial() string {
	filePath := z.GetFilePath()
	z.GetLogger().Trace("getCurrentSerial: Reading from file=%s", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		z.GetLogger().Trace("getCurrentSerial: Cannot open file %s: %v", filePath, err)
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	serialRe := regexp.MustCompile(`^\s*([0-9]{10,})\s*;\s*Serial`)
	for scanner.Scan() {
		line := scanner.Text()
		if matches := serialRe.FindStringSubmatch(line); len(matches) > 1 {
			z.GetLogger().Trace("getCurrentSerial: Found serial=%s in file=%s", matches[1], filePath)
			return matches[1]
		}
	}

	z.GetLogger().Trace("getCurrentSerial: No serial found in file=%s", filePath)
	return ""
}

// incrementSerial increments the serial number using YYYYMMDDnn format
func (z *ZoneFormat) incrementSerial(currentSerial string) string {
	today := time.Now().Format("20060102")
	z.GetLogger().Trace("incrementSerial: today=%s, currentSerial=%s", today, currentSerial)

	if currentSerial == "" {
		newSerial := fmt.Sprintf("%s01", today)
		z.GetLogger().Trace("incrementSerial: No current serial, returning new=%s", newSerial)
		return newSerial
	}

	// Check if current serial is from today
	if len(currentSerial) >= 10 && strings.HasPrefix(currentSerial, today) {
		// Extract increment part and increment it
		if inc, err := strconv.Atoi(currentSerial[8:]); err == nil {
			newInc := inc + 1
			var newSerial string
			if newInc >= 100 {
				newSerial = fmt.Sprintf("%s%d", today, newInc)
			} else {
				newSerial = fmt.Sprintf("%s%02d", today, newInc)
			}
			z.GetLogger().Trace("incrementSerial: Incremented from=%s to=%s (inc %d->%d)", currentSerial, newSerial, inc, newInc)
			return newSerial
		} else {
			z.GetLogger().Trace("incrementSerial: Failed to parse increment from=%s: %v", currentSerial, err)
		}
	} else {
		z.GetLogger().Trace("incrementSerial: Serial %s not from today or wrong format, resetting", currentSerial)
	}

	// Not from today or parsing failed, start fresh
	newSerial := fmt.Sprintf("%s01", today)
	z.GetLogger().Trace("incrementSerial: Reset to new=%s", newSerial)
	return newSerial
}

// generateNSRecords generates NS records
func (z *ZoneFormat) generateNSRecords(domain string) []string {
	var lines []string
	for _, ns := range z.nsRaw {
		expandedNS := expandTags(ns, domain, z.CommonFormat.GetProfile())
		lines = append(lines, fmt.Sprintf("%-20s %-6d %-4s %-5s %s", "@", 300, "IN", "NS", expandedNS))
	}
	return lines
}

// generateManagedRecords generates the managed DNS records from in-memory state merged with existing file records
func (z *ZoneFormat) generateManagedRecords(domain string) []string {
	var lines []string

	export := z.GetExportData()
	if export == nil || export.Domains == nil {
		return lines
	}
	domainData, ok := export.Domains[domain]
	if !ok || domainData == nil {
		return lines
	}

	// Create a map to track all records by unique key (hostname + type)
	recordMap := make(map[string]*common.BaseRecord)

	// First, load existing records from the file to preserve manual records
	filePath := z.GetFilePath()
	if fileExists(filePath) {
		existingRecords := z.loadRecordsFromManagedSection(domain, filePath)
		for _, record := range existingRecords {
			key := record.Hostname + ":" + record.Type
			recordMap[key] = record
		}
		z.GetLogger().Debug("generateManagedRecords: Loaded %d existing records from file for domain %s", len(existingRecords), domain)
	}

	// Then overlay/update with in-memory records from Herald providers
	for _, record := range domainData.Records {
		key := record.Hostname + ":" + record.Type
		recordMap[key] = record // This will overwrite existing records with same hostname+type
	}
	z.GetLogger().Debug("generateManagedRecords: Final record count for domain %s: %d", domain, len(recordMap))

	// Convert map to slice for sorting
	records := make([]*common.BaseRecord, 0, len(recordMap))
	for _, record := range recordMap {
		records = append(records, record)
	}

	// Sorting logic based on config
	sortKey := "host"
	sortOrder := "asc"
	if z.CommonFormat != nil && z.CommonFormat.GetConfig() != nil {
		if sortCfg, ok := z.CommonFormat.GetConfig()["sort"].(map[string]interface{}); ok {
			if k, ok := sortCfg["key"].(string); ok && k != "" {
				sortKey = k
			}
			if o, ok := sortCfg["order"].(string); ok && o != "" {
				sortOrder = o
			}
		}
	}
	// Always default to host/asc if not set or invalid
	if sortKey != "host" && sortKey != "ip" && sortKey != "input" {
		sortKey = "host"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}
	less := func(i, j int) bool { return false }
	switch sortKey {
	case "host":
		less = func(i, j int) bool {
			return records[i].Hostname < records[j].Hostname
		}
	case "ip":
		less = func(i, j int) bool {
			if sortOrder == "desc" {
				return records[i].Target > records[j].Target
			}
			return records[i].Target < records[j].Target
		}
	case "input":
		less = func(i, j int) bool {
			if sortOrder == "desc" {
				return records[i].Source > records[j].Source
			}
			return records[i].Source < records[j].Source
		}
	}
	if sortKey == "host" || sortOrder == "asc" {
		// Always sort host ascending by default
		sort.Slice(records, func(i, j int) bool { return records[i].Hostname < records[j].Hostname })
	} else if len(records) > 1 {
		sort.Slice(records, less)
	}

	// Generate output lines from the sorted record slice
	for _, record := range records {
		hostname := record.Hostname
		if hostname == "" || hostname == "@" {
			hostname = "@"
		}
		comment := ""
		if !record.CreatedAt.IsZero() {
			comment = fmt.Sprintf("; created_at: %s input: %s",
				record.CreatedAt.Format(time.RFC3339), record.Source)
		} else {
			comment = fmt.Sprintf("; input: %s", record.Source)
		}
		line := fmt.Sprintf("%-20s %-6d %-4s %-5s %-15s %s",
			hostname, record.TTL, "IN", record.Type, record.Target, comment)
		lines = append(lines, line)
	}
	return lines
}

// WriteRecordWithSource writes or updates a DNS record with source information
func (z *ZoneFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	z.GetLogger().Debug("WriteRecordWithSource called: domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", domain, hostname, target, recordType, ttl, source)
	defer func() {
		z.GetLogger().Debug("WriteRecordWithSource finished: domain=%s, hostname=%s, type=%s", domain, hostname, recordType)
	}()

	// Load existing records from file before making any changes (once per domain)
	loadKey := domain + "|" + z.GetFilePath()
	loadedZoneMutex.RLock()
	loaded := loadedZoneDomains[loadKey]
	loadedZoneMutex.RUnlock()

	// Count current records before loading
	export := z.GetExportData()
	currentCount := 0
	if export != nil && export.Domains != nil {
		if domainData, ok := export.Domains[domain]; ok && domainData != nil {
			currentCount = len(domainData.Records)
		}
	}
	z.GetLogger().Debug("WriteRecordWithSource: domain=%s, loaded=%v, currentRecords=%d", domain, loaded, currentCount)

	if !loaded {
		filePath := z.GetFilePath()
		if fileExists(filePath) {
			z.GetLogger().Info("Loading existing records from zone file: %s (currentRecords=%d)", filePath, currentCount)
			if err := z.loadManagedRecordsFromFile(domain, filePath); err != nil {
				z.GetLogger().Warn("Failed to load existing records from %s: %v", filePath, err)
			} else {
				// Count records after loading
				afterCount := 0
				if export != nil && export.Domains != nil {
					if domainData, ok := export.Domains[domain]; ok && domainData != nil {
						afterCount = len(domainData.Records)
					}
				}
				z.GetLogger().Info("Successfully loaded existing records from %s (before=%d, after=%d)", filePath, currentCount, afterCount)
			}
		}

		loadedZoneMutex.Lock()
		loadedZoneDomains[loadKey] = true
		loadedZoneMutex.Unlock()
	}

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

// loadRecordsFromManagedSection loads records specifically from the managed section of the zone file
func (z *ZoneFormat) loadRecordsFromManagedSection(domain, filePath string) []*common.BaseRecord {
	var records []*common.BaseRecord

	content, err := os.ReadFile(filePath)
	if err != nil {
		z.GetLogger().Warn("Failed to read zone file %s: %v", filePath, err)
		return records
	}

	lines := strings.Split(string(content), "\n")
	inManagedSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for managed section markers
		if strings.Contains(line, "; Managed Records") {
			inManagedSection = true
			continue
		}
		if strings.Contains(line, "; End Managed Records") {
			inManagedSection = false
			continue
		}

		// Skip non-managed sections and empty/comment lines
		if !inManagedSection || line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse the record line
		if record := z.parseRecordLine(line, domain); record != nil {
			records = append(records, record)
		}
	}

	return records
}

// parseRecordLine parses a single DNS record line and returns a BaseRecord
func (z *ZoneFormat) parseRecordLine(line, domain string) *common.BaseRecord {
	// Handle typical zone file format: hostname TTL class type target [comment]
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	hostname := fields[0]
	ttl, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil
	}

	// fields[2] should be "IN" (class)
	recordType := fields[3]
	target := fields[4]

	// Determine source from comment if available
	source := "manual" // default for records without source info
	for i := 5; i < len(fields); i++ {
		if strings.Contains(fields[i], "input:") && i+1 < len(fields) {
			source = fields[i+1]
			break
		}
	}

	return &common.BaseRecord{
		Hostname:  hostname,
		Type:      recordType,
		Target:    target,
		TTL:       uint32(ttl),
		Source:    source,
		CreatedAt: time.Now(), // Set current time for parsed records
	}
}
