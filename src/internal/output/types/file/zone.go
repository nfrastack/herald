// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"github.com/nfrastack/herald/internal/output/common"

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

var (
	loadedZoneDomains = make(map[string]bool)
	loadedZoneMutex   sync.RWMutex
)

type ZoneFormat struct {
	*common.CommonFormat
	soaRaw        map[string]interface{} // store raw SOA config for per-domain expansion
	nsRaw         []string               // store raw NS config for per-domain expansion
	staticMu      sync.Mutex
	staticLines   map[string][]string
	migratedFiles map[string]bool
}

type SOARecord struct {
	PrimaryNS  string
	AdminEmail string
	Serial     string
	Refresh    int
	Retry      int
	Expire     int
	Minimum    int
}

func NewZoneFormat(profileName, domain string, config map[string]interface{}) (OutputFormat, error) {
	commonFormat, err := common.NewCommonFormat(profileName, "zone", config)
	if err != nil {
		return nil, err
	}

	format := &ZoneFormat{
		CommonFormat:  commonFormat,
		staticLines:   make(map[string][]string),
		migratedFiles: make(map[string]bool),
	}

	if err := format.parseSOAConfig(config); err != nil {
		return nil, fmt.Errorf("failed to parse SOA config: %v", err)
	}

	if err := format.parseNSConfig(config); err != nil {
		return nil, fmt.Errorf("failed to parse NS config: %v", err)
	}

	return format, nil
}

func (z *ZoneFormat) parseSOAConfig(config map[string]interface{}) error {
	soaConfig, ok := config["soa"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("soa configuration is required")
	}
	z.soaRaw = soaConfig
	return nil
}

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

func (z *ZoneFormat) GetName() string {
	return "zone"
}

func (z *ZoneFormat) GetFilePath() string {
	path := "zone_%domain_underscore%.zone" // default fallback
	if z.CommonFormat != nil && z.CommonFormat.GetConfig() != nil {
		if p, ok := z.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTagsWithUnderscore(path, z.CommonFormat.GetDomain(), z.CommonFormat.GetProfile())
}

func (z *ZoneFormat) Sync() error {
	export := z.GetExportData()
	if export != nil && export.Domains != nil {
		for domain := range export.Domains {
			origDomain := z.CommonFormat.GetDomain()
			z.CommonFormat.SetDomain(domain)
			err := z.SyncDomain(domain)
			z.CommonFormat.SetDomain(origDomain)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (z *ZoneFormat) SyncDomain(domain string) error {
	filePath := z.GetFilePath()
	z.GetLogger().Trace("SyncDomain: Starting for domain=%s, file=%s", domain, filePath)

	var existingContent string
	if fileExists(filePath) {
		if raw, readErr := os.ReadFile(filePath); readErr == nil {
			existingContent = string(raw)
		} else if !os.IsNotExist(readErr) {
			z.GetLogger().Error("SyncDomain: Failed to read existing file %s: %v", filePath, readErr)
		}
	}
	staticLines := z.staticLinesForFile(filePath, existingContent, domain)

	newManaged := normalizeManagedLines(z.generateManagedRecords(domain))
	newStatic := normalizeManagedLines(filterStaticCollisions(z, domain, staticLines, z.generateManagedRecords(domain)))
	if existingContent != "" {
		existingManaged := extractManagedLines(existingContent)
		existingStatic := extractStaticLines(existingContent)
		if managedLinesEqual(existingManaged, newManaged) && managedLinesEqual(existingStatic, newStatic) {
			z.GetLogger().Trace("SyncDomain: No record changes detected for %s, skipping write", filePath)
			return nil
		}
	}

	newSerial := z.incrementSerial(z.getCurrentSerial())
	content, err := z.generateZoneFileContent(domain, staticLines, z.generateManagedRecords(domain), newSerial)
	if err != nil {
		z.GetLogger().Error("SyncDomain: Failed to generate content for domain=%s: %v", domain, err)
		return err
	}

	z.GetLogger().Trace("SyncDomain: Generated content (%d bytes) for domain=%s", len(content), domain)

	err = os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		z.GetLogger().Error("SyncDomain: Failed to write file %s: %v", filePath, err)
	} else {
		z.GetLogger().Trace("SyncDomain: Successfully wrote file %s for domain=%s", filePath, domain)
	}

	return err
}

func (z *ZoneFormat) staticLinesForFile(filePath, existingContent, domain string) []string {
	z.staticMu.Lock()
	defer z.staticMu.Unlock()

	static := append([]string(nil), extractStaticRawLines(existingContent)...)

	if existingContent != "" && !z.migratedFiles[filePath] {
		z.migratedFiles[filePath] = true
		for _, line := range extractManagedRawLines(existingContent) {
			host, rtype, source := parseZoneRecordLine(line)
			if host == "" || rtype == "" {
				continue
			}
			if isManualSource(source) {
				static = append(static, line)
				z.GetLogger().Info("Migrating legacy manual record to static section in %s: %s", filePath, strings.Join(strings.Fields(line), " "))
			}
		}
		z.dropFileRecordsBySource(domain)
	}
	z.staticLines[filePath] = static
	return append([]string(nil), static...)
}

func (z *ZoneFormat) dropFileRecordsBySource(domain string) {
	export := z.GetExportData()
	if export == nil || export.Domains == nil {
		return
	}
	domainData, ok := export.Domains[domain]
	if !ok || domainData == nil {
		return
	}
	snapshot := append([]*common.BaseRecord(nil), domainData.Records...)
	for _, r := range snapshot {
		if isManualSource(r.Source) {
			_ = z.CommonFormat.RemoveRecord(domain, r.Hostname, r.Type)
		}
	}
}

func isManualSource(source string) bool {
	s := strings.ToLower(strings.TrimSpace(source))
	return s == "" || s == "manual"
}

func parseZoneRecordLine(line string) (hostname, recordType, source string) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return "", "", ""
	}
	source = "manual"
	for i := 5; i < len(fields); i++ {
		if strings.Contains(fields[i], "input:") && i+1 < len(fields) {
			source = fields[i+1]
			break
		}
	}
	return fields[0], fields[3], source
}

func extractStaticRawLines(content string) []string {
	var lines []string
	inStatic := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "; Static Records" {
			inStatic = true
			continue
		}
		if trimmed == "; Managed Records" {
			break
		}
		if !inStatic {
			continue
		}
		lines = append(lines, line)
	}
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func extractManagedRawLines(content string) []string {
	var lines []string
	inManaged := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "; Managed Records" {
			inManaged = true
			continue
		}
		if !inManaged {
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func extractStaticLines(content string) []string {
	return normalizeManagedLines(extractStaticRawLines(content))
}

func filterStaticCollisions(z *ZoneFormat, domain string, staticLines, managedLines []string) []string {
	managedHosts := make(map[string]map[string]bool) // hostname -> type -> true
	for _, line := range managedLines {
		if host, rtype, _ := parseZoneRecordLine(line); host != "" {
			if managedHosts[host] == nil {
				managedHosts[host] = make(map[string]bool)
			}
			managedHosts[host][rtype] = true
		}
	}

	seenStatic := make(map[string]bool)
	var out []string
	for _, line := range staticLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, ";") {
			out = append(out, line)
			continue
		}
		host, rtype, _ := parseZoneRecordLine(line)
		if host == "" {
			out = append(out, line)
			continue
		}
		if managedHosts[host] != nil {
			z.GetLogger().Warn("Static record %s.%s (%s) shadowed by managed records - emitting as comment", host, domain, rtype)
			out = append(out, fmt.Sprintf("; CONFLICT (shadowed by managed %s): %s", rtype, strings.TrimSpace(line)))
			continue
		}
		key := host + ":" + rtype
		if seenStatic[key] {
			z.GetLogger().Warn("Duplicate static record %s.%s (%s) - emitting as-is", host, domain, rtype)
		}
		seenStatic[key] = true
		out = append(out, line)
	}
	staticTypes := make(map[string]map[string]bool)
	for _, line := range out {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if host, rtype, _ := parseZoneRecordLine(line); host != "" {
			if staticTypes[host] == nil {
				staticTypes[host] = make(map[string]bool)
			}
			staticTypes[host][rtype] = true
		}
	}
	for host, types := range staticTypes {
		if types["CNAME"] && (types["A"] || types["AAAA"]) {
			z.GetLogger().Error("Invalid static records for %s.%s: CNAME cannot coexist with address records - fix by hand", host, domain)
		}
	}
	return out
}

func extractManagedLines(content string) []string {
	var lines []string
	inManaged := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "; Managed Records" {
			inManaged = true
			continue
		}
		if !inManaged {
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		lines = append(lines, strings.Join(strings.Fields(line), " "))
	}
	return lines
}

func normalizeManagedLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		out = append(out, strings.Join(strings.Fields(line), " "))
	}
	return out
}

func managedLinesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue // Need at least hostname, TTL, IN, TYPE, TARGET
		}

		rec := &common.BaseRecord{
			Hostname: fields[0],
			TTL:      uint32(parseTTL(fields[1])),
			Type:     fields[3],
			Target:   fields[4],
			Source:   "manual", // Default source for records without comments
		}

		if idx := strings.Index(line, "; input: "); idx != -1 {
			source := strings.TrimSpace(line[idx+9:])
			if i := strings.Index(source, " "); i != -1 {
				source = source[:i]
			}
			rec.Source = source
		}

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

	for _, rec := range records {
		if rec.Hostname != "" && rec.Type != "" && rec.Target != "" {
			err := z.CommonFormat.WriteRecordWithSource(domain, rec.Hostname, rec.Target, rec.Type, int(rec.TTL), rec.Source)
			if err != nil {
				z.GetLogger().Warn("Failed to merge loaded record %s.%s (%s): %v", rec.Hostname, domain, rec.Type, err)
			}
		}
	}
	return nil
}

func parseTTL(s string) int {
	ttl, err := strconv.Atoi(s)
	if err != nil {
		return 300
	}
	return ttl
}

func (z *ZoneFormat) generateZoneFileContent(domain string, staticLines, managedRecords []string, serial string) (string, error) {
	var lines []string

	now := time.Now()
	lines = append(lines, fmt.Sprintf("; Last-updated: %s", now.Format(time.RFC3339)))
	lines = append(lines, fmt.Sprintf("; Zone file for %s", domain))
	lines = append(lines, fmt.Sprintf("; Generated by herald at %s", now.Format("20060102-150405")))
	lines = append(lines, "")

	lines = append(lines, fmt.Sprintf("$ORIGIN %s.", domain))
	lines = append(lines, "$TTL 300")
	lines = append(lines, "")

	soa, err := z.generateSOARecord(domain, serial)
	if err != nil {
		return "", err
	}
	lines = append(lines, soa...)
	lines = append(lines, "")

	nsRecords := z.generateNSRecords(domain)
	lines = append(lines, nsRecords...)
	lines = append(lines, "")

	emittedStatic := filterStaticCollisions(z, domain, staticLines, managedRecords)
	if len(emittedStatic) > 0 {
		lines = append(lines, "; Static Records")
		lines = append(lines, emittedStatic...)
		lines = append(lines, "")
	}

	if len(managedRecords) > 0 {
		lines = append(lines, "; Managed Records")
		lines = append(lines, managedRecords...)
	}

	return strings.Join(lines, "\n") + "\n", nil
}

func (z *ZoneFormat) generateSOARecord(domain string, serial string) ([]string, error) {
	newSerial := serial
	if newSerial == "" {
		newSerial = z.incrementSerial(z.getCurrentSerial())
	}
	z.GetLogger().Trace("SOA: New=%s", newSerial)

	soa := z.expandSOAConfig(domain)

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

func (z *ZoneFormat) incrementSerial(currentSerial string) string {
	today := time.Now().Format("20060102")
	z.GetLogger().Trace("incrementSerial: today=%s, currentSerial=%s", today, currentSerial)

	if currentSerial == "" {
		newSerial := fmt.Sprintf("%s01", today)
		z.GetLogger().Trace("incrementSerial: No current serial, returning new=%s", newSerial)
		return newSerial
	}

	if len(currentSerial) >= 10 && strings.HasPrefix(currentSerial, today) {
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

	newSerial := fmt.Sprintf("%s01", today)
	z.GetLogger().Trace("incrementSerial: Reset to new=%s", newSerial)
	return newSerial
}

func (z *ZoneFormat) generateNSRecords(domain string) []string {
	var lines []string
	for _, ns := range z.nsRaw {
		expandedNS := expandTags(ns, domain, z.CommonFormat.GetProfile())
		lines = append(lines, fmt.Sprintf("%-20s %-6d %-4s %-5s %s", "@", 300, "IN", "NS", expandedNS))
	}
	return lines
}

func (z *ZoneFormat) generateManagedRecords(domain string) []string {
	records := z.collectManagedRecords(domain)

	var lines []string
	for _, record := range records {
		lines = append(lines, formatManagedRecord(record))
	}
	return lines
}

func formatManagedRecord(record *common.BaseRecord) string {
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
	return fmt.Sprintf("%-20s %-6d %-4s %-5s %-15s %s",
		hostname, record.TTL, "IN", record.Type, record.Target, comment)
}

func (z *ZoneFormat) collectManagedRecords(domain string) []*common.BaseRecord {
	export := z.GetExportData()
	if export == nil || export.Domains == nil {
		return nil
	}
	domainData, ok := export.Domains[domain]
	if !ok || domainData == nil {
		return nil
	}

	recordMap := make(map[string]*common.BaseRecord)

	filePath := z.GetFilePath()
	if fileExists(filePath) {
		existingRecords := z.loadRecordsFromManagedSection(domain, filePath)
		for _, record := range existingRecords {
			if isManualSource(record.Source) {
				continue
			}
			key := record.Hostname + ":" + record.Type
			recordMap[key] = record
		}
		z.GetLogger().Debug("generateManagedRecords: Loaded %d existing records from file for domain %s", len(existingRecords), domain)
	}

	for _, record := range domainData.Records {
		key := record.Hostname + ":" + record.Type
		recordMap[key] = record // This will overwrite existing records with same hostname+type
	}
	z.GetLogger().Debug("generateManagedRecords: Final record count for domain %s: %d", domain, len(recordMap))

	records := make([]*common.BaseRecord, 0, len(recordMap))
	for _, record := range recordMap {
		records = append(records, record)
	}

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
		sort.Slice(records, func(i, j int) bool { return records[i].Hostname < records[j].Hostname })
	} else if len(records) > 1 {
		sort.Slice(records, less)
	}

	return enforceCNAMEExclusivity(z, domain, records)
}

func enforceCNAMEExclusivity(z *ZoneFormat, domain string, records []*common.BaseRecord) []*common.BaseRecord {
	hasAddress := make(map[string]bool)
	for _, r := range records {
		if r.Type == "A" || r.Type == "AAAA" {
			hasAddress[r.Hostname] = true
		}
	}
	kept := records[:0]
	for _, r := range records {
		if r.Type == "CNAME" && hasAddress[r.Hostname] {
			z.GetLogger().Warn("Dropping conflicting CNAME record %s.%s -> %s (hostname also has address records)", r.Hostname, domain, r.Target)
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

func (z *ZoneFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	z.GetLogger().Debug("WriteRecordWithSource called: domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", domain, hostname, target, recordType, ttl, source)
	defer func() {
		z.GetLogger().Debug("WriteRecordWithSource finished: domain=%s, hostname=%s, type=%s", domain, hostname, recordType)
	}()

	loadKey := domain + "|" + z.GetFilePath()
	loadedZoneMutex.RLock()
	loaded := loadedZoneDomains[loadKey]
	loadedZoneMutex.RUnlock()

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

func (z *ZoneFormat) ClearRecords(domain string) {
	export := z.GetExportData()
	if export.Domains != nil {
		if d, ok := export.Domains[domain]; ok && d != nil {
			d.Records = nil
		}
	}
}

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

		if strings.Contains(line, "; Managed Records") {
			inManagedSection = true
			continue
		}
		if strings.Contains(line, "; End Managed Records") {
			inManagedSection = false
			continue
		}

		if !inManagedSection || line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		if record := z.parseRecordLine(line, domain); record != nil {
			records = append(records, record)
		}
	}

	return records
}

func (z *ZoneFormat) parseRecordLine(line, domain string) *common.BaseRecord {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	hostname := fields[0]
	ttl, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil
	}

	recordType := fields[3]
	target := fields[4]

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
