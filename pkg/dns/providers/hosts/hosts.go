// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	dns "dns-companion/pkg/dns"
	"dns-companion/pkg/log"

	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostsProvider implements DNS Provider for /etc/hosts style files
// Supports only A and AAAA records. CNAMEs are ignored or mapped to A/AAAA if possible.
type HostsProvider struct {
	source    string
	mutex     sync.Mutex
	logPrefix string
	profile   string
	config    HostsProviderConfig
}

// Ensure HostsProvider implements Provider interface
var _ dns.Provider = (*HostsProvider)(nil)

// HostsProviderConfig holds config for the hosts provider
// Source: path to the hosts file
// User: username or uid to own the file (optional)
// Group: group name or gid to own the file (optional)
// Mode: file permissions (e.g. 0644, 0600)
// EnableIPv4: whether to write IPv4 A records (default: true)
// EnableIPv6: whether to write IPv6 AAAA records (default: true)
type HostsProviderConfig struct {
	Source     string
	User       string // optional
	Group      string // optional
	Mode       uint32 // optional, default 0644
	EnableIPv4 bool   // optional, default true
	EnableIPv6 bool   // optional, default true
}

// buildFullFQDN constructs the full FQDN from hostname and domain
func (h *HostsProvider) buildFullFQDN(hostname, domain string) string {
	if hostname == "@" || hostname == domain {
		return strings.ToLower(domain)
	}
	if strings.HasSuffix(hostname, "."+domain) {
		return strings.ToLower(hostname)
	}
	return strings.ToLower(hostname + "." + domain)
}

// validateRecordType checks if the record type is supported
func (h *HostsProvider) validateRecordType(recordType string) error {
	if recordType != "A" && recordType != "AAAA" {
		return fmt.Errorf("hosts provider only supports A and AAAA records, got %s", recordType)
	}
	return nil
}

// validateAndCheckIP validates an IP address and checks if it's enabled
func (h *HostsProvider) validateAndCheckIP(ip string) (net.IP, bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, false, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check if this IP type is enabled in config
	isIPv4 := parsedIP.To4() != nil
	if isIPv4 && !h.config.EnableIPv4 {
		log.Debug("%s Skipping IPv4 address %s (IPv4 disabled)", h.logPrefix, ip)
		return parsedIP, false, nil
	}
	if !isIPv4 && !h.config.EnableIPv6 {
		log.Debug("%s Skipping IPv6 address %s (IPv6 disabled)", h.logPrefix, ip)
		return parsedIP, false, nil
	}

	return parsedIP, true, nil
}

// removeExistingEntries removes all existing entries for a given FQDN
func (h *HostsProvider) removeExistingEntries(lines []string, fullFQDN string) []string {
	newLines := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(strings.SplitN(line, "|#|", 2)[0])
		if len(fields) >= 2 && fields[1] == fullFQDN {
			continue // Skip existing entries for this FQDN
		}
		newLines = append(newLines, line)
	}
	return newLines
}

// NewHostsProvider creates a new HostsProvider
func NewHostsProvider(config map[string]string) (dns.Provider, error) {
	cfg := HostsProviderConfig{
		EnableIPv4: true, // default to true - really only used when CNAME flattening from external source
		EnableIPv6: true,
	}
	profileName := "hosts"
	if v, ok := config["profile_name"]; ok && v != "" {
		profileName = v
	}
	logPrefix := fmt.Sprintf("[dns/hosts/%s]", profileName)
	log.Debug("%s Initializing hosts provider with config: %+v", logPrefix, config)
	if v, ok := config["source"]; ok {
		cfg.Source = v
	}
	if v, ok := config["user"]; ok {
		cfg.User = v
	}
	if v, ok := config["group"]; ok {
		cfg.Group = v
	}
	if v, ok := config["mode"]; ok {
		if modeInt, err := strconv.ParseUint(v, 0, 32); err == nil {
			cfg.Mode = uint32(modeInt)
		}
	}
	if v, ok := config["enable_ipv4"]; ok {
		cfg.EnableIPv4 = v == "true" || v == "1" || v == "yes"
	}
	if v, ok := config["enable_ipv6"]; ok {
		cfg.EnableIPv6 = v == "true" || v == "1" || v == "yes"
	}
	if cfg.Source == "" {
		log.Error("%s Provider misconfigured: 'source' is required and was not set in config. Refusing to start.", logPrefix)
		return nil, fmt.Errorf("hosts provider: 'source' is required in config")
	}
	if cfg.Mode == 0 {
		cfg.Mode = 0644
	}
	log.Debug("%s Provider loaded with source=%s user=%s group=%s mode=%o ipv4=%t ipv6=%t", logPrefix, cfg.Source, cfg.User, cfg.Group, cfg.Mode, cfg.EnableIPv4, cfg.EnableIPv6)
	return &HostsProvider{source: cfg.Source, logPrefix: logPrefix, profile: profileName, config: cfg}, nil
}

func (h *HostsProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, overwrite bool) error {
	if recordType == "CNAME" {
		log.Verbose("%s Flattening CNAME %s -> %s: resolving to A/AAAA for hosts file", h.logPrefix, hostname, target)

		// Build the full CNAME chain by following all intermediate CNAMEs
		cnameChain := []string{hostname}
		current := target
		visited := map[string]bool{hostname: true}

		// Follow the CNAME chain to the end
		for {
			if visited[current] {
				break // Prevent infinite loops
			}
			visited[current] = true
			cnameChain = append(cnameChain, current)

			cname, err := net.LookupCNAME(current)
			log.Debug("%s CNAME lookup for %s: result=%s, err=%v", h.logPrefix, current, cname, err)
			if err != nil {
				log.Debug("%s CNAME lookup failed for %s: %v (treating as final target)", h.logPrefix, current, err)
				break
			}

			// Clean up the CNAME result
			cname = strings.TrimSuffix(cname, ".")

			// If it points to itself, we're done
			if cname == current {
				log.Debug("%s CNAME %s points to itself, stopping chain", h.logPrefix, current)
				break
			}

			log.Debug("%s Following CNAME: %s -> %s", h.logPrefix, current, cname)
			// Continue with the next CNAME in the chain
			current = cname
		}

		// Try alternative resolution: if we only got 2 IPs but nslookup shows more, the DNS records might be configured differently than what Go's resolver sees
		// TODO resarch libunbound
		finalTarget := current
		ips, err := net.LookupIP(finalTarget)
		if err != nil || len(ips) == 0 {
			log.Warn("%s Failed to resolve final CNAME target %s for %s: %v", h.logPrefix, finalTarget, hostname, err)
			return fmt.Errorf("cannot flatten CNAME: failed to resolve %s: %v", finalTarget, err)
		}

		chainStr := strings.Join(cnameChain, " -> ")
		log.Debug("%s Resolved CNAME chain: %s -> %d IP addresses", h.logPrefix, chainStr, len(ips))

		// Batch all IPs for this CNAME and write once
		h.mutex.Lock()
		defer h.mutex.Unlock()

		lines, err := h.readLines()
		if err != nil {
			return err
		}

		fullFQDN := h.buildFullFQDN(hostname, domain)

		// Remove existing entries for this FQDN to prevent duplicates
		newLines := h.removeExistingEntries(lines, fullFQDN)

		// Add all new IPs for this CNAME
		for _, ip := range ips {
			parsedIP, enabled, err := h.validateAndCheckIP(ip.String())
			if err != nil {
				log.Debug("%s Skipping invalid IP %s: %v", h.logPrefix, ip.String(), err)
				continue
			}
			if !enabled {
				continue
			}

			recType := "A"
			if parsedIP.To4() == nil {
				recType = "AAAA"
			}
			comment := fmt.Sprintf("pollprovider=%s, flattened from: %s", h.profile, chainStr)
			newLines = append(newLines, fmt.Sprintf("%s %s|#|%s", parsedIP.String(), fullFQDN, comment))
			log.Info("%s Flattened CNAME %s as %s %s", h.logPrefix, chainStr, recType, parsedIP.String())
		}

		return h.writeLines(newLines)
	}

	// Construct full FQDN for logging
	fullFQDN := h.buildFullFQDN(hostname, domain)
	log.Verbose("%s Writing hosts record %s (%s) -> %s", h.logPrefix, fullFQDN, recordType, target)
	comment := fmt.Sprintf("pollprovider=%s", h.profile)
	return h.EnsureDNSWithComment(domain, hostname, target, recordType, comment)
}

// EnsureDNSWithComment writes a record with a custom comment
func (h *HostsProvider) EnsureDNSWithComment(domain, fqdn, ip, recordType, comment string) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if err := h.validateRecordType(recordType); err != nil {
		return err
	}

	parsedIP, enabled, err := h.validateAndCheckIP(ip)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}

	lines, err := h.readLines()
	if err != nil {
		return err
	}

	fullFQDN := h.buildFullFQDN(fqdn, domain)
	// Remove all existing entries for this FQDN
	newLines := h.removeExistingEntries(lines, fullFQDN)
	// Add the new entry
	newLines = append(newLines, fmt.Sprintf("%s %s|#|%s", parsedIP.String(), fullFQDN, comment))
	return h.writeLines(newLines)
}

func (h *HostsProvider) RemoveRecord(domain, hostname, recordType string) error {
	log.Debug("%s RemoveRecord called with domain=%s, hostname=%s, recordType=%s", h.logPrefix, domain, hostname, recordType)

	// For hosts files, record type is irrelevant. If hostname looks like a record type (A, AAAA), then the parameters might be in the wrong order from the caller.
	actualHostname := hostname
	if hostname == "A" || hostname == "AAAA" || hostname == "CNAME" {
		log.Debug("%s hostname=%s looks like a record type, assuming parameters are swapped", h.logPrefix, hostname)
		actualHostname = recordType // Swap them
	}

	fullFQDN := h.buildFullFQDN(actualHostname, domain)
	log.Debug("%s RemoveRecord constructed fullFQDN=%s from actualHostname=%s and domain=%s", h.logPrefix, fullFQDN, actualHostname, domain)
	return h.EnsureDNSRemove(domain, fullFQDN)
}

func (h *HostsProvider) DeleteRecord(domain, fqdn, recordType string) error {
	return h.RemoveRecord(domain, fqdn, recordType)
}

func (h *HostsProvider) GetRecordID(domain, fqdn, recordType string) (string, error) {
	return fqdn + ":" + recordType, nil
}

func (h *HostsProvider) GetRecordValue(domain, fqdn, recordType string) (*dns.Record, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	lines, err := h.readLines()
	if err != nil {
		return nil, err
	}
	fqdn = strings.ToLower(fqdn)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == fqdn {
			rec := &dns.Record{
				Name:  fqdn,
				Type:  recordType,
				Value: fields[0],
			}
			return rec, nil
		}
	}
	return nil, fmt.Errorf("record not found")
}

func (h *HostsProvider) GetRecords(domain, fqdn, recordType string) ([]*dns.Record, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	lines, err := h.readLines()
	if err != nil {
		return nil, err
	}
	var records []*dns.Record
	fqdn = strings.ToLower(fqdn)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if (domain == "" || strings.HasSuffix(fields[1], domain)) &&
				(fqdn == "" || fields[1] == fqdn) &&
				(recordType == "" || recordType == "A" || recordType == "AAAA") {
				rec := &dns.Record{
					Name:  fields[1],
					Type:  "A",
					Value: fields[0],
				}
				records = append(records, rec)
			}
		}
	}
	return records, nil
}

func (h *HostsProvider) EnsureDNS(domain, fqdn, ip string, recordType string) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if err := h.validateRecordType(recordType); err != nil {
		return err
	}

	parsedIP, enabled, err := h.validateAndCheckIP(ip)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}

	lines, err := h.readLines()
	if err != nil {
		return err
	}

	fullFQDN := h.buildFullFQDN(fqdn, domain)
	// Remove all existing entries for this FQDN
	newLines := h.removeExistingEntries(lines, fullFQDN)
	// Add the new entry
	newLines = append(newLines, fmt.Sprintf("%s %s|#|pollprovider=%s", parsedIP.String(), fullFQDN, h.profile))
	return h.writeLines(newLines)
}

func (h *HostsProvider) EnsureDNSRemove(domain, fqdn string) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	lines, err := h.readLines()
	if err != nil {
		return err
	}
	fqdn = strings.ToLower(fqdn)
	// Always use the FQDN as it appears in the hosts file for matching
	removed := 0
	newLines := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(strings.SplitN(line, "|#|", 2)[0])
		if len(fields) >= 2 && fields[1] == fqdn {
			removed++
			continue // Remove all entries for this FQDN
		}
		newLines = append(newLines, line)
	}
	log.Debug("%s EnsureDNSRemove: removed %d entries for FQDN %s", h.logPrefix, removed, fqdn)
	return h.writeLines(newLines)
}

func (h *HostsProvider) readLines() ([]string, error) {
	log.Trace("%s Reading hosts file: %s", h.logPrefix, h.source)
	file, err := os.OpenFile(h.source, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Error("%s Failed to open hosts file %s: %v", h.logPrefix, h.source, err)
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header lines (lines starting with '# This file ..)
		if strings.HasPrefix(line, "# This file was generated by dns-companion") ||
			strings.HasPrefix(line, "# Do not edit manually!") ||
			strings.HasPrefix(line, "# Last updated:") ||
			strings.TrimSpace(line) == "" {
			continue
		}

		// Preserve existing comments using the |#| delimiter format, if line has comment convert it to our internal format
		if commentIdx := strings.Index(line, "# source:"); commentIdx > 0 {
			recordPart := strings.TrimSpace(line[:commentIdx])
			commentPart := strings.TrimSpace(line[commentIdx+9:]) // Skip "# source:"
			lines = append(lines, recordPart+"|#|"+commentPart)
		} else {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Error("%s Error reading hosts file %s: %v", h.logPrefix, h.source, err)
		return nil, err
	}
	log.Trace("%s Read %d records from hosts file %s", h.logPrefix, len(lines), h.source)
	return lines, nil
}

func (h *HostsProvider) writeLines(lines []string) error {
	log.Trace("%s Writing %d records to hosts file: %s", h.logPrefix, len(lines), h.source)
	file, err := os.OpenFile(h.source, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Error("%s Failed to open hosts file for writing %s: %v", h.logPrefix, h.source, err)
		return err
	}
	defer file.Close()
	w := bufio.NewWriter(file)

	// Write header lines
	header := []string{
		"# This file was generated by dns-companion (provider: hosts)",
		"# Do not edit manually! Changes will be overwritten.",
		fmt.Sprintf("# Last updated: %s", time.Now().Format(time.RFC3339)),
		"",
	}
	for _, line := range header {
		if _, err := w.WriteString(line + "\n"); err != nil {
			log.Error("%s Failed to write header to hosts file %s: %v", h.logPrefix, h.source, err)
			return err
		}
	}

	// Parse lines into IP, FQDN, comment
	type hostEntry struct {
		ip      string
		fqdn    string
		comment string
	}
	entries := make([]hostEntry, 0, len(lines))
	maxIPLen := 0
	maxFQDNLen := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var ip, fqdn, comment string
		if parts := strings.SplitN(line, "|#|", 2); len(parts) == 2 {
			comment = "# source: " + parts[1]
			trimmed = parts[0]
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			ip = fields[0]
			fqdn = fields[1]
			if len(ip) > maxIPLen {
				maxIPLen = len(ip)
			}
			if len(fqdn) > maxFQDNLen {
				maxFQDNLen = len(fqdn)
			}
			entries = append(entries, hostEntry{ip, fqdn, comment})
		}
	}
	ipCol := maxIPLen + 2
	fqdnCol := ipCol + maxFQDNLen + 2

	// Write records with aligned columns
	for _, entry := range entries {
		line := entry.ip
		if entry.fqdn != "" {
			pad := ipCol - len(entry.ip)
			if pad < 1 {
				pad = 1
			}
			line += strings.Repeat(" ", pad) + entry.fqdn
		}
		if entry.comment != "" {
			pad := fqdnCol - len(line)
			if pad < 1 {
				pad = 1
			}
			line += strings.Repeat(" ", pad) + entry.comment
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			log.Error("%s Failed to write record to hosts file %s: %v", h.logPrefix, h.source, err)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		log.Error("%s Failed to flush hosts file %s: %v", h.logPrefix, h.source, err)
		return err
	}
	// Set file permissions and ownership if configured
	cfg := h.getConfig()
	if cfg.Mode != 0 {
		if err := os.Chmod(h.source, os.FileMode(cfg.Mode)); err != nil {
			log.Warn("%s Failed to set file mode %o on %s: %v", h.logPrefix, cfg.Mode, h.source, err)
		}
	}
	if cfg.User != "" || cfg.Group != "" {
		uid, gid := lookupUserGroup(cfg.User, cfg.Group)
		if uid >= 0 && gid >= 0 {
			if err := os.Chown(h.source, uid, gid); err != nil {
				log.Warn("%s Failed to set ownership %d:%d on %s: %v", h.logPrefix, uid, gid, h.source, err)
			}
		}
	}
	return nil
}

// getConfig returns the provider's configuration
func (h *HostsProvider) getConfig() HostsProviderConfig {
	return h.config
}

// lookupUserGroup resolves user/group to uid/gid (returns -1 if not found)
func lookupUserGroup(user, group string) (int, int) {
	uid, gid := -1, -1
	if user != "" {
		if u, err := lookupUser(user); err == nil {
			uid = u
		}
	}
	if group != "" {
		if g, err := lookupGroup(group); err == nil {
			gid = g
		}
	}
	return uid, gid
}

// lookupUser returns uid for a username or uid string
func lookupUser(userStr string) (int, error) {
	if userStr == "" {
		return -1, fmt.Errorf("empty user")
	}
	// Try to parse as integer UID
	if uid, err := strconv.Atoi(userStr); err == nil {
		return uid, nil
	}
	// Lookup by username
	u, err := user.Lookup(userStr)
	if err != nil {
		return -1, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, err
	}
	return uid, nil
}

// lookupGroup returns gid for a group name or gid string
func lookupGroup(groupStr string) (int, error) {
	if groupStr == "" {
		return -1, fmt.Errorf("empty group")
	}
	// Try to parse as integer GID
	if gid, err := strconv.Atoi(groupStr); err == nil {
		return gid, nil
	}
	// Lookup by group name
	g, err := user.LookupGroup(groupStr)
	if err != nil {
		return -1, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, err
	}
	return gid, nil
}

// Register registers the hosts DNS provider
func Register() {
	dns.RegisterProvider("hosts", NewHostsProvider)
}
