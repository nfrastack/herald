// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package formats

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"

	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// HostsFormat implements OutputFormat for hosts files
type HostsFormat struct {
	*output.BaseFormat
	domain     string
	records    map[string]*HostsRecord // key: hostname:type
	config     HostsConfig
	enableIPv4 bool
	enableIPv6 bool
}

// HostsConfig holds configuration specific to hosts files
type HostsConfig struct {
	EnableIPv4 bool `yaml:"enable_ipv4" json:"enable_ipv4"`
	EnableIPv6 bool `yaml:"enable_ipv6" json:"enable_ipv6"`
}

// HostsRecord represents a DNS record in the hosts file
type HostsRecord struct {
	Hostname string
	Type     string
	Target   string
	TTL      uint32
	Source   string
}

// NewHostsFormat creates a new hosts file format instance
func NewHostsFormat(domain string, config map[string]interface{}) (output.OutputFormat, error) {
	baseFormat, _, err := output.NewBaseFormat(domain, "hosts", config)
	if err != nil {
		return nil, err
	}

	hostsConfig := HostsConfig{
		EnableIPv4: true, // Default to true
		EnableIPv6: true, // Default to true
	}

	// Parse hosts-specific configuration
	if enableIPv4, ok := config["enable_ipv4"].(bool); ok {
		hostsConfig.EnableIPv4 = enableIPv4
	}
	if enableIPv6, ok := config["enable_ipv6"].(bool); ok {
		hostsConfig.EnableIPv6 = enableIPv6
	}

	h := &HostsFormat{
		BaseFormat: baseFormat,
		domain:     domain,
		records:    make(map[string]*HostsRecord),
		config:     hostsConfig,
		enableIPv4: hostsConfig.EnableIPv4,
		enableIPv6: hostsConfig.EnableIPv6,
	}

	return h, nil
}

// GetName returns the format name
func (h *HostsFormat) GetName() string {
	return "hosts"
}

// WriteRecord writes or updates a DNS record
func (h *HostsFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return h.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "dns-companion")
}

// WriteRecordWithSource writes or updates a DNS record with source information
func (h *HostsFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	h.Lock()
	defer h.Unlock()

	// Handle CNAME records by flattening them to A/AAAA records
	if recordType == "CNAME" {
		return h.flattenCNAME(domain, hostname, target, ttl, source)
	}

	// Filter IPv4/IPv6 records based on configuration
	if recordType == "A" && !h.enableIPv4 {
		log.Trace("%s Skipping IPv4 record (disabled): %s.%s (%s) -> %s", h.GetLogPrefix(), hostname, domain, recordType, target)
		return nil
	}
	if recordType == "AAAA" && !h.enableIPv6 {
		log.Trace("%s Skipping IPv6 record (disabled): %s.%s (%s) -> %s", h.GetLogPrefix(), hostname, domain, recordType, target)
		return nil
	}

	// Only A and AAAA records are supported in hosts files
	if recordType != "A" && recordType != "AAAA" {
		log.Trace("%s Skipping unsupported record type for hosts file: %s.%s (%s) -> %s", h.GetLogPrefix(), hostname, domain, recordType, target)
		return nil
	}

	key := fmt.Sprintf("%s:%s", hostname, recordType)

	// Check if record already exists
	existingRecord := h.records[key]
	if existingRecord != nil {
		// Update existing record
		existingRecord.Target = target
		existingRecord.TTL = uint32(ttl)
		existingRecord.Source = source
		log.Verbose("[output/hosts/%s] Updated record: %s.%s (%s) -> %s", source, hostname, domain, recordType, target)
	} else {
		// Create new record
		h.records[key] = &HostsRecord{
			Hostname: hostname,
			Type:     recordType,
			Target:   target,
			TTL:      uint32(ttl),
			Source:   source,
		}
		log.Verbose("[output/hosts/%s] Added record: %s.%s (%s) -> %s", source, hostname, domain, recordType, target)
	}

	return nil
}

// flattenCNAME resolves CNAME records to A/AAAA records
func (h *HostsFormat) flattenCNAME(domain, hostname, target string, ttl int, source string) error {
	log.Verbose("%s Flattening CNAME %s -> %s: resolving to A/AAAA for hosts file", h.GetLogPrefix(), hostname, target)

	// Resolve the CNAME target to IP addresses
	ips, err := net.LookupIP(target)
	if err != nil {
		log.Warn("%s Failed to resolve CNAME target %s: %v", h.GetLogPrefix(), target, err)
		return err
	}

	if len(ips) == 0 {
		log.Warn("%s No IP addresses found for CNAME target %s", h.GetLogPrefix(), target)
		return fmt.Errorf("no IP addresses found for %s", target)
	}

	// Create A/AAAA records for each resolved IP
	for _, ip := range ips {
		var recordType string
		if ip.To4() != nil {
			recordType = "A"
			if !h.enableIPv4 {
				continue
			}
		} else {
			recordType = "AAAA"
			if !h.enableIPv6 {
				continue
			}
		}

		key := fmt.Sprintf("%s:%s", hostname, recordType)
		h.records[key] = &HostsRecord{
			Hostname: hostname,
			Type:     recordType,
			Target:   ip.String(),
			TTL:      uint32(ttl),
			Source:   source,
		}

		log.Info("%s Flattened CNAME %s -> %s -> %s as %s %s", h.GetLogPrefix(), hostname, target, target, recordType, ip.String())
	}

	return nil
}

// RemoveRecord removes a DNS record
func (h *HostsFormat) RemoveRecord(domain, hostname, recordType string) error {
	h.Lock()
	defer h.Unlock()

	key := fmt.Sprintf("%s:%s", hostname, recordType)
	if _, exists := h.records[key]; exists {
		delete(h.records, key)
		fqdn := hostname + "." + domain
		log.Verbose("%s Removed record: %s (%s)", h.GetLogPrefix(), fqdn, recordType)
	}

	return nil
}

// Sync writes the hosts file to disk
func (h *HostsFormat) Sync() error {
	h.Lock()
	defer h.Unlock()

	if err := h.EnsureFileAndSetOwnership(); err != nil {
		return fmt.Errorf("failed to ensure file: %v", err)
	}

	content := h.generateHostsFile()

	if err := os.WriteFile(h.GetFilePath(), []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %v", err)
	}
	log.Trace("%s fsnotify event: Name='%s', Op=WRITE", h.GetLogPrefix(), h.GetFilePath())

	log.Debug("%s Generated export for 1 domain with %d records: %s", h.GetLogPrefix(), len(h.records), h.GetFilePath())
	return nil
}

// generateHostsFile creates the hosts file content
func (h *HostsFormat) generateHostsFile() string {
	var content strings.Builder

	// Write header comment
	content.WriteString(fmt.Sprintf("# Hosts file generated by dns-companion\n"))
	content.WriteString(fmt.Sprintf("# Generated at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	content.WriteString(fmt.Sprintf("# Domain: %s\n", h.domain))
	if !h.enableIPv4 {
		content.WriteString("# IPv4 records: disabled\n")
	}
	if !h.enableIPv6 {
		content.WriteString("# IPv6 records: disabled\n")
	}
	content.WriteString("\n")

	if len(h.records) == 0 {
		content.WriteString("# No records to write\n")
		return content.String()
	}

	// Group records by hostname and calculate maximum widths for alignment
	hostnameMap := make(map[string][]*HostsRecord)
	maxIPWidth := 0
	maxHostnameWidth := 0

	for _, record := range h.records {
		fullHostname := record.Hostname
		if record.Hostname != "@" && record.Hostname != h.domain {
			fullHostname = fmt.Sprintf("%s.%s", record.Hostname, h.domain)
		} else if record.Hostname == "@" {
			fullHostname = h.domain
		}
		hostnameMap[fullHostname] = append(hostnameMap[fullHostname], record)

		// Track maximum widths for alignment
		if len(record.Target) > maxIPWidth {
			maxIPWidth = len(record.Target)
		}
		if len(fullHostname) > maxHostnameWidth {
			maxHostnameWidth = len(fullHostname)
		}
	}

	// Add padding for readability
	maxIPWidth += 2
	maxHostnameWidth += 2

	// Sort hostnames for consistent output
	var hostnames []string
	for hostname := range hostnameMap {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	// Write records grouped by hostname with aligned comments
	for _, hostname := range hostnames {
		records := hostnameMap[hostname]

		// Sort records by type (A before AAAA)
		sort.Slice(records, func(i, j int) bool {
			return records[i].Type < records[j].Type
		})

		for _, record := range records {
			// Calculate spacing for alignment
			ipSpaces := strings.Repeat(" ", maxIPWidth-len(record.Target))
			hostnameSpaces := strings.Repeat(" ", maxHostnameWidth-len(hostname))

			// Format: IP<spaces>HOSTNAME<spaces># Comment
			line := fmt.Sprintf("%s%s%s%s# %s (%s)",
				record.Target,
				ipSpaces,
				hostname,
				hostnameSpaces,
				record.Type,
				record.Source)

			content.WriteString(line + "\n")
		}
	}

	return content.String()
}

// init registers this format
func init() {
	output.RegisterFormat("hosts", NewHostsFormat)
}
