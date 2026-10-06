// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output/common"

	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type HostsFormat struct {
	*common.CommonFormat
	domain      string
	profileName string                  // store the output profile name explicitly
	records     map[string]*HostsRecord // key: hostname:type
	config      HostsConfig
	enableIPv4  bool
	enableIPv6  bool
}

type HostsConfig struct {
	EnableIPv4     bool   `yaml:"enable_ipv4" json:"enable_ipv4"`
	EnableIPv6     bool   `yaml:"enable_ipv6" json:"enable_ipv6"`
	FlattenCNAMEs  bool   `yaml:"flatten_cnames" json:"flatten_cnames"`
	SkipLoopback   bool   `yaml:"skip_loopback" json:"skip_loopback"`
	OverrideTarget string `yaml:"override_target" json:"override_target"`
}

type HostsRecord struct {
	Hostname  string
	Type      string
	Target    string
	TTL       uint32
	Source    string
	CreatedAt time.Time
}

var hostsReentrancyGuard sync.Map

func NewHostsFormat(domainArg, profileName string, config map[string]interface{}) (OutputFormat, error) {
	commonFormat, err := common.NewCommonFormat(profileName, "hosts", config)
	if err != nil {
		return nil, err
	}

	hostsConfig := HostsConfig{
		EnableIPv4:     true, // Default to true
		EnableIPv6:     true, // Default to true
		FlattenCNAMEs:  true, // Default to true for backward compatibility
		SkipLoopback:   true, // Default to true to avoid localhost issues
		OverrideTarget: "",   // Default to empty (no override)
	}

	if enableIPv4, ok := config["enable_ipv4"].(bool); ok {
		hostsConfig.EnableIPv4 = enableIPv4
	}
	if enableIPv6, ok := config["enable_ipv6"].(bool); ok {
		hostsConfig.EnableIPv6 = enableIPv6
	}
	if flattenCNAMEs, ok := config["flatten_cnames"].(bool); ok {
		hostsConfig.FlattenCNAMEs = flattenCNAMEs
	}
	if skipLoopback, ok := config["skip_loopback"].(bool); ok {
		hostsConfig.SkipLoopback = skipLoopback
	}
	if overrideTarget, ok := config["override_target"].(string); ok {
		hostsConfig.OverrideTarget = overrideTarget
	}

	realDomain := domainArg
	if d, ok := config["domain"].(string); ok && d != "" {
		realDomain = d
	}

	h := &HostsFormat{
		CommonFormat: commonFormat,
		domain:       realDomain,
		profileName:  profileName,
		records:      make(map[string]*HostsRecord),
		config:       hostsConfig,
		enableIPv4:   hostsConfig.EnableIPv4,
		enableIPv6:   hostsConfig.EnableIPv6,
	}
	log.Debug("[output/hosts/%s] Initialized hosts format: %s (domain=%s)", profileName, h.GetFilePath(), h.domain)

	return h, nil
}

func (h *HostsFormat) GetName() string {
	return "hosts"
}

func (h *HostsFormat) GetFilePath() string {
	path := "hosts_%domain_underscore%.hosts" // default fallback, matches other providers
	if h.CommonFormat != nil && h.CommonFormat.GetConfig() != nil {
		if p, ok := h.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	filename := expandTagsWithUnderscore(path, h.domain, h.profileName)
	return filename
}

func (h *HostsFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return h.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

func (h *HostsFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	start := time.Now().UnixMilli()
	log.Debug("%s WriteRecordWithSource called: domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", h.getHostsLogPrefix(), domain, hostname, target, recordType, ttl, source)
	defer func() {
		dur := time.Now().UnixMilli() - start
		log.Debug("%s WriteRecordWithSource finished: domain=%s, hostname=%s, type=%s, records_now=%d, dur_ms=%d", h.getHostsLogPrefix(), domain, hostname, recordType, len(h.records), dur)
		if dur > 5000 {
			log.Warn("%s WriteRecordWithSource took too long: %d ms (>5s)", h.getHostsLogPrefix(), dur)
		}
	}()

	if recordType == "CNAME" {
		if !h.config.FlattenCNAMEs {
			log.Debug("%s Skipping CNAME flattening (disabled): %s.%s -> %s", h.getHostsLogPrefix(), hostname, domain, target)
			return nil
		}
		ip, err := h.resolveCNAMEOutsideLock(domain, hostname, target, ttl, source)
		if err != nil {
			return err
		}
		if ip != nil {
			h.Lock()
			key := fmt.Sprintf("%s:%s", hostname, ip.Type)
			h.records[key] = ip
			h.Unlock()
			log.Verbose("%s Flattened and added CNAME: %s.%s -> %s (%s)", h.getHostsLogPrefix(), hostname, domain, ip.Target, ip.Type)
		}
		return nil
	}

	h.Lock()
	if recordType == "A" && !h.enableIPv4 {
		h.Unlock()
		return nil
	}
	if recordType == "AAAA" && !h.enableIPv6 {
		h.Unlock()
		return nil
	}

	if recordType != "A" && recordType != "AAAA" {
		h.Unlock()
		return nil
	}

	key := fmt.Sprintf("%s:%s", hostname, recordType)
	existingRecord := h.records[key]
	if existingRecord != nil {
		existingRecord.Target = target
		existingRecord.TTL = uint32(ttl)
		existingRecord.Source = source
	} else {
		h.records[key] = &HostsRecord{
			Hostname:  hostname,
			Type:      recordType,
			Target:    target,
			TTL:       uint32(ttl),
			Source:    source,
			CreatedAt: time.Now(),
		}
	}
	h.Unlock()

	if h.CommonFormat != nil {
		err := h.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
		if err != nil {
			log.Warn("[output/hosts] Failed to update CommonFormat for export: %v", err)
		}
	}

	return nil
}

func (h *HostsFormat) resolveCNAMEOutsideLock(domain, hostname, target string, ttl int, source string) (*HostsRecord, error) {
	var overrideIP string
	if strings.TrimSpace(h.config.OverrideTarget) != "" {
		overrideIP = strings.TrimSpace(h.config.OverrideTarget)
	}
	if overrideIP != "" {
		parsedIP := net.ParseIP(overrideIP)
		if parsedIP == nil {
			return nil, fmt.Errorf("invalid ip_override value: %s", overrideIP)
		}
		var recordType string
		if parsedIP.To4() != nil {
			recordType = "A"
			if !h.enableIPv4 {
				return nil, nil
			}
		} else {
			recordType = "AAAA"
			if !h.enableIPv6 {
				return nil, nil
			}
		}
		return &HostsRecord{
			Hostname: hostname,
			Type:     recordType,
			Target:   overrideIP,
			TTL:      uint32(ttl),
			Source:   source,
		}, nil
	}
	var selectedIP net.IP
	var err error
	var dnsServer string
	resolveExternal := false
	if v, ok := h.CommonFormat.GetConfig()["resolve_external"]; ok {
		if b, ok := v.(bool); ok {
			resolveExternal = b
		}
	}
	dnsServer = ""
	if v, ok := h.CommonFormat.GetConfig()["dns_server"]; ok {
		if s, ok := v.(string); ok {
			dnsServer = s
		}
	}
	if resolveExternal && dnsServer != "" && dnsServer != "system" {
		selectedIP, err = h.resolveWithExternalDNS(target, dnsServer)
	} else {
		ips, sysErr := net.LookupIP(target)
		if sysErr != nil {
			err = sysErr
		} else if len(ips) == 0 {
			err = fmt.Errorf("no IP addresses found")
		} else {
			for _, ip := range ips {
				if ip.To4() != nil && h.enableIPv4 {
					selectedIP = ip
					break
				} else if ip.To4() == nil && h.enableIPv6 {
					selectedIP = ip
					break
				}
			}
			if selectedIP == nil {
				err = fmt.Errorf("no compatible IP addresses found")
			}
		}
	}
	if err != nil || selectedIP == nil {
		return nil, err
	}
	var recordType string
	if selectedIP.To4() != nil {
		recordType = "A"
		if !h.enableIPv4 {
			return nil, nil
		}
	} else {
		recordType = "AAAA"
		if !h.enableIPv6 {
			return nil, nil
		}
	}
	return &HostsRecord{
		Hostname: hostname,
		Type:     recordType,
		Target:   selectedIP.String(),
		TTL:      uint32(ttl),
		Source:   source,
	}, nil
}

func (h *HostsFormat) resolveWithExternalDNS(target, dnsServer string) (net.IP, error) {
	log.Debug("%s Resolving %s using external DNS server %s", h.getHostsLogPrefix(), target, dnsServer)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(target), dns.TypeA)
	resp, _, err := c.Exchange(m, dnsServer+":53")
	if err == nil && resp != nil && len(resp.Answer) > 0 {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok && h.enableIPv4 {
				return a.A, nil
			}
		}
	}
	m.SetQuestion(dns.Fqdn(target), dns.TypeAAAA)
	resp, _, err = c.Exchange(m, dnsServer+":53")
	if err == nil && resp != nil && len(resp.Answer) > 0 {
		for _, ans := range resp.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok && h.enableIPv6 {
				return aaaa.AAAA, nil
			}
		}
	}
	log.Warn("%s External DNS lookup failed or no answer, falling back to system resolver", h.getHostsLogPrefix())
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.To4() != nil && h.enableIPv4 {
			return ip, nil
		} else if ip.To4() == nil && h.enableIPv6 {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no compatible IP addresses found")
}

func (h *HostsFormat) RemoveRecord(domain, hostname, recordType string) error {
	start := time.Now().UnixMilli()
	log.Debug("%s Attempting to acquire lock in RemoveRecord", h.getHostsLogPrefix())
	h.Lock()
	log.Debug("%s Acquired lock in RemoveRecord", h.getHostsLogPrefix())
	defer func() {
		h.Unlock()
		dur := time.Now().UnixMilli() - start
		log.Trace("%s Released lock in RemoveRecord (lock_held_ms=%d)", h.getHostsLogPrefix(), dur)
		if dur > 5000 {
			log.Warn("%s RemoveRecord lock held for %d ms (>5s)!", h.getHostsLogPrefix(), dur)
		}
	}()

	removed := false
	for _, t := range []string{"A", "AAAA", recordType} {
		key := fmt.Sprintf("%s:%s", hostname, t)
		if _, exists := h.records[key]; exists {
			delete(h.records, key)
			fqdn := hostname + "." + domain
			log.Verbose("%s Removed record: %s (%s)", h.getHostsLogPrefix(), fqdn, t)
			removed = true
		}
	}
	if !removed {
		log.Debug("%s No record found to remove for hostname=%s, domain=%s", h.getHostsLogPrefix(), hostname, domain)
	}

	return nil
}

func (h *HostsFormat) Sync() error {
	key := h.domain + "|" + h.profileName + "|hosts" // Use profileName for re-entrancy guard
	if _, loaded := hostsReentrancyGuard.LoadOrStore(key, true); loaded {
		log.Warn("%s Sync() re-entrancy detected for key=%s, skipping", h.getHostsLogPrefix(), key)
		return nil
	}
	defer hostsReentrancyGuard.Delete(key)

	log.Debug("%s Sync() called: domain=%s, profile=%s, file=%s, records=%d", h.getHostsLogPrefix(), h.domain, h.profileName, h.GetFilePath(), len(h.records))
	log.Debug("%s Attempting to write file: %s", h.getHostsLogPrefix(), h.GetFilePath())

	err := h.CommonFormat.SyncWithSerializer(h.serializeHosts, h.domain)
	if err != nil {
		log.Error("%s Sync FAILED for domain=%s, profile=%s, file=%s: %v", h.getHostsLogPrefix(), h.domain, h.profileName, h.GetFilePath(), err)
	} else {
		log.Info("%s Sync SUCCESS for domain=%s, profile=%s, file=%s, records=%d", h.getHostsLogPrefix(), h.domain, h.profileName, h.GetFilePath(), len(h.records))
	}
	return err
}

func (h *HostsFormat) serializeHosts(domain string, export *common.ExportData) ([]byte, error) {
	content := h.generateHostsFile(domain, export)
	return []byte(content), nil
}

func (h *HostsFormat) generateHostsFile(domain string, export *common.ExportData) string {
	recordsLen := 0
	if h.records != nil {
		recordsLen = len(h.records)
	}
	domainsLen := 0
	if export != nil && export.Domains != nil {
		domainsLen = len(export.Domains)
	}
	log.Debug("[output/hosts] generateHostsFile called for domain=%s, export.Domains.len=%d, h.records.len=%d", domain, domainsLen, recordsLen)
	var content strings.Builder
	estimatedSize := len(h.records)*80 + 500 // Rough estimate
	content.Grow(estimatedSize)

	header := expandTags("# Hosts file for %domain%\n# Generated by herald at %date%\n# Last-updated: "+time.Now().Format(time.RFC3339)+"\n", h.CommonFormat.GetDomain(), h.CommonFormat.GetProfile())
	content.WriteString(header)

	var recordsToWrite []*HostsRecord
	for _, rec := range h.records {
		recordsToWrite = append(recordsToWrite, rec)
	}

	if len(recordsToWrite) == 0 {
		content.WriteString("# No records to write\n")
		return content.String()
	}

	hostnameMap := make(map[string][]*HostsRecord, len(recordsToWrite))
	maxIPWidth := 0
	maxHostnameWidth := 0

	for _, record := range recordsToWrite {
		fullHostname := record.Hostname
		if record.Hostname != "@" && record.Hostname != h.domain {
			fullHostname = record.Hostname + "." + h.domain
		} else if record.Hostname == "@" {
			fullHostname = h.domain
		}
		hostnameMap[fullHostname] = append(hostnameMap[fullHostname], record)

		if len(record.Target) > maxIPWidth {
			maxIPWidth = len(record.Target)
		}
		if len(fullHostname) > maxHostnameWidth {
			maxHostnameWidth = len(fullHostname)
		}
	}

	maxIPWidth += 2
	maxHostnameWidth += 2

	var hostnames []string
	for hostname := range hostnameMap {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	for _, hostname := range hostnames {
		records := hostnameMap[hostname]

		sort.Slice(records, func(i, j int) bool {
			return records[i].Type < records[j].Type
		})

		for _, record := range records {
			ipSpaces := strings.Repeat(" ", maxIPWidth-len(record.Target))
			hostnameSpaces := strings.Repeat(" ", maxHostnameWidth-len(hostname))

			comment := ""
			if !record.CreatedAt.IsZero() {
				comment = fmt.Sprintf("# created_at: %s input: %s", record.CreatedAt.Format(time.RFC3339), record.Source)
			} else {
				comment = fmt.Sprintf("# input: %s", record.Source)
			}
			line := fmt.Sprintf("%s%s%s%s%s",
				record.Target,
				ipSpaces,
				hostname,
				hostnameSpaces,
				comment)

			content.WriteString(line + "\n")
		}
	}

	return content.String()
}

func (h *HostsFormat) getHostsLogPrefix() string {
	return fmt.Sprintf("[output/hosts/%s]", h.profileName)
}
