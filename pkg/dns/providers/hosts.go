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
}

// Ensure HostsProvider implements Provider interface
var _ dns.Provider = (*HostsProvider)(nil)

// HostsProviderConfig holds config for the hosts provider
// Source: path to the hosts file
// User: username or uid to own the file (optional)
// Group: group name or gid to own the file (optional)
// Mode: file permissions (e.g. 0644, 0600)
type HostsProviderConfig struct {
	Source string
	User   string // optional
	Group  string // optional
	Mode   uint32 // optional, default 0644
}

// NewHostsProvider creates a new HostsProvider
func NewHostsProvider(config map[string]string) (dns.Provider, error) {
	cfg := HostsProviderConfig{}
	profileName := "hosts"
	if v, ok := config["profile_name"]; ok && v != "" {
		profileName = v
	}
	log.Trace("[dns/hosts/%s] Initializing hosts provider with config: %+v", profileName, config)
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
	if cfg.Source == "" {
		log.Error("[dns/hosts/%s] Provider misconfigured: 'source' is required and was not set in config. Refusing to start.", profileName)
		return nil, fmt.Errorf("hosts provider: 'source' is required in config")
	}
	if cfg.Mode == 0 {
		cfg.Mode = 0644
	}
	logPrefix := fmt.Sprintf("[dns/hosts/%s]", profileName)
	log.Debug("%s Provider loaded with source=%s user=%s group=%s mode=%o", logPrefix, cfg.Source, cfg.User, cfg.Group, cfg.Mode)
	return &HostsProvider{source: cfg.Source, logPrefix: logPrefix, profile: profileName}, nil
}

func (h *HostsProvider) CreateOrUpdateRecord(domain, fqdn, target, recordType string, ttl int, overwrite bool) error {
	if recordType == "CNAME" {
		log.Verbose("%s Flattening CNAME %s -> %s: resolving to A/AAAA for hosts file", h.logPrefix, fqdn, target)
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			log.Warn("%s Failed to resolve CNAME target %s for %s: %v", h.logPrefix, target, fqdn, err)
			return fmt.Errorf("cannot flatten CNAME: failed to resolve %s: %v", target, err)
		}
		var lastErr error
		for _, ip := range ips {
			recType := "A"
			if ip.To4() == nil {
				recType = "AAAA"
			}
			err := h.EnsureDNS(domain, fqdn, ip.String(), recType)
			if err != nil {
				log.Warn("%s Failed to write flattened %s record for %s -> %s: %v", h.logPrefix, recType, fqdn, ip.String(), err)
				lastErr = err
			} else {
				log.Info("%s Flattened CNAME %s -> %s as %s %s", h.logPrefix, fqdn, target, recType, ip.String())
			}
		}
		return lastErr
	}
	log.Verbose("%s Writing %s record for %s -> %s", h.logPrefix, recordType, fqdn, target)
	return h.EnsureDNS(domain, fqdn, target, recordType)
}

func (h *HostsProvider) RemoveRecord(domain, fqdn, recordType string) error {
	return h.EnsureDNSRemove(domain, fqdn)
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

	if recordType != "A" && recordType != "AAAA" {
		return fmt.Errorf("hosts provider only supports A and AAAA records, got %s", recordType)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	lines, err := h.readLines()
	if err != nil {
		return err
	}

	fqdn = strings.ToLower(fqdn)
	updated := false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == fqdn {
			lines[i] = fmt.Sprintf("%s %s", ip, fqdn)
			updated = true
		}
	}
	if !updated {
		lines = append(lines, fmt.Sprintf("%s %s", ip, fqdn))
	}
	return h.writeLines(lines)
}

func (h *HostsProvider) EnsureDNSRemove(domain, fqdn string) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	lines, err := h.readLines()
	if err != nil {
		return err
	}
	fqdn = strings.ToLower(fqdn)
	newLines := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == fqdn {
			continue
		}
		newLines = append(newLines, line)
	}
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
		lines = append(lines, scanner.Text())
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

	// Write records
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			log.Error("%s Failed to write line to hosts file %s: %v", h.logPrefix, h.source, err)
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

// getConfig returns the config for this provider (stub: adapt as needed for your config system)
func (h *HostsProvider) getConfig() HostsProviderConfig {
	// TODO: wire this to your config system if needed
	return HostsProviderConfig{
		Source: h.source,
		Mode:   0644,
	}
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
