// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package system

import (
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input/common"
	"github.com/nfrastack/herald/internal/log"
	state "github.com/nfrastack/herald/internal/state"
	"github.com/nfrastack/herald/internal/util"

	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"strings"
	"time"
)

var defaultVirtualInterfaces = []string{
	"docker*",
	"veth*",
	"br-*",
	"virbr*",
	"cni*",
	"cali*",
	"flannel*",
	"tun*",
	"tap*",
	"wg*",
	"lo",
}

type SystemProvider struct {
	profileName        string
	logPrefix          string
	logger             *log.ScopedLogger
	hostname           string
	domain             string
	additionalDomains  []string
	interfaces         []string
	wantIPv4           bool
	wantIPv6           bool
	address            string
	addressFile        string
	discoverURL        string
	timeout            time.Duration
	interval           time.Duration
	processExisting    bool
	recordRemoveOnStop bool
	ctx                context.Context
	cancel             context.CancelFunc
	running            bool
	lastKnownRecords   map[string]string
	outputWriter       domain.OutputWriter
	outputSyncer       domain.OutputSyncer
	httpClient         *http.Client
}

func stringOption(config map[string]interface{}, key string) string {
	if config == nil {
		return ""
	}
	if v, ok := config[key]; ok {
		switch t := v.(type) {
		case string:
			return util.ReadSecretValue(t)
		case []byte:
			return string(t)
		default:
			return fmt.Sprintf("%v", t)
		}
	}
	return ""
}

func boolOption(config map[string]interface{}, key string, def bool) bool {
	if config == nil {
		return def
	}
	if v, ok := config[key]; ok {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			s := strings.ToLower(strings.TrimSpace(util.ReadSecretValue(t)))
			if s == "true" || s == "1" || s == "yes" || s == "on" {
				return true
			}
			if s == "false" || s == "0" || s == "no" || s == "off" {
				return false
			}
		}
	}
	return def
}

func durationOption(config map[string]interface{}, key string, def time.Duration) time.Duration {
	if config == nil {
		return def
	}
	if v, ok := config[key]; ok {
		switch t := v.(type) {
		case string:
			if d, err := time.ParseDuration(strings.TrimSpace(t)); err == nil && d > 0 {
				return d
			}
		case int:
			if t > 0 {
				return time.Duration(t) * time.Second
			}
		case int64:
			if t > 0 {
				return time.Duration(t) * time.Second
			}
		case float64:
			if t > 0 {
				return time.Duration(t * float64(time.Second))
			}
		}
	}
	return def
}

func listOption(config map[string]interface{}, key string) []string {
	if config == nil {
		return nil
	}
	v, ok := config[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return common.ParseDomainList(util.ReadSecretValue(t))
	default:
		return nil
	}
}

func NewProvider(profileName string, config map[string]interface{}, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (*SystemProvider, error) {
	logPrefix := common.BuildLogPrefix("system", profileName)

	hostname := strings.ToLower(strings.TrimSpace(stringOption(config, "hostname")))
	if hostname == "" {
		osHostname, err := os.Hostname()
		if err != nil || strings.TrimSpace(osHostname) == "" {
			return nil, fmt.Errorf("%s hostname is required (set 'hostname' or ensure the OS hostname is available)", logPrefix)
		}
		hostname = strings.ToLower(strings.TrimSpace(osHostname))
	}
	if i := strings.Index(hostname, "."); i >= 0 {
		hostname = hostname[:i]
	}
	if hostname == "" {
		return nil, fmt.Errorf("%s hostname is required", logPrefix)
	}

	domain := strings.TrimSpace(util.ReadSecretValue(stringOption(config, "domain")))
	if domain == "" {
		return nil, fmt.Errorf("%s domain is required", logPrefix)
	}
	additionalDomains := common.ParseDomainList(util.ReadSecretValue(stringOption(config, "additional_domains")))

	interfaces := listOption(config, "interfaces")

	families := listOption(config, "families")
	wantIPv4 := false
	wantIPv6 := false
	if len(families) == 0 {
		wantIPv4 = true
	} else {
		for _, f := range families {
			switch strings.ToLower(strings.TrimSpace(f)) {
			case "ipv4", "inet4", "4", "v4":
				wantIPv4 = true
			case "ipv6", "inet6", "6", "v6":
				wantIPv6 = true
			case "both", "all":
				wantIPv4 = true
				wantIPv6 = true
			}
		}
		if !wantIPv4 && !wantIPv6 {
			wantIPv4 = true
		}
	}

	timeout := durationOption(config, "timeout", 10*time.Second)
	interval := durationOption(config, "interval", 300*time.Second)
	processExisting := boolOption(config, "process_existing", true)
	recordRemoveOnStop := boolOption(config, "record_remove_on_stop", true)

	address := strings.TrimSpace(stringOption(config, "address"))
	if address != "" {
		if _, err := netip.ParseAddr(address); err != nil {
			return nil, fmt.Errorf("%s invalid address '%s': %v", logPrefix, address, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	logLevel := stringOption(config, "log_level")
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	return &SystemProvider{
		profileName:        profileName,
		logPrefix:          logPrefix,
		logger:             scopedLogger,
		hostname:           hostname,
		domain:             domain,
		additionalDomains:  additionalDomains,
		interfaces:         interfaces,
		wantIPv4:           wantIPv4,
		wantIPv6:           wantIPv6,
		address:            address,
		addressFile:        strings.TrimSpace(stringOption(config, "address_file")),
		discoverURL:        strings.TrimSpace(stringOption(config, "discover_url")),
		timeout:            timeout,
		interval:           interval,
		processExisting:    processExisting,
		recordRemoveOnStop: recordRemoveOnStop,
		ctx:                ctx,
		cancel:             cancel,
		lastKnownRecords:   make(map[string]string),
		outputWriter:       outputWriter,
		outputSyncer:       outputSyncer,
		httpClient:         &http.Client{Timeout: timeout},
	}, nil
}

func (p *SystemProvider) GetName() string {
	return "system"
}

func (p *SystemProvider) StartPolling() error {
	if p.running {
		return nil
	}
	p.running = true
	p.logger.With("action", "provider.poll").Debug("system polling with interval: %v", p.interval)
	go p.pollLoop()
	return nil
}

func (p *SystemProvider) StopPolling() error {
	p.running = false
	p.cancel()
	return nil
}

func (p *SystemProvider) IsRunning() bool {
	return p.running
}

func (p *SystemProvider) matchInterface(name string, patterns []string, hasExplicitIncludes bool) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "!") {
			if ok, _ := path.Match(strings.TrimPrefix(pattern, "!"), name); ok {
				return false
			}
			continue
		}
		if pattern == name {
			return true
		}
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}
	if !hasExplicitIncludes {
		for _, blocked := range defaultVirtualInterfaces {
			if ok, _ := path.Match(blocked, name); ok {
				return false
			}
		}
		return true
	}
	return false
}

func usableAddress(addr netip.Addr, wantIPv4, wantIPv6 bool) (string, bool) {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return "", false
	}
	if addr.Is4() {
		if !wantIPv4 {
			return "", false
		}
		return addr.String(), true
	}
	if !wantIPv6 {
		return "", false
	}
	return addr.WithZone("").String(), true
}

func (p *SystemProvider) interfaceTargets() map[string]string {
	targets := make(map[string]string)
	var includes []string
	for _, pattern := range p.interfaces {
		if pattern == "" || strings.HasPrefix(pattern, "!") {
			continue
		}
		includes = append(includes, pattern)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		p.logger.With("action", "sync.fail").Error("failed to list interfaces: %v", err)
		return targets
	}
	for _, iface := range ifaces {
		if !p.matchInterface(iface.Name, p.interfaces, len(includes) > 0) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch t := a.(type) {
			case *net.IPNet:
				ip = t.IP
			case *net.IPAddr:
				ip = t.IP
			default:
				continue
			}
			addr, err := netip.ParseAddr(ip.String())
			if err != nil {
				continue
			}
			if target, ok := usableAddress(addr, p.wantIPv4, p.wantIPv6); ok {
				recordType := "A"
				if strings.Contains(target, ":") {
					recordType = "AAAA"
				}
				if _, exists := targets[recordType]; !exists {
					targets[recordType] = target
				}
			}
		}
	}
	return targets
}

func firstUsableIP(body string, wantIPv4, wantIPv6 bool) string {
	for _, field := range strings.Fields(body) {
		field = strings.Trim(strings.TrimPrefix(field, "ip="), "\"',;")
		addr, err := netip.ParseAddr(field)
		if err != nil {
			continue
		}
		if target, ok := usableAddress(addr, wantIPv4, wantIPv6); ok {
			return target
		}
	}
	return ""
}

func (p *SystemProvider) discoveredTarget() string {
	if p.discoverURL == "" {
		return ""
	}
	req, err := http.NewRequestWithContext(p.ctx, http.MethodGet, p.discoverURL, nil)
	if err != nil {
		p.logger.With("action", "sync.fail").Warn("discovery request failed: %v", err)
		return ""
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.logger.With("action", "sync.fail").Warn("discovery failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.logger.With("action", "sync.fail").Warn("discovery status %d", resp.StatusCode)
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		p.logger.With("action", "sync.fail").Warn("discovery read failed: %v", err)
		return ""
	}
	target := firstUsableIP(string(body), p.wantIPv4, p.wantIPv6)
	if target == "" {
		p.logger.With("action", "sync.fail").Warn("discovery response held no usable IP")
	}
	return target
}

func (p *SystemProvider) fileTarget() string {
	if p.addressFile == "" {
		return ""
	}
	raw, err := os.ReadFile(p.addressFile)
	if err != nil {
		p.logger.With("action", "sync.fail").Warn("address file unreadable: %v", err)
		return ""
	}
	target := firstUsableIP(string(raw), p.wantIPv4, p.wantIPv6)
	if target == "" {
		p.logger.With("action", "sync.fail").Warn("address file held no usable IP")
	}
	return target
}

func (p *SystemProvider) currentTargets() map[string]string {
	if p.address != "" {
		targets := make(map[string]string)
		if target, ok := usableAddress(mustParseAddr(p.address), p.wantIPv4, p.wantIPv6); ok {
			recordType := "A"
			if strings.Contains(target, ":") {
				recordType = "AAAA"
			}
			targets[recordType] = target
		}
		return targets
	}
	known := make(map[string]string)
	for key, target := range p.lastKnownRecords {
		known[key] = target
	}
	if p.addressFile != "" {
		if target := p.fileTarget(); target != "" {
			recordType := "A"
			if strings.Contains(target, ":") {
				recordType = "AAAA"
			}
			return map[string]string{recordType: target}
		}
		return known
	}
	if p.discoverURL != "" {
		if target := p.discoveredTarget(); target != "" {
			recordType := "A"
			if strings.Contains(target, ":") {
				recordType = "AAAA"
			}
			return map[string]string{recordType: target}
		}
		return known
	}
	return p.interfaceTargets()
}

func mustParseAddr(s string) netip.Addr {
	addr, _ := netip.ParseAddr(s)
	return addr
}

func (p *SystemProvider) targetDomains() []string {
	domains := []string{p.domain}
	seen := map[string]bool{p.domain: true}
	for _, d := range p.additionalDomains {
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	return domains
}

func (p *SystemProvider) pollLoop() {
	if p.processExisting {
		p.processAddresses()
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for p.running {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.processAddresses()
		}
	}
}

func (p *SystemProvider) processAddresses() {
	targets := p.currentTargets()
	current := make(map[string]string)
	for recordType, target := range targets {
		current[p.hostname+":"+recordType] = target
	}

	batchProcessor := domain.NewBatchProcessorWithProvider(p.profileName, p.profileName, p.outputWriter, p.outputSyncer)

	for key, target := range current {
		parts := strings.SplitN(key, ":", 2)
		hostname, recordType := parts[0], parts[1]
		lastTarget, known := p.lastKnownRecords[key]
		if known && lastTarget == target {
			for _, targetDomain := range p.targetDomains() {
				state.Touch(targetDomain, hostname, recordType, target, p.profileName, "")
			}
			continue
		}
		if !known {
			p.logger.With("action", "provider.event", "host", hostname).Info("added")
		} else {
			p.logger.With("action", "provider.event", "host", hostname).Info("changed: %s -> %s", lastTarget, target)
		}
		for _, targetDomain := range p.targetDomains() {
			fqdn := hostname + "." + targetDomain
			p.logger.With("action", "record.sync").Trace("record %s (%s) -> %s", fqdn, recordType, target)
			routerState := domain.RouterState{
				SourceType:           p.profileName,
				Name:                 p.profileName,
				Service:              target,
				RecordType:           recordType,
				ForceServiceAsTarget: true,
			}
			if err := batchProcessor.ProcessRecord(targetDomain, fqdn, routerState); err != nil {
				p.logger.With("action", "record.reject").Error("ensure DNS: %v", err)
				continue
			}
			state.Touch(targetDomain, hostname, recordType, target, p.profileName, "")
		}
	}

	if p.recordRemoveOnStop {
		for key, oldTarget := range p.lastKnownRecords {
			if _, exists := current[key]; exists {
				continue
			}
			parts := strings.SplitN(key, ":", 2)
			if len(parts) != 2 {
				continue
			}
			hostname, recordType := parts[0], parts[1]
			for _, targetDomain := range p.targetDomains() {
				fqdn := hostname + "." + targetDomain
				p.logMemberRemoved(fqdn)
				routerState := domain.RouterState{
					SourceType:           p.profileName,
					Name:                 p.profileName,
					Service:              oldTarget,
					RecordType:           recordType,
					ForceServiceAsTarget: true,
				}
				if err := batchProcessor.ProcessRecordRemoval(targetDomain, fqdn, routerState); err != nil {
					p.logger.With("action", "record.reject").Error("remove DNS: %v", err)
				} else {
					state.Remove(targetDomain, hostname, recordType)
				}
			}
		}
	}

	p.lastKnownRecords = current
	batchProcessor.FinalizeBatch()
}

func (p *SystemProvider) logMemberRemoved(fqdn string) {
	p.logger.With("action", "provider.event", "host", fqdn).Info("removed")
}
