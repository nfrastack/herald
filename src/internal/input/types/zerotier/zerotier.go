// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package zerotier

import (
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input/common"
	"github.com/nfrastack/herald/internal/log"
	heraldstate "github.com/nfrastack/herald/internal/state"

	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type Provider interface {
	StartPolling() error
	StopPolling() error
	GetName() string
}

type DNSEntry struct {
	Name                   string `json:"name"`
	Hostname               string `json:"hostname"`
	Domain                 string `json:"domain"`
	RecordType             string `json:"type"`
	Target                 string `json:"target"`
	TTL                    int    `json:"ttl"`
	Overwrite              bool   `json:"overwrite"`
	RecordTypeAMultiple    bool   `json:"record_type_a_multiple"`
	RecordTypeAAAAMultiple bool   `json:"record_type_aaaa_multiple"`
	SourceName             string `json:"source_name"`
}

func (d DNSEntry) GetFQDN() string {
	return d.Name
}

func (d DNSEntry) GetRecordType() string {
	return d.RecordType
}

type ZerotierProvider struct {
	apiURL                 string
	token                  string
	networkID              string
	apiType                string // "zerotier" or "ztnet"
	apiTypeDetected        bool   // true if we've already detected and cached the API type
	domain                 string
	additionalDomains      []string // extra domains to publish each member under (single poll, N writes)
	interval               time.Duration
	processExisting        bool
	recordRemoveOnStop     bool
	useAddressAsFallback   bool                // Use address as hostname when name is empty
	onlineTimeoutSeconds   int                 // Seconds to consider a member offline for ZeroTier Central
	filterConfig           common.FilterConfig // Filter configuration
	ctx                    context.Context
	cancel                 context.CancelFunc
	running                bool
	logPrefix              string
	profileName            string
	lastKnownRecords       map[string]string // hostname -> target, to track changes
	logger                 *log.ScopedLogger // provider-specific logger
	isFirstPoll            bool              // Track if this is the first poll cycle
	loggedFallbackMembers  map[string]bool   // Track members we've already logged fallback message for
	addressFallbackMembers map[string]bool   // Track which members are using address fallback (for output context)
	name                   string
	lastEntries            []DNSEntry
	domainConfigs          map[string]config.DomainConfig
	outputWriter           domain.OutputWriter // Injected dependency
	outputSyncer           domain.OutputSyncer // Injected dependency
}

func NewProvider(options map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	apiURL := common.ReadFileValue(options["api_url"])
	apiToken := common.ReadFileValue(options["api_token"])
	networkID := common.ReadFileValue(options["network_id"])
	apiType := common.ReadFileValue(options["api_type"]) // "zerotier" or "ztnet"
	domain := common.ReadFileValue(options["domain"])
	additionalDomains := common.ParseDomainList(common.ReadFileValue(options["additional_domains"]))
	interval := 60 * time.Second
	if v := options["interval"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}
	processExisting := options["process_existing"] == "true"
	recordRemoveOnStop := options["record_remove_on_stop"] == "true"
	useAddressAsFallback := options["use_address_fallback"] == "true"
	onlineTimeoutSeconds := 120 // Default to 120 seconds for online timeout
	if v := options["online_timeout_seconds"]; v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			onlineTimeoutSeconds = parsed
		}
	}

	profileName := options["name"]
	if profileName == "" {
		profileName = options["profile_name"]
	}
	if profileName == "" {
		profileName = "zerotier"
	}

	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	filterLogPrefix := fmt.Sprintf("[poll/zerotier/%s/filter]", profileName)
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions, filterLogger)
	if err != nil {
		tempLogPrefix := fmt.Sprintf("[poll/zerotier/%s]", profileName)
		log.NewScopedLogger(tempLogPrefix, "").With("action", "config.error").Debug("creating filter configuration: %v, using default", err)
		filterConfig = common.DefaultFilterConfig()
	}

	if len(filterConfig.Filters) == 0 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == common.FilterTypeNone) {
		tempLogPrefix := fmt.Sprintf("[poll/zerotier/%s]", profileName)
		log.NewScopedLogger(tempLogPrefix, "").With("action", "input.filter").Debug("default online=true filter")
		filterConfig.Filters = []common.Filter{
			{
				Type:      common.FilterTypeOnline,
				Operation: common.FilterOperationAND,
				Negate:    false,
				Conditions: []common.FilterCondition{{
					Value: "true",
					Logic: "and",
				}},
			},
		}
	}
	logLevel := options["log_level"] // Get provider-specific log level
	logPrefix := common.BuildLogPrefix("zerotier", profileName)

	if apiURL == "" {
		apiURL = "https://my.zerotier.com"
		log.NewScopedLogger(logPrefix, "").With("action", "config.load").Warn("no api_url specified, defaulting to ZeroTier Central: %s", apiURL)
	}

	if apiType == "" {
		if strings.Contains(apiURL, "my.zerotier.com") || strings.Contains(apiURL, "zerotier.com") {
			apiType = "zerotier"
			log.NewScopedLogger(logPrefix, "").With("action", "provider.init").Debug("api type 'zerotier' based on URL: %s", apiURL)
		} else {
			log.NewScopedLogger(logPrefix, "").With("action", "provider.init").Debug("custom API URL: %s, will auto-detect API type", apiURL)
		}
	}

	if apiToken == "" || networkID == "" || domain == "" {
		var missing []string
		if apiToken == "" {
			missing = append(missing, "api_token")
		}
		if networkID == "" {
			missing = append(missing, "network_id")
		}
		if domain == "" {
			missing = append(missing, "domain")
		}
		return nil, fmt.Errorf("%s missing required parameter(s): %s", logPrefix, strings.Join(missing, ", "))
	}

	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		scopedLogger.With("action", "config.load").Info("provider log_level set to: '%s'", logLevel)
	}

	if useAddressAsFallback {
		scopedLogger.With("action", "config.load").Verbose("address fallback enabled - will use member address as hostname when name is empty")
	} else {
		scopedLogger.With("action", "config.load").Debug("address fallback disabled - members without names will be skipped (enable with use_address_fallback: true)")
	}
	if onlineTimeoutSeconds != 60 {
		apiTypeName := "ZeroTier Central"
		if apiType == "ztnet" {
			apiTypeName = "ZT-Net"
		} else if strings.Contains(apiURL, "my.zerotier.com") || strings.Contains(apiURL, "zerotier.com") {
			apiTypeName = "ZeroTier Central"
		} else {
			apiTypeName = "ZeroTier API"
		}
		scopedLogger.With("action", "config.load").Verbose("%s online timeout set to %d seconds", apiTypeName, onlineTimeoutSeconds)
	}

	if onlineTimeoutSeconds < 60 {
		scopedLogger.With("action", "config.validate").Warn("online_timeout_seconds is set to %d seconds, which may cause erratic behavior due to ZeroTier Central's heartbeat timing. Consider using 60+ seconds.", onlineTimeoutSeconds)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ZerotierProvider{
		apiURL:                 apiURL,
		token:                  apiToken,
		networkID:              networkID,
		apiType:                apiType,
		domain:                 domain,
		additionalDomains:      additionalDomains,
		interval:               interval,
		processExisting:        processExisting,
		recordRemoveOnStop:     recordRemoveOnStop,
		useAddressAsFallback:   useAddressAsFallback,
		onlineTimeoutSeconds:   onlineTimeoutSeconds,
		filterConfig:           filterConfig,
		ctx:                    ctx,
		cancel:                 cancel,
		logPrefix:              logPrefix,
		profileName:            profileName,
		lastKnownRecords:       make(map[string]string),
		logger:                 scopedLogger,
		isFirstPoll:            true,                  // Initialize as first poll
		loggedFallbackMembers:  make(map[string]bool), // Initialize fallback tracking
		addressFallbackMembers: make(map[string]bool), // Initialize address fallback tracking
		outputWriter:           outputWriter,
		outputSyncer:           outputSyncer,
	}, nil
}

func (p *ZerotierProvider) StartPolling() error {
	if p.running {
		p.logger.With("action", "provider.poll").Warn("already running")
		return nil
	}
	p.logger.With("action", "provider.poll").Debug("zerotier polling loop")
	p.running = true
	go p.pollLoop()
	return nil
}

func (p *ZerotierProvider) StopPolling() error {
	p.running = false
	p.cancel()
	return nil
}

func (p *ZerotierProvider) IsRunning() bool {
	return p.running
}

func (p *ZerotierProvider) GetDNSEntries() ([]DNSEntry, error) {
	p.logger.With("action", "provider.poll").Trace("getDNSEntries")
	return p.fetchMembers()
}

func (p *ZerotierProvider) pollLoop() {
	p.logger.With("action", "provider.poll").Debug("performing initial poll immediately on startup")
	if p.processExisting {
		p.logger.With("action", "sync.start").Trace("existing Zerotier members on startup (process_existing=true)")
		entries, err := p.fetchMembers()
		if err == nil {
			_ = p.updateDNSEntries(entries, nil)
			p.lastEntries = entries
		}
	} else {
		p.logger.With("action", "sync.start").Trace("poll on startup (process_existing=false), inventory only")
		entries, err := p.fetchMembers()
		if err == nil {
			p.lastKnownRecords = make(map[string]string)
			for _, entry := range entries {
				key := entry.GetFQDN() + ":" + entry.GetRecordType()
				p.lastKnownRecords[key] = entry.Target
			}
			p.lastEntries = entries
		}
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for p.running {
		<-ticker.C
		entries, err := p.fetchMembers()
		if err == nil {
			_ = p.updateDNSEntries(entries, p.lastEntries)
			p.lastEntries = entries
		}
	}
}

func (p *ZerotierProvider) logMemberAdded(name string) {
	p.logger.With("action", "provider.event", "member", name).Info("added: %s", name)
}

func (p *ZerotierProvider) logMemberRemoved(name string) {
	p.logger.With("action", "provider.event", "member", name).Info("removed: %s", name)
}

func (p *ZerotierProvider) targetDomains() []string {
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

func (p *ZerotierProvider) resolveRealDomain(domainKey string) string {
	realDomain := domainKey
	domainConfig := config.GetDomainConfig(domainKey)
	p.logger.With("action", "domain.match").Debug("domainConfig for key '%s': %+v", domainKey, domainConfig)
	if domainConfig != nil {
		if d, ok := domainConfig["domain"]; ok {
			realDomain = d
			p.logger.With("action", "domain.match").Trace("domain config key '%s' to real domain name '%s'", domainKey, realDomain)
		} else {
			p.logger.With("action", "domain.skip").Debug("domain config for key '%s' does not contain a 'domain' field, using as-is", domainKey)
		}
	} else {
		p.logger.With("action", "domain.skip").Debug("unresolved domain config key '%s', using as-is", domainKey)
	}
	return realDomain
}

func shortHostname(entry DNSEntry, primaryDomain string) string {
	if entry.Hostname != "" {
		return entry.Hostname
	}
	name := strings.TrimSuffix(entry.GetFQDN(), ".")
	if primaryDomain != "" {
		if name == primaryDomain {
			return "@"
		}
		if strings.HasSuffix(name, "."+primaryDomain) {
			return strings.TrimSuffix(name, "."+primaryDomain)
		}
	}
	if idx := strings.Index(name, "."); idx != -1 {
		return name[:idx]
	}
	return name
}

func (p *ZerotierProvider) publishEntry(batchProcessor *domain.BatchProcessor, entry DNSEntry, remove bool) {
	hostname := shortHostname(entry, p.domain)
	state := domain.RouterState{
		SourceType:           p.profileName, // Use the provider/profile name as source
		Name:                 p.profileName,
		Service:              entry.Target,
		RecordType:           entry.RecordType,
		ForceServiceAsTarget: true, // VPN providers always use Service IP as target
	}

	for _, targetDomain := range p.targetDomains() {
		realDomain := p.resolveRealDomain(targetDomain)
		fqdnNoDot := hostname + "." + realDomain
		if hostname == "" || hostname == "@" {
			fqdnNoDot = realDomain
		}
		if remove {
			p.logger.With("action", "record.delete", "domain", realDomain, "fqdn", fqdnNoDot).Trace("processRecordRemoval: %+v", state)
			if err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state); err != nil {
				p.logger.With("action", "record.reject").Error("remove DNS for '%s': %v", fqdnNoDot, err)
			} else {
				heraldstate.Remove(realDomain, hostname, entry.RecordType)
			}
		} else {
			p.logger.With("action", "record.create", "domain", realDomain, "fqdn", fqdnNoDot).Trace("processRecord: %+v", state)
			if err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state); err != nil {
				p.logger.With("action", "record.reject").Error("ensure DNS for '%s': %v", fqdnNoDot, err)
			}
			heraldstate.Touch(realDomain, hostname, entry.RecordType, entry.Target, p.profileName, "")
		}
	}
}

func (p *ZerotierProvider) updateDNSEntries(currentEntries []DNSEntry, lastEntries []DNSEntry) error {
	current := make(map[string]DNSEntry)
	for _, entry := range currentEntries {
		key := entry.GetFQDN() + ":" + entry.GetRecordType()
		current[key] = entry
	}

	last := make(map[string]DNSEntry)
	for _, entry := range lastEntries {
		key := entry.GetFQDN() + ":" + entry.GetRecordType()
		last[key] = entry
	}

	batchLogPrefix := fmt.Sprintf("[domain/%s/%s]", p.domain, p.profileName)
	batchProcessor := domain.NewBatchProcessorWithProvider(batchLogPrefix, p.profileName, p.outputWriter, p.outputSyncer)

	for key, entry := range current {
		if lastEntry, exists := last[key]; !exists {
			p.logMemberAdded(entry.GetFQDN())
			p.publishEntry(batchProcessor, entry, false)
		} else {
			if entry.Target != lastEntry.Target || entry.TTL != lastEntry.TTL || entry.RecordType != lastEntry.RecordType {
				p.logger.With("action", "provider.event", "member", entry.GetFQDN()).Info("changed: %s (target: %s -> %s, ttl: %d -> %d, type: %s -> %s)", entry.GetFQDN(), lastEntry.Target, entry.Target, lastEntry.TTL, entry.TTL, lastEntry.RecordType, entry.RecordType)
				p.publishEntry(batchProcessor, entry, false)
			} else {
				hostname := shortHostname(entry, p.domain)
				for _, targetDomain := range p.targetDomains() {
					realDomain := p.resolveRealDomain(targetDomain)
					heraldstate.Touch(realDomain, hostname, entry.RecordType, entry.Target, p.profileName, "")
				}
			}
		}
	}

	for key, entry := range last {
		if _, exists := current[key]; !exists {
			p.logMemberRemoved(entry.GetFQDN())
			p.publishEntry(batchProcessor, entry, true)
		}
	}

	batchProcessor.FinalizeBatch()
	return nil
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func diffKeys(old, new map[string]struct{}) (added, removed []string) {
	for k := range new {
		if _, ok := old[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range old {
		if _, ok := new[k]; !ok {
			removed = append(removed, k)
		}
	}
	return
}

func (p *ZerotierProvider) fetchMembers() ([]DNSEntry, error) {
	p.logger.With("action", "provider.poll").Trace("fetchMembers (apiType=%s, detected=%v)", p.apiType, p.apiTypeDetected)
	if !p.apiTypeDetected {
		p.logger.With("action", "provider.init").Debug("ZTNet API detection")
		entries, err := p.fetchZTNetMembers()
		if err == nil && len(entries) > 0 {
			p.apiType = "ztnet"
			p.apiTypeDetected = true
			p.logger.With("action", "provider.init").Verbose("ZTNet API")
			return entries, nil
		} else if err != nil {
			p.logger.With("action", "provider.init").Debug("ZTNet API error: %v", err)
		}
		p.logger.With("action", "provider.init").Debug("ZTNet API not detected, falling back to Zerotier Central")
		entries, err = p.fetchZerotierMembers()
		if err == nil && len(entries) > 0 {
			p.apiType = "zerotier"
			p.apiTypeDetected = true
			p.logger.With("action", "provider.init").Verbose("Zerotier Central API")
			return entries, nil
		} else if err != nil {
			p.logger.With("action", "provider.init").Debug("Zerotier Central API error: %v", err)
		}
		p.logger.With("action", "sync.fail").Error("no working Zerotier API (tried ZTNet and Zerotier Central)")
		return nil, fmt.Errorf("could not detect working Zerotier API (tried ZTNet and Zerotier Central)")
	}
	if p.apiType == "ztnet" {
		return p.fetchZTNetMembers()
	}
	return p.fetchZerotierMembers()
}

func (p *ZerotierProvider) fetchZerotierMembers() ([]DNSEntry, error) {
	p.logger.With("action", "provider.poll").Debug("Zerotier members from %s", p.apiURL)

	networkid := p.networkID
	parts := strings.Split(networkid, ":")
	if len(parts) >= 2 { // It can be 2 or 3 parts for ZT-Net format
		networkid = parts[len(parts)-1] // The actual network ID is always the last part
	}
	url := strings.TrimRight(p.apiURL, "/") + "/api/network/" + networkid + "/member"
	p.logger.With("action", "provider.poll").Trace("member API URL: %s", url)

	headers := map[string]string{
		"Authorization": "bearer " + p.token,
	}
	body, err := common.FetchRemoteResourceWithHeaders(url, "", "", headers, p.logPrefix)
	if err != nil {
		return nil, err
	}
	p.logger.With("action", "provider.poll").Trace("zerotier members API response: %s", string(body))

	var members []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		LastSeen int64  `json:"lastSeen"`
		Config   struct {
			IPAssignments []string `json:"ipAssignments"`
			Authorized    bool     `json:"authorized"`
			Address       string   `json:"address"` // For fallback hostname
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("failed to parse Zerotier members response: %w", err)
	}

	domain := p.domain
	if domain == "" {
		p.logger.With("action", "config.error").Warn("no domain configured for Zerotier, skipping DNS entry creation")
		return nil, nil
	}

	p.logger.With("action", "input.filter").Debug("members using filter system")
	var entries []DNSEntry
	for _, m := range members {
		currentTime := time.Now().Unix() * 1000 // Convert to milliseconds
		timeoutMs := int64(p.onlineTimeoutSeconds * 1000)
		timeSinceLastSeen := currentTime - m.LastSeen
		isOnline := timeSinceLastSeen < timeoutMs

		p.logger.With("action", "input.filter", "member", m.Name).Debug("online check: lastSeen=%dms ago, timeout=%dms (%ds), isOnline=%v",
			timeSinceLastSeen, timeoutMs, p.onlineTimeoutSeconds, isOnline)

		p.logger.With("action", "input.filter").Trace("member: id=%s, name=%s, online=%v (lastSeen %dms ago, timeout %dms), authorized=%v, ips=%v, address=%s", m.ID, m.Name, isOnline, timeSinceLastSeen, timeoutMs, m.Config.Authorized, m.Config.IPAssignments, m.Config.Address)

		memberData := ZerotierCentralMember{
			ID:            m.ID,
			Name:          m.Name,
			LastSeen:      m.LastSeen,
			Online:        isOnline,
			IPAssignments: m.Config.IPAssignments,
			Authorized:    m.Config.Authorized,
			Address:       m.Config.Address,
		}

		if !EvaluateZerotierFilters(p.filterConfig, memberData) {
			p.logger.With("action", "input.filter", "member", m.Name).Trace("did not match filters, skipping")
			continue
		}

		hostname := m.Name
		if hostname == "" {
			if p.useAddressAsFallback && m.Config.Address != "" {
				hostname = m.Config.Address
				p.addressFallbackMembers[hostname] = true
				if !p.loggedFallbackMembers[hostname] {
					p.logger.With("action", "input.pass", "member", hostname).Verbose("has no name, using address as hostname")
					p.loggedFallbackMembers[hostname] = true
				} else {
					p.logger.With("action", "input.pass", "member", hostname).Debug("has no name, using address as hostname")
				}
			} else {
				p.logger.With("action", "input.filter").Warn("member %s - no name provided and use_address_fallback not enabled", m.ID)
				continue
			}
		}

		if len(m.Config.IPAssignments) == 0 {
			p.logger.With("action", "input.filter").Debug("member %s (no IP assignments)", hostname)
			continue
		}

		for _, ip := range m.Config.IPAssignments {
			recordType := "A"
			if strings.Contains(ip, ":") {
				recordType = "AAAA"
			}
			entry := DNSEntry{
				Hostname:   hostname,
				Domain:     p.domain, // Force use of configured domain
				RecordType: recordType,
				Target:     ip,
				TTL:        120,
			}
			entry.Name = entry.Hostname + "." + entry.Domain
			entries = append(entries, entry)
		}
	}
	p.logger.With("action", "sync.done").Debug("%d DNS entries", len(entries))
	return entries, nil
}

func (p *ZerotierProvider) fetchZTNetMembers() ([]DNSEntry, error) {
	p.logger.With("action", "provider.poll").Debug("ZT-Net members from %s", p.apiURL)
	org := ""
	networkid := p.networkID
	parts := strings.Split(networkid, ":")
	if len(parts) == 3 {
		org = parts[0]
		networkid = parts[2]
	} else if len(parts) == 2 {
		networkid = parts[1]
	}

	var url string
	if org != "" {
		url = strings.TrimRight(p.apiURL, "/") + "/api/v1/org/" + org + "/network/" + networkid + "/member/"
	} else {
		url = strings.TrimRight(p.apiURL, "/") + "/api/v1/network/" + networkid + "/member/"
	}
	p.logger.With("action", "provider.poll").Trace("ZT-Net members API URL: %s", url)

	headers := map[string]string{
		"x-ztnet-auth": p.token,
	}
	body, err := common.FetchRemoteResourceWithHeaders(url, "", "", headers, p.logPrefix)
	if err != nil {
		return nil, err
	}
	p.logger.With("action", "provider.poll").Trace("ZT-Net members API response: %s", string(body))
	var members []struct {
		Name            string      `json:"name"`
		LastSeen        string      `json:"lastSeen"` // ISO timestamp for ZT-Net
		Online          bool        `json:"online"`
		IPs             []string    `json:"ipAssignments"`
		Authorized      bool        `json:"authorized"`
		Tags            StringArray `json:"tags"`
		ID              string      `json:"id"`
		Address         string      `json:"address"`
		NodeID          int         `json:"nodeid"`
		PhysicalAddress string      `json:"physicalAddress"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("failed to parse ZT-Net members response: %w", err)
	}

	domain := p.domain
	if domain == "" {
		p.logger.With("action", "config.error").Warn("no domain configured for ZT-Net, skipping DNS entry creation")
		return nil, nil
	}

	p.logger.With("action", "input.filter").Debug("members using filter system")
	var entries []DNSEntry
	for _, m := range members {
		isOnline := true // Default to online if we can't parse lastSeen
		if m.LastSeen != "" {
			if lastSeenTime, err := time.Parse(time.RFC3339, m.LastSeen); err == nil {
				timeSinceLastSeen := time.Since(lastSeenTime)
				timeoutDuration := time.Duration(p.onlineTimeoutSeconds) * time.Second
				isOnline = timeSinceLastSeen < timeoutDuration

				p.logger.With("action", "input.filter", "member", m.Name).Debug("online check: lastSeen=%v ago, timeout=%v (%ds), isOnline=%v",
					timeSinceLastSeen.Truncate(time.Second), timeoutDuration, p.onlineTimeoutSeconds, isOnline)
			} else {
				p.logger.With("action", "input.filter", "member", m.Name).Warn("parse lastSeen timestamp: %s", m.LastSeen)
				isOnline = m.Online
			}
		} else {
			isOnline = m.Online
		}

		p.logger.With("action", "input.filter").Trace("member: id=%s, name=%s, online=%v, authorized=%v, tags=%v, address=%s, nodeid=%d, physicalAddress=%s", m.ID, m.Name, isOnline, m.Authorized, m.Tags, m.Address, m.NodeID, m.PhysicalAddress)

		memberData := ZTNetMember{
			ID:              m.ID,
			Name:            m.Name,
			LastSeen:        m.LastSeen,
			Online:          isOnline,
			IPAssignments:   m.IPs,
			Authorized:      m.Authorized,
			Tags:            m.Tags,
			Address:         m.Address,
			NodeID:          m.NodeID,
			PhysicalAddress: m.PhysicalAddress,
		}

		if !EvaluateZerotierFilters(p.filterConfig, memberData) {
			p.logger.With("action", "input.filter", "member", m.Name).Trace("did not match filters, skipping")
			continue
		}

		hostname := m.Name
		if hostname == "" {
			if p.useAddressAsFallback && m.Address != "" {
				hostname = m.Address
				p.addressFallbackMembers[hostname] = true
				if !p.loggedFallbackMembers[hostname] {
					p.logger.With("action", "input.pass", "member", hostname).Verbose("has no name, using address as hostname")
					p.loggedFallbackMembers[hostname] = true
				} else {
					p.logger.With("action", "input.pass", "member", hostname).Debug("has no name, using address as hostname")
				}
			} else {
				p.logger.With("action", "input.filter").Warn("member %s - no name provided and use_address_fallback not enabled", m.ID)
				continue
			}
		}

		if len(m.IPs) == 0 {
			p.logger.With("action", "input.filter").Debug("member %s (no IP assignments)", hostname)
			continue
		}

		for _, ip := range m.IPs {
			recordType := "A"
			if strings.Contains(ip, ":") {
				recordType = "AAAA"
			}
			fqdn := hostname + "." + domain
			p.logger.With("action", "record.create").Debug("FQDN: hostname='%s', domain='%s', fqdn='%s'", hostname, domain, fqdn)
			entry := DNSEntry{
				Name:       fqdn,
				Hostname:   hostname,
				Domain:     domain,
				RecordType: recordType,
				Target:     ip,
				TTL:        120,
			}
			entries = append(entries, entry)
		}
	}
	p.logger.With("action", "sync.done").Debug("%d DNS entries", len(entries))
	return entries, nil
}

type ZerotierCentralMember struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	LastSeen      int64    `json:"lastSeen"`
	Online        bool     `json:"online"`
	IPAssignments []string `json:"ipAssignments"`
	Authorized    bool     `json:"authorized"`
	Address       string   `json:"address"`
}

type StringArray []string

func (sa *StringArray) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*sa = StringArray{s}
		return nil
	}

	var strs []string
	if err := json.Unmarshal(b, &strs); err == nil {
		*sa = StringArray(strs)
		return nil
	}

	var arr []interface{}
	if err := json.Unmarshal(b, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, el := range arr {
			switch v := el.(type) {
			case string:
				out = append(out, v)
			case float64:
				if v == math.Trunc(v) {
					out = append(out, fmt.Sprintf("%d", int64(v)))
				} else {
					out = append(out, fmt.Sprintf("%v", v))
				}
			case []interface{}:
				if len(v) >= 2 {
					a := formatInterfaceValue(v[0])
					b := formatInterfaceValue(v[1])
					out = append(out, fmt.Sprintf("%s:%s", a, b))
				} else {
					out = append(out, fmt.Sprint(v))
				}
			default:
				out = append(out, fmt.Sprint(v))
			}
		}
		*sa = StringArray(out)
		return nil
	}

	return fmt.Errorf("invalid tags field: %s", string(b))
}

func formatInterfaceValue(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == math.Trunc(x) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	default:
		return fmt.Sprint(x)
	}
}

type ZTNetMember struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	LastSeen        string      `json:"lastSeen"`
	Online          bool        `json:"online"`
	IPAssignments   []string    `json:"ipAssignments"`
	Authorized      bool        `json:"authorized"`
	Tags            StringArray `json:"tags"`
	Address         string      `json:"address"`
	NodeID          int         `json:"nodeid"`
	PhysicalAddress string      `json:"physicalAddress"`
}

func EvaluateZerotierFilters(filterConfig common.FilterConfig, member interface{}) bool {
	return filterConfig.Evaluate(member, func(filter common.Filter, entry any) bool {
		return evaluateZerotierFilter(filter, entry)
	})
}

func evaluateZerotierFilter(filter common.Filter, member interface{}) bool {
	switch filter.Type {
	case common.FilterTypeOnline:
		for _, condition := range filter.Conditions {
			expected := strings.ToLower(condition.Value) == "true"
			switch m := member.(type) {
			case ZerotierCentralMember:
				if m.Online != expected {
					return false
				}
			case ZTNetMember:
				if m.Online != expected {
					return false
				}
			}
		}
		return true

	case common.FilterTypeName:
		for _, condition := range filter.Conditions {
			switch m := member.(type) {
			case ZerotierCentralMember:
				if !common.RegexMatch(condition.Value, m.Name) {
					return false
				}
			case ZTNetMember:
				if !common.RegexMatch(condition.Value, m.Name) {
					return false
				}
			}
		}
		return true

	case "authorized":
		for _, condition := range filter.Conditions {
			expected := strings.ToLower(condition.Value) == "true"
			switch m := member.(type) {
			case ZerotierCentralMember:
				if m.Authorized != expected {
					return false
				}
			case ZTNetMember:
				if m.Authorized != expected {
					return false
				}
			}
		}
		return true

	case common.FilterTypeTag:
		if ztnetMember, ok := member.(ZTNetMember); ok {
			for _, condition := range filter.Conditions {
				found := false
				for _, tag := range ztnetMember.Tags {
					if common.RegexMatch(condition.Value, tag) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
		return true

	case "id":
		for _, condition := range filter.Conditions {
			switch m := member.(type) {
			case ZerotierCentralMember:
				if !common.RegexMatch(condition.Value, m.ID) {
					return false
				}
			case ZTNetMember:
				if !common.RegexMatch(condition.Value, m.ID) {
					return false
				}
			}
		}
		return true

	case "address":
		for _, condition := range filter.Conditions {
			switch m := member.(type) {
			case ZerotierCentralMember:
				if !common.RegexMatch(condition.Value, m.Address) {
					return false
				}
			case ZTNetMember:
				if !common.RegexMatch(condition.Value, m.Address) {
					return false
				}
			}
		}
		return true

	case "nodeid":
		if ztnetMember, ok := member.(ZTNetMember); ok {
			for _, condition := range filter.Conditions {
				nodeIDStr := fmt.Sprintf("%d", ztnetMember.NodeID)
				if !common.RegexMatch(condition.Value, nodeIDStr) {
					return false
				}
			}
		}
		return true

	case "ipAssignments":
		for _, condition := range filter.Conditions {
			found := false
			switch m := member.(type) {
			case ZerotierCentralMember:
				for _, ip := range m.IPAssignments {
					if common.RegexMatch(condition.Value, ip) {
						found = true
						break
					}
				}
			case ZTNetMember:
				for _, ip := range m.IPAssignments {
					if common.RegexMatch(condition.Value, ip) {
						found = true
						break
					}
				}
			}
			if !found {
				return false
			}
		}
		return true

	case "physicalAddress":
		if ztnetMember, ok := member.(ZTNetMember); ok {
			for _, condition := range filter.Conditions {
				if !common.RegexMatch(condition.Value, ztnetMember.PhysicalAddress) {
					return false
				}
			}
		}
		return true

	default:
		return true
	}
}

func detectAPIType(apiURL, networkID, apiToken string) string {
	org := ""
	networkid := networkID
	parts := strings.Split(networkID, ":")
	if len(parts) == 3 {
		org = parts[0]
		networkid = parts[2]
	} else if len(parts) == 2 {
		networkid = parts[1]
	}

	var url string
	if org != "" {
		url = strings.TrimRight(apiURL, "/") + "/api/v1/org/" + org + "/network/" + networkid + "/member/"
	} else {
		url = strings.TrimRight(apiURL, "/") + "/api/v1/network/" + networkid + "/member/"
	}

	headers := map[string]string{
		"x-ztnet-auth": apiToken,
	}
	body, err := common.FetchRemoteResourceWithHeaders(url, "", "", headers, "")
	if err == nil && len(body) > 0 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "ipAssignments") || strings.Contains(bodyStr, "authorized") {
			return "ztnet"
		}
	}

	return "zerotier"
}

func (zp *ZerotierProvider) GetName() string {
	return "zerotier"
}
