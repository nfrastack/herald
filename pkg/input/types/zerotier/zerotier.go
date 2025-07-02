// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package zerotier

import (
	inputtypes "herald/pkg/input/types"
	"herald/pkg/input/registry"
	"herald/pkg/config"
	"herald/pkg/domain"
	"herald/pkg/input/common"
	"herald/pkg/log"

	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ZerotierProvider struct {
	apiURL                 string
	token                  string
	networkID              string
	apiType                string // "zerotier" or "ztnet"
	apiTypeDetected        bool   // true if we've already detected and cached the API type
	domain                 string
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
	lastEntries            []inputtypes.DNSEntry
	domainConfigs          map[string]config.DomainConfig
	outputWriter           domain.OutputWriter // Injected dependency
	outputSyncer           domain.OutputSyncer // Injected dependency
}

func NewProvider(options map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (inputtypes.Provider, error) {
	// Use file:// and env:// support for all configuration options
	apiURL := common.ReadFileValue(options["api_url"])
	apiToken := common.ReadFileValue(options["api_token"])
	networkID := common.ReadFileValue(options["network_id"])
	apiType := common.ReadFileValue(options["api_type"]) // "zerotier" or "ztnet"
	domain := common.ReadFileValue(options["domain"])
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

	ctx, cancel := context.WithCancel(context.Background())
	profileName := options["name"]
	if profileName == "" {
		profileName = options["profile_name"]
	}
	if profileName == "" {
		profileName = "zerotier"
	}

	// Convert string options to structured options for filtering
	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	// Parse filter configuration using structured format
	filterLogPrefix := fmt.Sprintf("[poll/zerotier/%s/filter]", profileName)
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions, filterLogger)
	if err != nil {
		// Build logPrefix for this debug message - we need it before the full logPrefix is created
		tempLogPrefix := fmt.Sprintf("[poll/zerotier/%s]", profileName)
		log.Debug("%s Error creating filter configuration: %v, using default", tempLogPrefix, err)
		filterConfig = common.DefaultFilterConfig()
	}

	// Add default online=true filter if no filters are configured
	if len(filterConfig.Filters) == 0 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == common.FilterTypeNone) {
		// Build logPrefix for this debug message - we need it before the full logPrefix is created
		tempLogPrefix := fmt.Sprintf("[poll/zerotier/%s]", profileName)
		log.Debug("%s Adding default online=true filter", tempLogPrefix)
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

	// Auto-detect API URL if not provided - default to ZeroTier Central
	if apiURL == "" {
		apiURL = "https://my.zerotier.com"
		log.Warn("No api_url specified, defaulting to ZeroTier Central: %s", apiURL)
	}

	// Auto-detect API type based on URL if not explicitly set
	if apiType == "" {
		if strings.Contains(apiURL, "my.zerotier.com") || strings.Contains(apiURL, "zerotier.com") {
			apiType = "zerotier"
			log.Debug("Auto-detected API type as 'zerotier' based on URL: %s", apiURL)
		} else {
			// For custom URLs, we'll still try auto-detection later in detectAPIType()
			log.Debug("Custom API URL detected: %s, will auto-detect API type", apiURL)
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

	// Create scoped logger - if no specific log level set, pass empty string to inherit global level
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		scopedLogger.Info("Provider log_level set to: '%s'", logLevel)
	}

	// Log address fallback configuration
	if useAddressAsFallback {
		scopedLogger.Verbose("Address fallback enabled - will use member address as hostname when name is empty")
	} else {
		scopedLogger.Debug("Address fallback disabled - members without names will be skipped (enable with use_address_fallback: true)")
	}
	// Log online timeout configuration if non-default
	if onlineTimeoutSeconds != 60 {
		// Determine API type name for logging
		apiTypeName := "ZeroTier Central"
		if apiType == "ztnet" {
			apiTypeName = "ZT-Net"
		} else if strings.Contains(apiURL, "my.zerotier.com") || strings.Contains(apiURL, "zerotier.com") {
			apiTypeName = "ZeroTier Central"
		} else {
			// For custom URLs where we haven't detected the type yet
			apiTypeName = "ZeroTier API"
		}
		scopedLogger.Verbose("%s Online timeout set to %d seconds", apiTypeName, onlineTimeoutSeconds)
	}

	// Warn if timeout is too low - can cause erratic behavior
	if onlineTimeoutSeconds < 60 {
		scopedLogger.Warn("Warning: online_timeout_seconds is set to %d seconds, which may cause erratic behavior due to ZeroTier Central's heartbeat timing. Consider using 60+ seconds.", onlineTimeoutSeconds)
	}

	return &ZerotierProvider{
		apiURL:                 apiURL,
		token:                  apiToken,
		networkID:              networkID,
		apiType:                apiType,
		domain:                 domain,
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
		p.logger.Warn("StartPolling called but already running")
		return nil
	}
	p.logger.Debug("Starting Zerotier polling loop")
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

func (p *ZerotierProvider) GetDNSEntries() ([]inputtypes.DNSEntry, error) {
	p.logger.Trace("GetDNSEntries called")
	return p.fetchMembers()
}

func (p *ZerotierProvider) pollLoop() {
	p.logger.Debug("pollLoop started: performing initial poll immediately on startup")
	if p.processExisting {
		p.logger.Trace("Processing existing Zerotier members on startup (process_existing=true)")
		entries, err := p.fetchMembers()
		if err == nil {
			_ = p.updateDNSEntries(entries, nil)
			p.lastEntries = entries
		}
	} else {
		p.logger.Trace("Initial poll on startup (process_existing=false), inventory only, no processing")
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

// logMemberAdded logs when a member is added with appropriate message based on filter type
func (p *ZerotierProvider) logMemberAdded(name string) {
	p.logger.Info("Member added: %s", name)
}

// logMemberRemoved logs when a member is removed with appropriate message based on filter type
func (p *ZerotierProvider) logMemberRemoved(name string) {
	p.logger.Info("Member removed: %s", name)
}

// updateDNSEntries compares current and previous entries and updates DNS accordingly
func (p *ZerotierProvider) updateDNSEntries(currentEntries []inputtypes.DNSEntry, lastEntries []inputtypes.DNSEntry) error {
	// Build maps for comparison
	current := make(map[string]inputtypes.DNSEntry)
	for _, entry := range currentEntries {
		key := entry.GetFQDN() + ":" + entry.GetRecordType()
		current[key] = entry
	}

	last := make(map[string]inputtypes.DNSEntry)
	for _, entry := range lastEntries {
		key := entry.GetFQDN() + ":" + entry.GetRecordType()
		last[key] = entry
	}

	// Use a domain-specific log prefix for batch processor logs
	batchLogPrefix := fmt.Sprintf("[domain/%s/%s]", p.domain, p.profileName)
	batchProcessor := domain.NewBatchProcessorWithProvider(batchLogPrefix, p.profileName, p.outputWriter, p.outputSyncer)

	// Process additions and changes
	for key, entry := range current {
		if lastEntry, exists := last[key]; !exists {
			// NEW ENTRY
			fqdn := entry.GetFQDN()
			fqdnNoDot := strings.TrimSuffix(fqdn, ".")
			p.logMemberAdded(fqdn)

			// Resolve real domain name from config key
			realDomain := p.domain
			domainConfig := config.GetDomainConfig(p.domain)
			p.logger.Debug("domainConfig for key '%s': %+v", p.domain, domainConfig)
			if domainConfig != nil {
				if d, ok := domainConfig["domain"]; ok {
					realDomain = d
					p.logger.Trace("Resolved domain config key '%s' to real domain name '%s'", p.domain, realDomain)
				} else {
					p.logger.Warn("Domain config for key '%s' does not contain a 'domain' field, using as-is", p.domain)
				}
			} else {
				p.logger.Warn("Could not resolve domain config key '%s' to a real domain name, using as-is", p.domain)
			}

			state := domain.RouterState{
				SourceType:           p.profileName, // Use the provider/profile name as source
				Name:                 p.profileName,
				Service:              entry.Target,
				RecordType:           entry.RecordType,
				ForceServiceAsTarget: true, // VPN providers always use Service IP as target
			}

			p.logger.Trace("Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state) // Pass resolved domain
			if err != nil {
				p.logger.Error("Failed to ensure DNS for '%s': %v", fqdnNoDot, err)
			}
		} else {
			// CHANGED ENTRY: compare fields
			if entry.Target != lastEntry.Target || entry.TTL != lastEntry.TTL || entry.RecordType != lastEntry.RecordType {
				fqdn := entry.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				p.logger.Info("Member changed: %s (target: %s -> %s, ttl: %d -> %d, type: %s -> %s)", fqdn, lastEntry.Target, entry.Target, lastEntry.TTL, entry.TTL, lastEntry.RecordType, entry.RecordType)

				// Resolve real domain name from config key
				realDomain := p.domain
				domainConfig := config.GetDomainConfig(p.domain)
				p.logger.Debug("domainConfig for key '%s': %+v", p.domain, domainConfig)
				if domainConfig != nil {
					if d, ok := domainConfig["domain"]; ok {
						realDomain = d
						p.logger.Trace("Resolved domain config key '%s' to real domain name '%s'", p.domain, realDomain)
					} else {
						p.logger.Warn("Domain config for key '%s' does not contain a 'domain' field, using as-is", p.domain)
					}
				} else {
					p.logger.Warn("Could not resolve domain config key '%s' to a real domain name, using as-is", p.domain)
				}

				state := domain.RouterState{
					SourceType:           p.profileName, // Use the provider/profile name as source
					Name:                 p.profileName,
					Service:              entry.Target,
					RecordType:           entry.RecordType,
					ForceServiceAsTarget: true, // VPN providers always use Service IP as target
				}

				p.logger.Trace("Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
				err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state) // Pass resolved domain
				if err != nil {
					p.logger.Error("Failed to ensure DNS for '%s': %v", fqdnNoDot, err)
				}
			}
		}
	}

	// Process removals
	for key, entry := range last {
		if _, exists := current[key]; !exists {
			fqdn := entry.GetFQDN()
			fqdnNoDot := strings.TrimSuffix(fqdn, ".")
			p.logMemberRemoved(fqdn)

			// Resolve real domain name from config key
			realDomain := p.domain
			domainConfig := config.GetDomainConfig(p.domain)
			if domainConfig != nil {
				if d, ok := domainConfig["domain"]; ok {
					realDomain = d
					p.logger.Trace("Resolved domain config key '%s' to real domain name '%s' (removal)", p.domain, realDomain)
				} else {
					p.logger.Warn("Domain config for key '%s' does not contain a 'domain' field, using as-is (removal)", p.domain)
				}
			} else {
				p.logger.Warn("Could not resolve domain config key '%s' to a real domain name, using as-is (removal)", p.domain)
			}

			state := domain.RouterState{
				SourceType:           p.profileName, // Use the provider/profile name as source
				Name:                 p.profileName,
				Service:              entry.Target,
				RecordType:           entry.RecordType,
				ForceServiceAsTarget: true, // VPN providers always use Service IP as target
			}

			p.logger.Trace("Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state) // Pass resolved domain
			if err != nil {
				p.logger.Error("Failed to remove DNS for '%s': %v", fqdnNoDot, err)
			}
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

func (p *ZerotierProvider) fetchMembers() ([]inputtypes.DNSEntry, error) {
	p.logger.Trace("fetchMembers called (apiType=%s, detected=%v)", p.apiType, p.apiTypeDetected)
	if !p.apiTypeDetected {
		// Try ZTNet first if apiType is empty or ztnet
		p.logger.Debug("Attempting ZTNet API detection")
		entries, err := p.fetchZTNetMembers()
		if err == nil && len(entries) > 0 {
			p.apiType = "ztnet"
			p.apiTypeDetected = true
			p.logger.Verbose("Detected ZTNet API")
			return entries, nil
		} else if err != nil {
			p.logger.Debug("ZTNet API error: %v", err)
		}
		// If ZTNet fails, try Zerotier Central
		p.logger.Debug("ZTNet API not detected, falling back to Zerotier Central")
		entries, err = p.fetchZerotierMembers()
		if err == nil && len(entries) > 0 {
			p.apiType = "zerotier"
			p.apiTypeDetected = true
			p.logger.Verbose("Detected Zerotier Central API")
			return entries, nil
		} else if err != nil {
			p.logger.Debug("Zerotier Central API error: %v", err)
		}
		// If both fail, log error and return
		p.logger.Error("Could not detect working Zerotier API (tried ZTNet and Zerotier Central)")
		return nil, fmt.Errorf("could not detect working Zerotier API (tried ZTNet and Zerotier Central)")
	}
	// Use cached type for all future polls
	if p.apiType == "ztnet" {
		return p.fetchZTNetMembers()
	}
	return p.fetchZerotierMembers()
}

func (p *ZerotierProvider) fetchZerotierMembers() ([]inputtypes.DNSEntry, error) {
	p.logger.Debug("Fetching Zerotier members from %s", p.apiURL)

	// Parse network_id to handle ZT-Net format gracefully if fallback occurs
	networkid := p.networkID
	parts := strings.Split(networkid, ":")
	if len(parts) >= 2 { // It can be 2 or 3 parts for ZT-Net format
		networkid = parts[len(parts)-1] // The actual network ID is always the last part
	}
	url := strings.TrimRight(p.apiURL, "/") + "/api/network/" + networkid + "/member"
	p.logger.Trace("Member API URL: %s", url)

	// Use shared HTTP function with Bearer token header
	headers := map[string]string{
		"Authorization": "bearer " + p.token,
	}
	body, err := common.FetchRemoteResourceWithHeaders(url, "", "", headers, p.logPrefix)
	if err != nil {
		return nil, err
	}
	p.logger.Trace("Zerotier members API response: %s", string(body))

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
	// Always use the configured domain. Remove autodetect from network config.
	if domain == "" {
		p.logger.Warn("No domain configured for Zerotier, skipping DNS entry creation")
		return nil, nil
	}

	p.logger.Debug("Filtering members using filter system")
	var entries []inputtypes.DNSEntry
	for _, m := range members {
		// Determine if member is "online" based on recent activity
		// Use configurable timeout (default 5 minutes)
		currentTime := time.Now().Unix() * 1000 // Convert to milliseconds
		timeoutMs := int64(p.onlineTimeoutSeconds * 1000)
		timeSinceLastSeen := currentTime - m.LastSeen
		isOnline := timeSinceLastSeen < timeoutMs

		p.logger.Debug("Member %s online check: lastSeen=%dms ago, timeout=%dms (%ds), isOnline=%v",
			m.Name, timeSinceLastSeen, timeoutMs, p.onlineTimeoutSeconds, isOnline)

		p.logger.Trace("Evaluating member: id=%s, name=%s, online=%v (lastSeen %dms ago, timeout %dms), authorized=%v, ips=%v, address=%s", m.ID, m.Name, isOnline, timeSinceLastSeen, timeoutMs, m.Config.Authorized, m.Config.IPAssignments, m.Config.Address)

		// Apply filtering
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
			p.logger.Trace("Member '%s' did not match filters, skipping", m.Name)
			continue
		}

		// Determine hostname to use
		hostname := m.Name
		if hostname == "" {
			if p.useAddressAsFallback && m.Config.Address != "" {
				hostname = m.Config.Address
				// Track that this member is using address fallback
				p.addressFallbackMembers[hostname] = true
				// Only log fallback message once per member hostname, or always in debug mode
				if !p.loggedFallbackMembers[hostname] {
					p.logger.Verbose("Member has no name, using address as hostname: %s", hostname)
					p.loggedFallbackMembers[hostname] = true
				} else {
					p.logger.Debug("Member has no name, using address as hostname: %s", hostname)
				}
			} else {
				p.logger.Warn("Skipping member %s - no name provided and use_address_fallback not enabled", m.ID)
				continue
			}
		}

		if len(m.Config.IPAssignments) == 0 {
			p.logger.Debug("Skipping member %s (no IP assignments)", hostname)
			continue
		}

		for _, ip := range m.Config.IPAssignments {
			recordType := "A"
			if strings.Contains(ip, ":") {
				recordType = "AAAA"
			}
			// Always use the configured domain for DNS entry creation
			entry := inputtypes.DNSEntry{
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
	p.logger.Debug("Returning %d DNS entries", len(entries))
	return entries, nil
}

func (p *ZerotierProvider) fetchZTNetMembers() ([]inputtypes.DNSEntry, error) {
	p.logger.Debug("Fetching ZT-Net members from %s", p.apiURL)
	// Parse network_id for org, dnsname, networkid
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
	p.logger.Trace("ZT-Net members API URL: %s", url)

	// Use shared HTTP function with ZTNet auth header
	headers := map[string]string{
		"x-ztnet-auth": p.token,
	}
	body, err := common.FetchRemoteResourceWithHeaders(url, "", "", headers, p.logPrefix)
	if err != nil {
		return nil, err
	}
	p.logger.Trace("ZT-Net members API response: %s", string(body))
	var members []struct {
		Name            string   `json:"name"`
		LastSeen        string   `json:"lastSeen"` // ISO timestamp for ZT-Net
		Online          bool     `json:"online"`
		IPs             []string `json:"ipAssignments"`
		Authorized      bool     `json:"authorized"`
		Tags            []string `json:"tags"`
		ID              string   `json:"id"`
		Address         string   `json:"address"`
		NodeID          int      `json:"nodeid"`
		PhysicalAddress string   `json:"physicalAddress"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("failed to parse ZT-Net members response: %w", err)
	}

	domain := p.domain
	// Always use the configured domain. Remove fallback to dnsname.
	if domain == "" {
		p.logger.Warn("No domain configured for ZT-Net, skipping DNS entry creation")
		return nil, nil
	}

	p.logger.Debug("Filtering members using filter system")
	var entries []inputtypes.DNSEntry
	for _, m := range members {
		// Determine if member is "online" based on lastSeen timestamp
		isOnline := true // Default to online if we can't parse lastSeen
		if m.LastSeen != "" {
			if lastSeenTime, err := time.Parse(time.RFC3339, m.LastSeen); err == nil {
				timeSinceLastSeen := time.Since(lastSeenTime)
				timeoutDuration := time.Duration(p.onlineTimeoutSeconds) * time.Second
				isOnline = timeSinceLastSeen < timeoutDuration

				p.logger.Debug("Member %s online check: lastSeen=%v ago, timeout=%v (%ds), isOnline=%v",
					m.Name, timeSinceLastSeen.Truncate(time.Second), timeoutDuration, p.onlineTimeoutSeconds, isOnline)
			} else {
				p.logger.Warn("Failed to parse lastSeen timestamp for member %s: %s", m.Name, m.LastSeen)
				// Fall back to the boolean online field if timestamp parsing fails
				isOnline = m.Online
			}
		} else {
			// If no lastSeen field, fall back to boolean online field
			isOnline = m.Online
		}

		p.logger.Trace("Evaluating member: id=%s, name=%s, online=%v, authorized=%v, tags=%v, address=%s, nodeid=%d, physicalAddress=%s", m.ID, m.Name, isOnline, m.Authorized, m.Tags, m.Address, m.NodeID, m.PhysicalAddress)

		// Apply filtering
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
			p.logger.Trace("Member '%s' did not match filters, skipping", m.Name)
			continue
		}

		// Determine hostname to use
		hostname := m.Name
		if hostname == "" {
			if p.useAddressAsFallback && m.Address != "" {
				hostname = m.Address
				// Track that this member is using address fallback
				p.addressFallbackMembers[hostname] = true
				// Only log fallback message once per member hostname, or always in debug mode
				if !p.loggedFallbackMembers[hostname] {
					p.logger.Verbose("Member has no name, using address as hostname: %s", hostname)
					p.loggedFallbackMembers[hostname] = true
				} else {
					p.logger.Debug("Member has no name, using address as hostname: %s", hostname)
				}
			} else {
				p.logger.Warn("Skipping member %s - no name provided and use_address_fallback not enabled", m.ID)
				continue
			}
		}

		if len(m.IPs) == 0 {
			p.logger.Debug("Skipping member %s (no IP assignments)", hostname)
			continue
		}

		for _, ip := range m.IPs {
			recordType := "A"
			if strings.Contains(ip, ":") {
				recordType = "AAAA"
			}
			fqdn := hostname + "." + domain
			p.logger.Debug("Constructed FQDN: hostname='%s', domain='%s', fqdn='%s'", hostname, domain, fqdn)
			// Create DNS entry
			entry := inputtypes.DNSEntry{
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
	p.logger.Debug("Returning %d DNS entries", len(entries))
	return entries, nil
}

// ZerotierCentralMember represents a member from ZeroTier Central API
type ZerotierCentralMember struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	LastSeen      int64    `json:"lastSeen"`
	Online        bool     `json:"online"`
	IPAssignments []string `json:"ipAssignments"`
	Authorized    bool     `json:"authorized"`
	Address       string   `json:"address"`
}

// ZTNetMember represents a member from ZT-Net API
type ZTNetMember struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	LastSeen        string   `json:"lastSeen"`
	Online          bool     `json:"online"`
	IPAssignments   []string `json:"ipAssignments"`
	Authorized      bool     `json:"authorized"`
	Tags            []string `json:"tags"`
	Address         string   `json:"address"`
	NodeID          int      `json:"nodeid"`
	PhysicalAddress string   `json:"physicalAddress"`
}

// EvaluateZerotierFilters evaluates structured filters against ZeroTier members
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
		// Only supported by ZT-Net
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
		// Only supported by ZT-Net
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
		// Only supported by ZT-Net
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

	// Try ZTNet detection using shared HTTP function
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

	// Fallback to Zerotier Central
	return "zerotier"
}

// GetName returns the provider name
func (zp *ZerotierProvider) GetName() string {
	return zp.profileName // Return the actual profile name (e.g., zt_toi)
}

// Remove local Provider interface, use inputtypes.Provider

// For registration, use registry.RegisterProviderFactory
func init() {
	factory := func(profileName string, config map[string]interface{}, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (interface{}, error) {
		// Convert config to map[string]string for legacy signature
		opts := make(map[string]string)
		for k, v := range config {
			if str, ok := v.(string); ok {
				opts[k] = str
			}
		}
		return NewProvider(opts, outputWriter, outputSyncer)
	}
	registry.RegisterProviderFactory("zerotier", factory)
}
