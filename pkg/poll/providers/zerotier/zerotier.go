// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package zerotier

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

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
	domain                 string
	interval               time.Duration
	processExisting        bool
	recordRemoveOnStop     bool
	useAddressAsFallback   bool // Use address as hostname when name is empty
	onlineTimeoutSeconds   int  // Seconds to consider a member offline for ZeroTier Central
	filterType             string
	filterValue            string
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
}

func NewProvider(options map[string]string) (poll.Provider, error) {
	apiURL := options["api_url"]
	apiToken := options["api_token"]
	networkID := options["network_id"]
	apiType := options["api_type"] // "zerotier" or "ztnet"
	domain := options["domain"]
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
	filterType := options["filter_type"]
	filterValue := options["filter_value"]
	if filterType == "" {
		filterType = "online"
	}
	if filterValue == "" && filterType == "online" {
		filterValue = "true"
	}
	ctx, cancel := context.WithCancel(context.Background())
	profileName := options["name"]
	if profileName == "" {
		profileName = options["profile_name"]
	}
	if profileName == "" {
		profileName = "zerotier"
	}
	logLevel := options["log_level"] // Get provider-specific log level
	logPrefix := pollCommon.BuildLogPrefix("zerotier", profileName)

	// Auto-detect API URL if not provided - default to ZeroTier Central
	if apiURL == "" {
		apiURL = "https://my.zerotier.com"
		log.Warn("%s No api_url specified, defaulting to ZeroTier Central: %s", logPrefix, apiURL)
	}

	// Auto-detect API type based on URL if not explicitly set
	if apiType == "" {
		if strings.Contains(apiURL, "my.zerotier.com") || strings.Contains(apiURL, "zerotier.com") {
			apiType = "zerotier"
			log.Debug("%s Auto-detected API type as 'zerotier' based on URL: %s", logPrefix, apiURL)
		} else {
			// For custom URLs, we'll still try auto-detection later in detectAPIType()
			log.Debug("%s Custom API URL detected: %s, will auto-detect API type", logPrefix, apiURL)
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
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	// Log address fallback configuration
	if useAddressAsFallback {
		log.Verbose("%s Address fallback enabled - will use member address as hostname when name is empty", logPrefix)
	} else {
		log.Debug("%s Address fallback disabled - members without names will be skipped (enable with use_address_fallback: true)", logPrefix)
	}
	// Log online timeout configuration if non-default
	if onlineTimeoutSeconds != 60 {
		log.Verbose("%s ZeroTier Central Online timeout set to %d seconds", logPrefix, onlineTimeoutSeconds)
	}

	// Warn if timeout is too low - can cause erratic behavior
	if onlineTimeoutSeconds < 60 {
		log.Warn("%s Warning: online_timeout_seconds is set to %d seconds, which may cause erratic behavior due to ZeroTier Central's heartbeat timing. Consider using 60+ seconds.", logPrefix, onlineTimeoutSeconds)
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
		filterType:             filterType,
		filterValue:            filterValue,
		ctx:                    ctx,
		cancel:                 cancel,
		logPrefix:              logPrefix,
		profileName:            profileName,
		lastKnownRecords:       make(map[string]string),
		logger:                 scopedLogger,
		isFirstPoll:            true,                  // Initialize as first poll
		loggedFallbackMembers:  make(map[string]bool), // Initialize fallback tracking
		addressFallbackMembers: make(map[string]bool), // Initialize address fallback tracking
	}, nil
}

func (p *ZerotierProvider) StartPolling() error {
	if p.running {
		p.logger.Warn("%s StartPolling called but already running", p.logPrefix)
		return nil
	}
	p.logger.Debug("%s Starting Zerotier polling loop", p.logPrefix)
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

func (p *ZerotierProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
	p.logger.Trace("%s GetDNSEntries called", p.logPrefix)
	return p.fetchMembers()
}

func (p *ZerotierProvider) pollLoop() {
	p.logger.Verbose("%s Entering poll loop (interval: %v)", p.logPrefix, p.interval)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	var lastEntries []poll.DNSEntry
	var lastMemberIDs map[string]struct{} = make(map[string]struct{})
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			entries, err := p.fetchMembers()
			if err != nil {
				p.logger.Error("%s Error fetching members: %v", p.logPrefix, err)
				continue
			}
			currentMemberIDs := make(map[string]struct{})
			for _, entry := range entries {
				currentMemberIDs[entry.Hostname] = struct{}{}
			}
			if len(lastMemberIDs) == 0 {
				// Only log initial discovery on the very first poll
				if p.isFirstPoll {
					p.logger.Debug("%s Initial member discovery completed: %v", p.logPrefix, keys(currentMemberIDs))
					p.isFirstPoll = false
				}
			} else {
				added, removed := diffKeys(lastMemberIDs, currentMemberIDs)
				for _, name := range added {
					p.logMemberAdded(name)
				}
				for _, name := range removed {
					p.logMemberRemoved(name)
				}
				if len(added) > 0 {
					p.logger.Info("%s Members added by filter: %v", p.logPrefix, added)
				}
				if len(removed) > 0 {
					p.logger.Info("%s Members removed by filter: %v", p.logPrefix, removed)
				}
			}
			// Actually update DNS/output
			if err := p.updateDNSEntries(entries, lastEntries); err != nil {
				p.logger.Error("%s Failed to update DNS/output: %v", p.logPrefix, err)
			}
			lastEntries = entries
			lastMemberIDs = currentMemberIDs
		}
	}
}

// logMemberAdded logs when a member is added with appropriate message based on filter type
func (p *ZerotierProvider) logMemberAdded(name string) {
	switch p.filterType {
	case "online":
		p.logger.Verbose("%s Member '%s' came online and is being added", p.logPrefix, name)
	case "authorized":
		if p.filterValue == "true" {
			p.logger.Verbose("%s Member '%s' was authorized and is being added", p.logPrefix, name)
		} else {
			p.logger.Verbose("%s Member '%s' was deauthorized and is being added", p.logPrefix, name)
		}
	case "name":
		p.logger.Verbose("%s Member '%s' name now matches filter '%s' and is being added", p.logPrefix, name, p.filterValue)
	case "tag":
		p.logger.Verbose("%s Member '%s' was tagged with '%s' and is being added", p.logPrefix, name, p.filterValue)
	case "id":
		p.logger.Verbose("%s Member '%s' ID matches filter '%s' and is being added", p.logPrefix, name, p.filterValue)
	case "address":
		p.logger.Verbose("%s Member '%s' address matches filter '%s' and is being added", p.logPrefix, name, p.filterValue)
	case "nodeid":
		p.logger.Verbose("%s Member '%s' node ID matches filter '%s' and is being added", p.logPrefix, name, p.filterValue)
	case "ipAssignments":
		p.logger.Verbose("%s Member '%s' was assigned IP '%s' and is being added", p.logPrefix, name, p.filterValue)
	case "physicalAddress":
		p.logger.Verbose("%s Member '%s' physical address matches filter '%s' and is being added", p.logPrefix, name, p.filterValue)
	default:
		p.logger.Verbose("%s Member '%s' now matches filter and is being added", p.logPrefix, name)
	}
}

// logMemberRemoved logs when a member is removed with appropriate message based on filter type
func (p *ZerotierProvider) logMemberRemoved(name string) {
	switch p.filterType {
	case "online":
		p.logger.Verbose("%s Member '%s' went offline and is being removed", p.logPrefix, name)
	case "authorized":
		if p.filterValue == "true" {
			p.logger.Verbose("%s Member '%s' was deauthorized and is being removed", p.logPrefix, name)
		} else {
			p.logger.Verbose("%s Member '%s' was authorized and is being removed", p.logPrefix, name)
		}
	case "name":
		p.logger.Verbose("%s Member '%s' name no longer matches filter '%s' and is being removed", p.logPrefix, name, p.filterValue)
	case "tag":
		p.logger.Verbose("%s Member '%s' tag '%s' was removed and is being removed", p.logPrefix, name, p.filterValue)
	case "id":
		p.logger.Verbose("%s Member '%s' ID no longer matches filter '%s' and is being removed", p.logPrefix, name, p.filterValue)
	case "address":
		p.logger.Verbose("%s Member '%s' address no longer matches filter '%s' and is being removed", p.logPrefix, name, p.filterValue)
	case "nodeid":
		p.logger.Verbose("%s Member '%s' node ID no longer matches filter '%s' and is being removed", p.logPrefix, name, p.filterValue)
	case "ipAssignments":
		p.logger.Verbose("%s Member '%s' IP assignment '%s' was removed and is being removed", p.logPrefix, name, p.filterValue)
	case "physicalAddress":
		p.logger.Verbose("%s Member '%s' physical address no longer matches filter '%s' and is being removed", p.logPrefix, name, p.filterValue)
	default:
		p.logger.Verbose("%s Member '%s' no longer matches filter and is being removed", p.logPrefix, name)
	}
}

// updateDNSEntries compares current and previous entries and updates DNS accordingly
func (p *ZerotierProvider) updateDNSEntries(currentEntries []poll.DNSEntry, lastEntries []poll.DNSEntry) error {
	// Build maps for comparison
	current := make(map[string]poll.DNSEntry)
	for _, entry := range currentEntries {
		key := entry.GetFQDN() + ":" + entry.GetRecordType()
		current[key] = entry
	}

	last := make(map[string]poll.DNSEntry)
	for _, entry := range lastEntries {
		key := entry.GetFQDN() + ":" + entry.GetRecordType()
		last[key] = entry
	}

	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(p.logPrefix)

	// Process additions
	for key, entry := range current {
		if _, exists := last[key]; !exists {
			fqdn := entry.GetFQDN()
			fqdnNoDot := strings.TrimSuffix(fqdn, ".")
			recordType := entry.GetRecordType()
			p.logMemberAdded(fqdn)

			domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
			p.logger.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s'", p.logPrefix, domainKey, subdomain, fqdnNoDot)
			if domainKey == "" {
				p.logger.Error("%s No domain config found for '%s' (tried to match domain from FQDN)", p.logPrefix, fqdnNoDot)
				continue
			}

			domainCfg, ok := config.GlobalConfig.Domains[domainKey]
			if !ok {
				p.logger.Error("%s Domain '%s' not found in config for fqdn='%s'", p.logPrefix, domainKey, fqdnNoDot)
				continue
			}

			realDomain := domainCfg.Name
			p.logger.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s')", p.logPrefix, realDomain, domainKey)

			state := domain.RouterState{
				SourceType: "zerotier",
				Name:       p.profileName,
				Service:    entry.Target,
				RecordType: recordType,
			}

			p.logger.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
			if err != nil {
				p.logger.Error("%s Failed to ensure DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
			}
		}
	}

	// Process removals (if record_remove_on_stop is enabled)
	if p.recordRemoveOnStop {
		for key, entry := range last {
			if _, exists := current[key]; !exists {
				fqdn := entry.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := entry.GetRecordType()
				p.logMemberRemoved(fqdn)

				domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
				p.logger.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s' (removal)", p.logPrefix, domainKey, subdomain, fqdnNoDot)
				if domainKey == "" {
					p.logger.Error("%s No domain config found for '%s' (removal, tried to match domain from FQDN)", p.logPrefix, fqdnNoDot)
					continue
				}

				domainCfg, ok := config.GlobalConfig.Domains[domainKey]
				if !ok {
					p.logger.Error("%s Domain '%s' not found in config for fqdn='%s' (removal)", p.logPrefix, domainKey, fqdnNoDot)
					continue
				}

				realDomain := domainCfg.Name
				p.logger.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s') (removal)", p.logPrefix, realDomain, domainKey)

				state := domain.RouterState{
					SourceType: "zerotier",
					Name:       p.profileName,
					Service:    entry.Target,
					RecordType: recordType,
				}

				p.logger.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
				err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
				if err != nil {
					p.logger.Error("%s Failed to remove DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
				}
			}
		}
	}

	// Finalize the batch - this will sync output files only if there were changes
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

func (p *ZerotierProvider) fetchMembers() ([]poll.DNSEntry, error) {
	p.logger.Trace("%s fetchMembers called (apiType=%s)", p.logPrefix, p.apiType)
	// Detect API type if not set
	apiType := p.apiType
	if apiType == "" {
		apiType = detectAPIType(p.apiURL, p.networkID, p.token)
		p.logger.Trace("%s API type autodetected as '%s'", p.logPrefix, apiType)
	}
	if apiType == "ztnet" {
		return p.fetchZTNetMembers()
	}
	return p.fetchZerotierMembers()
}

func (p *ZerotierProvider) fetchZerotierMembers() ([]poll.DNSEntry, error) {
	p.logger.Debug("%s Fetching Zerotier members from %s", p.logPrefix, p.apiURL)
	url := strings.TrimRight(p.apiURL, "/") + "/api/network/" + p.networkID + "/member"
	netconfURL := strings.TrimRight(p.apiURL, "/") + "/api/network/" + p.networkID
	p.logger.Trace("%s Member API URL: %s", p.logPrefix, url)

	// Use shared HTTP function with Bearer token header
	headers := map[string]string{
		"Authorization": "bearer " + p.token,
	}
	body, err := pollCommon.FetchRemoteResourceWithHeaders(url, "", "", headers, p.logPrefix)
	if err != nil {
		return nil, err
	}
	p.logger.Trace("%s Zerotier members API response: %s", p.logPrefix, string(body))

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
		return nil, fmt.Errorf("%s failed to parse Zerotier members response: %w", p.logPrefix, err)
	}

	domain := p.domain
	if domain == "" {
		p.logger.Trace("%s No domain configured, attempting autodetect from network config", p.logPrefix)
		// Try to autodetect domain from network config using shared HTTP function
		netconfBody, err := pollCommon.FetchRemoteResourceWithHeaders(netconfURL, "", "", headers, p.logPrefix)
		if err == nil {
			p.logger.Trace("%s Zerotier network config response: %s", p.logPrefix, string(netconfBody))
			var netconf struct {
				DNS struct {
					Domain string `json:"domain"`
				} `json:"dns"`
			}
			if err := json.Unmarshal(netconfBody, &netconf); err == nil && netconf.DNS.Domain != "" {
				domain = netconf.DNS.Domain
				p.logger.Info("%s Autodetected domain from Zerotier network config: %s", p.logPrefix, domain)
			}
		}
		if domain == "" {
			p.logger.Warn("%s Could not autodetect domain from Zerotier network config, skipping DNS entry creation", p.logPrefix)
			return nil, nil
		}
	}

	p.logger.Debug("%s Filtering members with filter_type='%s', filter_value='%s'", p.logPrefix, p.filterType, p.filterValue)
	var entries []poll.DNSEntry
	for _, m := range members {
		// Determine if member is "online" based on recent activity
		// Use configurable timeout (default 5 minutes)
		currentTime := time.Now().Unix() * 1000 // Convert to milliseconds
		timeoutMs := int64(p.onlineTimeoutSeconds * 1000)
		timeSinceLastSeen := currentTime - m.LastSeen
		isOnline := timeSinceLastSeen < timeoutMs

		p.logger.Debug("%s Member %s online check: lastSeen=%dms ago, timeout=%dms (%ds), isOnline=%v",
			p.logPrefix, m.Name, timeSinceLastSeen, timeoutMs, p.onlineTimeoutSeconds, isOnline)

		p.logger.Trace("%s Evaluating member: id=%s, name=%s, online=%v (lastSeen %dms ago, timeout %dms), authorized=%v, ips=%v, address=%s", p.logPrefix, m.ID, m.Name, isOnline, timeSinceLastSeen, timeoutMs, m.Config.Authorized, m.Config.IPAssignments, m.Config.Address)

		// Apply filtering like ZTNet
		if !matchZerotierCentralFilterWithLog(p.logger, p.filterType, p.filterValue, m, isOnline) {
			p.logger.Trace("%s Member '%s' did not match filter %s=%s, skipping", p.logPrefix, m.Name, p.filterType, p.filterValue)
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
					p.logger.Verbose("%s Member has no name, using address as hostname: %s", p.logPrefix, hostname)
					p.loggedFallbackMembers[hostname] = true
				} else {
					p.logger.Debug("%s Member has no name, using address as hostname: %s", p.logPrefix, hostname)
				}
			} else {
				p.logger.Warn("%s Skipping member %s - no name provided and use_address_fallback not enabled", p.logPrefix, m.ID)
				continue
			}
		}

		if len(m.Config.IPAssignments) == 0 {
			p.logger.Debug("%s Skipping member %s (no IP assignments)", p.logPrefix, hostname)
			continue
		}

		for _, ip := range m.Config.IPAssignments {
			recordType := "A"
			if strings.Contains(ip, ":") {
				recordType = "AAAA"
			}
			// Create DNS entry
			entry := poll.DNSEntry{
				Hostname:   hostname,
				Domain:     domain,
				RecordType: recordType,
				Target:     ip,
				TTL:        120,
			}
			entries = append(entries, entry)
		}
	}
	p.logger.Debug("%s Returning %d DNS entries", p.logPrefix, len(entries))
	return entries, nil
}

func (p *ZerotierProvider) fetchZTNetMembers() ([]poll.DNSEntry, error) {
	p.logger.Debug("%s Fetching ZT-Net members from %s", p.logPrefix, p.apiURL)
	// Parse network_id for org, dnsname, networkid
	org := ""
	dnsname := ""
	networkid := p.networkID
	parts := strings.Split(networkid, ":")
	if len(parts) == 3 {
		org = parts[0]
		dnsname = parts[1]
		networkid = parts[2]
	} else if len(parts) == 2 {
		dnsname = parts[0]
		networkid = parts[1]
	}

	var url string
	if org != "" {
		url = strings.TrimRight(p.apiURL, "/") + "/api/v1/org/" + org + "/network/" + networkid + "/member/"
	} else {
		url = strings.TrimRight(p.apiURL, "/") + "/api/v1/network/" + networkid + "/member/"
	}
	p.logger.Trace("%s ZT-Net members API URL: %s", p.logPrefix, url)

	// Use shared HTTP function with ZTNet auth header
	headers := map[string]string{
		"x-ztnet-auth": p.token,
	}
	body, err := pollCommon.FetchRemoteResourceWithHeaders(url, "", "", headers, p.logPrefix)
	if err != nil {
		return nil, err
	}
	p.logger.Trace("%s ZT-Net members API response: %s", p.logPrefix, string(body))
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
		return nil, fmt.Errorf("%s failed to parse ZT-Net members response: %w", p.logPrefix, err)
	}

	domain := p.domain
	if domain == "" && dnsname != "" {
		domain = dnsname
		p.logger.Info("%s Using DNS name from network_id: %s", p.logPrefix, domain)
	}
	if domain == "" {
		p.logger.Warn("%s No domain configured or detected for ZT-Net, skipping DNS entry creation", p.logPrefix)
		return nil, nil
	}

	p.logger.Debug("%s Filtering members with filter_type='%s', filter_value='%s'", p.logPrefix, p.filterType, p.filterValue)
	var entries []poll.DNSEntry
	for _, m := range members {
		// Determine if member is "online" based on lastSeen timestamp
		isOnline := true // Default to online if we can't parse lastSeen
		if m.LastSeen != "" {
			if lastSeenTime, err := time.Parse(time.RFC3339, m.LastSeen); err == nil {
				timeSinceLastSeen := time.Since(lastSeenTime)
				timeoutDuration := time.Duration(p.onlineTimeoutSeconds) * time.Second
				isOnline = timeSinceLastSeen < timeoutDuration

				p.logger.Debug("%s Member %s online check: lastSeen=%v ago, timeout=%v (%ds), isOnline=%v",
					p.logPrefix, m.Name, timeSinceLastSeen.Truncate(time.Second), timeoutDuration, p.onlineTimeoutSeconds, isOnline)
			} else {
				p.logger.Warn("%s Failed to parse lastSeen timestamp for member %s: %s", p.logPrefix, m.Name, m.LastSeen)
				// Fall back to the boolean online field if timestamp parsing fails
				isOnline = m.Online
			}
		} else {
			// If no lastSeen field, fall back to boolean online field
			isOnline = m.Online
		}

		p.logger.Trace("%s Evaluating member: id=%s, name=%s, online=%v, authorized=%v, tags=%v, address=%s, nodeid=%d, physicalAddress=%s", p.logPrefix, m.ID, m.Name, isOnline, m.Authorized, m.Tags, m.Address, m.NodeID, m.PhysicalAddress)

		if !matchZTNetFilterWithLog(p.logger, p.filterType, p.filterValue, m, isOnline) {
			p.logger.Trace("%s Member '%s' did not match filter %s=%s, skipping", p.logPrefix, m.Name, p.filterType, p.filterValue)
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
					p.logger.Verbose("%s Member has no name, using address as hostname: %s", p.logPrefix, hostname)
					p.loggedFallbackMembers[hostname] = true
				} else {
					p.logger.Debug("%s Member has no name, using address as hostname: %s", p.logPrefix, hostname)
				}
			} else {
				p.logger.Warn("%s Skipping member %s - no name provided and use_address_fallback not enabled", p.logPrefix, m.ID)
				continue
			}
		}

		if len(m.IPs) == 0 {
			p.logger.Debug("%s Skipping member %s (no IP assignments)", p.logPrefix, hostname)
			continue
		}

		for _, ip := range m.IPs {
			recordType := "A"
			if strings.Contains(ip, ":") {
				recordType = "AAAA"
			}
			// Create DNS entry
			entry := poll.DNSEntry{
				Hostname:   hostname,
				Domain:     domain,
				RecordType: recordType,
				Target:     ip,
				TTL:        120,
			}
			entries = append(entries, entry)
		}
	}
	p.logger.Debug("%s Returning %d DNS entries", p.logPrefix, len(entries))
	return entries, nil
}

func matchZTNetFilterWithLog(logger *log.ScopedLogger, filterType, filterValue string, m struct {
	Name            string   `json:"name"`
	LastSeen        string   `json:"lastSeen"`
	Online          bool     `json:"online"`
	IPs             []string `json:"ipAssignments"`
	Authorized      bool     `json:"authorized"`
	Tags            []string `json:"tags"`
	ID              string   `json:"id"`
	Address         string   `json:"address"`
	NodeID          int      `json:"nodeid"`
	PhysicalAddress string   `json:"physicalAddress"`
}, isOnline bool) bool {
	switch filterType {
	case "name":
		matched := strings.Contains(m.Name, filterValue)
		logger.Trace("Filter by name: member='%s', filter_value='%s', matched=%v", m.Name, filterValue, matched)
		return matched
	case "online":
		matched := (filterValue == "true" && isOnline) || (filterValue == "false" && !isOnline)
		logger.Trace("Filter by online: member='%s', online=%v, filter_value='%s', matched=%v", m.Name, isOnline, filterValue, matched)
		return matched
	case "authorized":
		matched := (filterValue == "true" && m.Authorized) || (filterValue == "false" && !m.Authorized)
		logger.Trace("Filter by authorized: member='%s', authorized=%v, filter_value='%s', matched=%v", m.Name, m.Authorized, filterValue, matched)
		return matched
	case "tag":
		matched := false
		for _, tag := range m.Tags {
			if tag == filterValue {
				matched = true
				break
			}
		}
		logger.Trace("Filter by tag: member='%s', tags=%v, filter_value='%s', matched=%v", m.Name, m.Tags, filterValue, matched)
		return matched
	case "id":
		matched := m.ID == filterValue
		logger.Trace("Filter by id: member='%s', id=%s, filter_value='%s', matched=%v", m.Name, m.ID, filterValue, matched)
		return matched
	case "address":
		matched := m.Address == filterValue
		logger.Trace("Filter by address: member='%s', address=%s, filter_value='%s', matched=%v", m.Name, m.Address, filterValue, matched)
		return matched
	case "nodeid":
		matched := fmt.Sprintf("%d", m.NodeID) == filterValue
		logger.Trace("Filter by nodeid: member='%s', nodeid=%d, filter_value='%s', matched=%v", m.Name, m.NodeID, filterValue, matched)
		return matched
	case "ipAssignments":
		matched := false
		for _, ip := range m.IPs {
			if ip == filterValue {
				matched = true
				break
			}
		}
		logger.Trace("Filter by ipAssignments: member='%s', ips=%v, filter_value='%s', matched=%v", m.Name, m.IPs, filterValue, matched)
		return matched
	case "physicalAddress":
		matched := m.PhysicalAddress == filterValue
		logger.Trace("Filter by physicalAddress: member='%s', physicalAddress=%s, filter_value='%s', matched=%v", m.Name, m.PhysicalAddress, filterValue, matched)
		return matched
	default:
		logger.Trace("No filter applied for member '%s'", m.Name)
		return true // No filter
	}
}

func matchZerotierCentralFilterWithLog(logger *log.ScopedLogger, filterType, filterValue string, m struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	LastSeen int64  `json:"lastSeen"`
	Config   struct {
		IPAssignments []string `json:"ipAssignments"`
		Authorized    bool     `json:"authorized"`
		Address       string   `json:"address"`
	} `json:"config"`
}, isOnline bool) bool {
	switch filterType {
	case "name":
		matched := strings.Contains(m.Name, filterValue)
		logger.Trace("Filter by name: member='%s', filter_value='%s', matched=%v", m.Name, filterValue, matched)
		return matched
	case "online":
		matched := (filterValue == "true" && isOnline) || (filterValue == "false" && !isOnline)
		logger.Trace("Filter by online: member='%s', online=%v, filter_value='%s', matched=%v", m.Name, isOnline, filterValue, matched)
		return matched
	case "authorized":
		matched := (filterValue == "true" && m.Config.Authorized) || (filterValue == "false" && !m.Config.Authorized)
		logger.Trace("Filter by authorized: member='%s', authorized=%v, filter_value='%s', matched=%v", m.Name, m.Config.Authorized, filterValue, matched)
		return matched
	case "id":
		matched := m.ID == filterValue
		logger.Trace("Filter by id: member='%s', id=%s, filter_value='%s', matched=%v", m.Name, m.ID, filterValue, matched)
		return matched
	case "address":
		matched := m.Config.Address == filterValue
		logger.Trace("Filter by address: member='%s', address=%s, filter_value='%s', matched=%v", m.Name, m.Config.Address, filterValue, matched)
		return matched
	case "ipAssignments":
		matched := false
		for _, ip := range m.Config.IPAssignments {
			if ip == filterValue {
				matched = true
				break
			}
		}
		logger.Trace("Filter by ipAssignments: member='%s', ips=%v, filter_value='%s', matched=%v", m.Name, m.Config.IPAssignments, filterValue, matched)
		return matched
	default:
		logger.Trace("No filter applied for member '%s'", m.Name)
		return true // No filter
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
	body, err := pollCommon.FetchRemoteResourceWithHeaders(url, "", "", headers, "")
	if err == nil && len(body) > 0 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "ipAssignments") || strings.Contains(bodyStr, "authorized") {
			return "ztnet"
		}
	}

	// Fallback to Zerotier Central
	return "zerotier"
}

func init() {
	poll.RegisterProvider("zerotier", NewProvider)
}
