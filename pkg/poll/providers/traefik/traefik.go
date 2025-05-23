// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package traefik

import (
	"container-dns-companion/pkg/log"
	"container-dns-companion/pkg/poll"
	"container-dns-companion/pkg/poll/providers/traefik/filter"
	"container-dns-companion/pkg/utils"
	"container-dns-companion/pkg/dns"
	"container-dns-companion/pkg/domain"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Enhanced regex to support Host(), HostSNI(), HostRegexp(), and multiple hosts
var (
	hostRuleRegex      = regexp.MustCompile(`Host\(([^)]*)\)`)
	hostSniRuleRegex   = regexp.MustCompile(`HostSNI\(([^)]*)\)`)
	hostRegexpRuleRegex = regexp.MustCompile(`HostRegexp\(([^)]*)\)`)
)

// TraefikProvider is a poll provider that monitors Traefik routers
type TraefikProvider struct {
	apiURL            string
	pollInterval       time.Duration
	running            bool
	ctx                context.Context
	cancel             context.CancelFunc
	callback           func(hostnames []string) error
	options            map[string]string
	processExisting    bool
	recordRemoveOnStop bool
	routerCache        map[string]domain.RouterState
	ticker             *time.Ticker
	authUser           string
	authPass           string
	profileName        string // Store profile name for logs
	logPrefix          string // Store log prefix for consistent logging

	// Filters
	filterConfig filter.FilterConfig

	initialPollDone bool // Track if initial poll is complete
}

// NewProvider creates a new Traefik poll provider
func NewProvider(options map[string]string) (poll.Provider, error) {
	// Trace all options keys at the start to help troubleshoot
	log.Trace("[poll/traefik] Provider options received: %+v", options)

	// Always use utils.GetProfileNameFromOptions for profile name resolution
	profileName := utils.GetProfileNameFromOptions(options, "default")
	logPrefix := fmt.Sprintf("[poll/traefik/%s]", profileName)

	log.Trace("%s Resolved profile name: %s", logPrefix, profileName)

	// Mask sensitive values before logging using shared utility
	maskedOptions := utils.MaskSensitiveOptions(options)
	log.Debug("%s Creating new Traefik provider with options: %+v", logPrefix, maskedOptions)

	// Add more detailed logging of received options to help debug
	availableKeys := make([]string, 0, len(options))
	for k := range options {
		availableKeys = append(availableKeys, k)
	}
	log.Debug("%s Available options keys: %v", logPrefix, availableKeys)

	// Debug all keys and values for troubleshooting
	for k, v := range options {
		if utils.IsSensitiveKey(k) {
			log.Trace("%s Option: %s = %s", logPrefix, k, utils.MaskSensitiveValue(v))
		} else {
			log.Trace("%s Option: %s = %s", logPrefix, k, v)
		}
	}

	// Get api URL from options
	apiURL := options["api_url"]
	if apiURL == "" {
		apiURL = "http://localhost:8080/api/http/routers"
		log.Debug("%s No URL specified, using default: %s", logPrefix, apiURL)
	} else {
		log.Debug("%s Using configured URL: %s", logPrefix, apiURL)
	}
	// Get basic auth credentials if provided
	authUser := options["api_auth_user"]
	authPass := options["api_auth_pass"]

	// Try to get credentials from environment variables as fallback
	if authUser == "" {
		envUser := os.Getenv("TRAEFIK_API_AUTH_USER")
		if envUser != "" {
			authUser = envUser
			log.Debug("%s Using basic auth user from environment variable", logPrefix)
		}
	}

	if authPass == "" {
		envPass := os.Getenv("TRAEFIK_API_AUTH_PASS")
		if envPass != "" {
			authPass = envPass
			log.Debug("%s Using basic auth password from environment variable", logPrefix)
		}
	}

	// Log whether auth credentials were found
	if authUser != "" {
		log.Trace("%s Basic auth user configured: %s", logPrefix, authUser)
		if authPass != "" {
			log.Trace("%s Basic auth password configured: %s", logPrefix, utils.MaskSensitiveValue(authPass))
		} else {
			log.Warn("%s Basic auth user provided without password", logPrefix)
		}
	} else {
		log.Debug("%s No basic auth user found in options or environment. Available keys: %v", logPrefix, utils.GetMapKeys(options))
	}

	// Get poll interval from options
	pollInterval := 60 * time.Second
	if interval := options["interval"]; interval != "" {
		dur, err := time.ParseDuration(interval)
		if err == nil && dur > 0 {
			pollInterval = dur
			log.Debug("%s Setting poll interval from duration: %s", logPrefix, pollInterval)
		} else if parsed, err := strconv.Atoi(interval); err == nil && parsed > 0 {
			pollInterval = time.Duration(parsed) * time.Second
			log.Debug("%s Setting poll interval from seconds: %s", logPrefix, pollInterval)
		} else {
			log.Debug("%s Invalid interval format, using default: %s", logPrefix, pollInterval)
		}
	} else {
		log.Debug("%s No interval specified, using default: %s", logPrefix, pollInterval)
	}

	processExisting := false
	if val, ok := options["process_existing"]; ok {
		processExisting = strings.ToLower(val) == "true" || val == "1"
	}
	recordRemoveOnStop := false
	if val, ok := options["record_remove_on_stop"]; ok {
		recordRemoveOnStop = strings.ToLower(val) == "true" || val == "1"
	}

	// Support environment variables for process_existing and record_remove_on_stop
	// POLL_<PROFILENAME>_PROCESS_EXISTING and POLL_<PROFILENAME>_RECORD_REMOVE_ON_STOP
	if !processExisting {
		envKey := fmt.Sprintf("POLL_%s_PROCESS_EXISTING", strings.ToUpper(profileName))
		if envVal := os.Getenv(envKey); envVal != "" {
			processExisting = strings.ToLower(envVal) == "true" || envVal == "1"
			log.Debug("%s Using process_existing from environment variable %s: %v", logPrefix, envKey, processExisting)
		}
	}
	if !recordRemoveOnStop {
		envKey := fmt.Sprintf("POLL_%s_RECORD_REMOVE_ON_STOP", strings.ToUpper(profileName))
		if envVal := os.Getenv(envKey); envVal != "" {
			recordRemoveOnStop = strings.ToLower(envVal) == "true" || envVal == "1"
			log.Debug("%s Using record_remove_on_stop from environment variable %s: %v", logPrefix, envKey, recordRemoveOnStop)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	log.Trace("%s Created context with cancel function", logPrefix)

	// Set up filters from options (no FixTraefikFilterConfig)
	filterConfig, err := filter.NewFilterFromOptions(options)
	if err != nil {
		log.Error("%s Error setting up filters: %v", logPrefix, err)
		return nil, fmt.Errorf("[poll/traefik] filter setup error: %w", err)
	}

	// Check if we have active filters (not just "none" filter)
	hasActiveFilters := len(filterConfig.Filters) > 0 && !(len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == filter.FilterTypeNone)

	if hasActiveFilters {
		log.Debug("%s Filter configuration: %d active filters", logPrefix, len(filterConfig.Filters))
		for i, f := range filterConfig.Filters {
			log.Debug("%s   Filter %d: Type=%s, Value=%s, Operation=%s, Negate=%v",
				logPrefix, i, f.Type, f.Value, f.Operation, f.Negate)
		}
	} else {
		log.Debug("%s No active filters configured, processing all routers", logPrefix)
	}

	provider := &TraefikProvider{
		apiURL:            apiURL,
		pollInterval:       pollInterval,
		running:            false,
		ctx:                ctx,
		cancel:             cancel,
		options:            options,
		processExisting:    processExisting,
		recordRemoveOnStop: recordRemoveOnStop,
		routerCache:        make(map[string]domain.RouterState),
		authUser:           authUser,
		authPass:           authPass,
		profileName:        profileName,
		logPrefix:          logPrefix,
		filterConfig:       filterConfig,
		initialPollDone:    false,
	}

	log.Info("%s Successfully created new Traefik provider instance", logPrefix)
	log.Trace("%s Provider details: URL=%s, interval=%s",
		logPrefix, provider.apiURL, provider.pollInterval)

	return provider, nil
}

// Register the Traefik provider
func init() {
	log.Debug("[poll/traefik] Registering Traefik provider")
	poll.RegisterProvider("traefik", NewProvider)
	log.Debug("[poll/traefik] Successfully registered Traefik provider")
}

// StartPolling starts polling Traefik for routers
func (t *TraefikProvider) StartPolling() error {
	log.Info("%s Starting polling for Routers (interval: %s)", t.logPrefix, t.pollInterval)

	if t.running {
		log.Debug("%s Already running, skipping start", t.logPrefix)
		return nil
	}

	t.running = true
	go t.pollLoop()
	return nil
}

// DiscoverHosts implements the poll.Provider interface
func (t *TraefikProvider) DiscoverHosts(callback func(hostnames []string) error) error {
	log.Debug("%s DiscoverHosts called with callback function", t.logPrefix)
	return t.MonitorTraefik(callback)
}

// StopPolling stops polling Traefik
func (t *TraefikProvider) StopPolling() error {
	if !t.running {
		return nil
	}

	t.running = false

	t.cancel()

	if t.ticker != nil {
		t.ticker.Stop()
	}

	return nil
}

// IsRunning returns whether the provider is running
func (t *TraefikProvider) IsRunning() bool {
	log.Trace("%s IsRunning check, current value: %v", t.logPrefix, t.running)
	return t.running
}

// MonitorTraefik sets the callback and starts polling
func (t *TraefikProvider) MonitorTraefik(callback func(hostnames []string) error) error {
	log.Debug("%s MonitorTraefik called with callback function", t.logPrefix)
	if callback == nil {
		log.Warn("%s Warning: Callback provided to MonitorTraefik is nil", t.logPrefix)
	}
	t.callback = callback
	log.Debug("%s Callback function set: %v, starting polling", t.logPrefix, callback != nil)
	return t.StartPolling()
}

// pollLoop continuously polls the Traefik API at the specified interval
func (t *TraefikProvider) pollLoop() {
	log.Debug("%s Starting poll loop", t.logPrefix)

	// Process existing routers first
	log.Trace("%s Performing initial processing of Traefik routers", t.logPrefix)
	if err := t.processTraefikRouters(); err != nil {
		// Error is already logged in processTraefikRouters, no need to log it again
		log.Trace("%s Initial processing encountered an error (see above logs)", t.logPrefix)
	} else {
		log.Debug("%s Initial processing of Traefik routers completed", t.logPrefix)
	}

	// Create ticker for regular polling
	log.Trace("%s Creating polling timer with interval: %s", t.logPrefix, t.pollInterval)
	ticker := time.NewTicker(t.pollInterval)
	t.ticker = ticker
	defer ticker.Stop()

	log.Debug("%s Entering main poll loop with interval: %s", t.logPrefix, t.pollInterval)
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			log.Trace("%s Ticker triggered, processing Traefik routers", t.logPrefix)
			if err := t.processTraefikRouters(); err != nil {
				// The error details have already been logged in processTraefikRouters
				log.Trace("%s Encountered error during processing (see above logs)", t.logPrefix)
			} else {
				log.Trace("%s Successfully processed Traefik routers", t.logPrefix)
			}
		}
	}
}

// processTraefikRouters polls the Traefik API for routers
func (t *TraefikProvider) processTraefikRouters() error {
	log.Debug("%s Processing Traefik routers from API", t.logPrefix)

	// Create HTTP request
	log.Trace("%s Creating HTTP request to %s", t.logPrefix, t.apiURL)
	req, err := http.NewRequestWithContext(t.ctx, "GET", t.apiURL, nil)
	if err != nil {
		log.Error("%s Failed to create HTTP request: %v", t.logPrefix, err)
		return fmt.Errorf("[poll/traefik] failed to create request: %w", err)
	}

	// Add basic auth if credentials are provided
	if t.authUser != "" {
		log.Trace("%s Adding basic auth credentials to request for user: %s", t.logPrefix, t.authUser)
		req.SetBasicAuth(t.authUser, t.authPass)
	} else {
		log.Trace("%s No basic auth credentials configured", t.logPrefix)
	}

	// Send request
	log.Trace("%s Sending HTTP request to %s", t.logPrefix, t.apiURL) // Increased log level to DEBUG for visibility
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Check for common DNS or connection errors
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			log.Error("%s Cannot reach Traefik API: Hostname '%s' does not exist or cannot be resolved. Please ensure that appropriate DNS records are in place and the host is accessible, or check your api_url configuration.", t.logPrefix, t.apiURL)
		} else if urlErr, ok := err.(*url.Error); ok {
			// Look for DNS errors inside URL errors or check error message
			if dnsErr, ok := urlErr.Err.(*net.DNSError); ok && dnsErr.IsNotFound {
				log.Error("%s Cannot reach Traefik API: Hostname '%s' does not exist or cannot be resolved. Please ensure that appropriate DNS records are in place and the host is accessible, or check your api_url configuration.", t.logPrefix, t.apiURL)
			} else if urlErr.Error() != "" && (urlErr.Unwrap() != nil && urlErr.Unwrap().Error() != "") && (strings.Contains(urlErr.Error(), "no such host") || strings.Contains(urlErr.Unwrap().Error(), "no such host")) {
				log.Error("%s Cannot reach Traefik API: Hostname '%s' does not exist or cannot be resolved. Please ensure that appropriate DNS records are in place and the host is accessible, or check your api_url configuration.", t.logPrefix, t.apiURL)
			} else {
				log.Error("%s Cannot connect to Traefik API at %s: %v. Please verify the URL and that Traefik is running.", t.logPrefix, t.apiURL, urlErr.Err)
			}
		} else {
			log.Error("%s Failed to connect to %s: %v", t.logPrefix, t.apiURL, err)
		}
		return fmt.Errorf("[poll/traefik] connection error: %w", err)
	}
	log.Debug("%s Received HTTP response from %s with status code: %d", t.logPrefix, t.apiURL, resp.StatusCode)
	defer resp.Body.Close()
	log.Trace("%s Received HTTP response with status code: %d", t.logPrefix, resp.StatusCode)

	// Read response
	log.Trace("%s Reading response body", t.logPrefix)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("%s Failed to read response body: %v", t.logPrefix, err)
		return fmt.Errorf("[poll/traefik] failed to read response: %w", err)
	}
	log.Trace("%s Response body size: %d bytes", t.logPrefix, len(body))

	// Always log the response body for debugging purposes
	bodyStr := string(body)
	log.Trace("%s Response body: %s", t.logPrefix, bodyStr)

	// Check response status
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Error("%s Authentication failed (401 Unauthorized). Please configure basic auth with 'api_auth_user' and 'api_auth_pass' options", t.logPrefix)
			return fmt.Errorf("[poll/traefik] authentication failed: configure basic auth with api_auth_user and api_auth_pass options")
		}
		log.Error("%s Unexpected HTTP status code: %d", t.logPrefix, resp.StatusCode)
		return fmt.Errorf("[poll/traefik] unexpected status code: %d", resp.StatusCode)
	}

	// Parse JSON response
	log.Trace("%s Parsing JSON response", t.logPrefix)

	// Try to parse as an array first (which is what the Traefik API returns)
	var routersArray []map[string]interface{}
	if err := json.Unmarshal(body, &routersArray); err != nil {
		// If parsing as array fails, try as a map (older API versions or different formats)
		var routersMap map[string]interface{}
		if err := json.Unmarshal(body, &routersMap); err != nil {
			log.Error("%s Failed to parse JSON response: %v", t.logPrefix, err)
			return fmt.Errorf("[poll/traefik] failed to parse JSON: %w", err)
		}
		log.Debug("%s Found %d routers in API response (map format)", t.logPrefix, len(routersMap))

		// Process the map format (convert to our array format for processing)
		routersArray = make([]map[string]interface{}, 0, len(routersMap))
		for name, router := range routersMap {
			if r, ok := router.(map[string]interface{}); ok {
				r["name"] = name
				routersArray = append(routersArray, r)
			}
		}
	}

	log.Debug("%s Found %d routers in API response", t.logPrefix, len(routersArray))

	filteredRouters := make([]map[string]interface{}, 0, len(routersArray))
	initialLog := !t.initialPollDone
	for _, router := range routersArray {
		shouldProcess, _ := t.filterConfig.ShouldProcessRouter(router)
		routerName := ""
		if name, ok := router["name"].(string); ok {
			routerName = name
		} else if name, ok := router["Name"].(string); ok {
			routerName = name
		}
		if shouldProcess {
			filteredRouters = append(filteredRouters, router)
			if initialLog {
				rule, _ := router["rule"].(string)
				hosts := extractHostsFromRule(rule)
				log.Debug("%s Router PASSED filter: %s | Hostnames: %v", t.logPrefix, routerName, hosts)
			}
		} else if initialLog {
			log.Debug("%s Router FILTERED OUT: %s", t.logPrefix, routerName)
		}
	}

	// Build set of hostnames from filtered routers (deduplicated) and map to RouterState
	hostnameToRouter := make(map[string]domain.RouterState)
	hostnameSet := make(map[string]struct{})
	for _, router := range filteredRouters {
		rule, _ := router["rule"].(string)
		routerName := ""
		if name, ok := router["name"].(string); ok {
			routerName = name
		} else if name, ok := router["Name"].(string); ok {
			routerName = name
		}
		entryPoints := []string{}
		if eps, ok := router["entryPoints"].([]interface{}); ok {
			for _, ep := range eps {
				if epstr, ok := ep.(string); ok {
					entryPoints = append(entryPoints, epstr)
				}
			}
		}
		service, _ := router["service"].(string)
		state := domain.RouterState{
			Name:        routerName,
			Rule:        rule,
			EntryPoints: entryPoints,
			Service:     service,
		}
		hosts := extractHostsFromRule(rule)
		for _, h := range hosts {
			hostnameSet[h] = struct{}{}
			hostnameToRouter[h] = state
		}
	}

	// Convert set to slice
	currentHostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		currentHostnames = append(currentHostnames, h)
	}

	if initialLog {
		if len(currentHostnames) == 0 {
			log.Info("%s No hostnames to process", t.logPrefix)
		} else {
			log.Info("%s Initial hostnames to process: %v", t.logPrefix, currentHostnames)
			// Initial run: process all hostnames as adds
			for _, h := range currentHostnames {
				state := hostnameToRouter[h]
				log.Trace("%s Preparing to add DNS for hostname: %s | RouterState: %+v", t.logPrefix, h, state)
				t.processRouterAdd(state)
				t.routerCache[h] = state
			}
		}
		//log.Info("%s Initial poll: processed all hostnames as adds", t.logPrefix)
		if !t.initialPollDone {
			t.initialPollDone = true
			log.Debug("%s Initial poll complete, future polls will only log changes.", t.logPrefix)
		}
		return nil
	}

	// Compare with previous cache to determine added/removed hostnames
	added := []string{}
	removed := []string{}
	prevHostnames := make(map[string]struct{})
	for h := range t.routerCache {
		prevHostnames[h] = struct{}{}
	}
	for _, h := range currentHostnames {
		if _, ok := prevHostnames[h]; !ok {
			added = append(added, h)
		}
	}
	for h := range prevHostnames {
		if _, ok := hostnameSet[h]; !ok {
			removed = append(removed, h)
		}
	}

	if t.initialPollDone {
		if len(added) > 0 {
			log.Info("%s Hostnames added: %v", t.logPrefix, added)
			for _, h := range added {
				t.processRouterAdd(hostnameToRouter[h])
			}
		}
		if len(removed) > 0 {
			log.Info("%s Hostnames removed: %v", t.logPrefix, removed)
			for _, h := range removed {
				if prevState, ok := t.routerCache[h]; ok {
					t.processRouterRemove(prevState)
				} else {
					t.processRouterRemove(domain.RouterState{Rule: h})
				}
			}
		}
	}

	// Update cache
	t.routerCache = make(map[string]domain.RouterState)
	for _, h := range currentHostnames {
		t.routerCache[h] = hostnameToRouter[h]
	}

	if !t.initialPollDone {
		t.initialPollDone = true
		log.Debug("%s Initial poll complete, future polls will only log changes.", t.logPrefix)
	}

	return nil
}

// routerStatesEqual compares two RouterState structs for equality
func routerStatesEqual(a, b domain.RouterState) bool {
	if a.Name != b.Name || a.Rule != b.Rule || a.Service != b.Service {
		return false
	}
	if len(a.EntryPoints) != len(b.EntryPoints) {
		return false
	}
	for i := range a.EntryPoints {
		if a.EntryPoints[i] != b.EntryPoints[i] {
			return false
		}
	}
	return true
}

// pollRouters fetches routers and processes add/update/remove using cache
func (p *TraefikProvider) pollRouters() error {
	// TODO: Integrate with actual router fetching logic (e.g., from processTraefikRouters)
	// For now, use an empty slice to avoid build errors
	currentRouters := []domain.RouterState{} // Replace with real router fetching logic
	currentMap := make(map[string]domain.RouterState)
	for _, r := range currentRouters {
		currentMap[r.Name] = r
	}

	// On first run, if processExisting is true, just populate cache
	if len(p.routerCache) == 0 && p.processExisting {
		for k, v := range currentMap {
			p.routerCache[k] = v
		}
		log.Info("[poll/traefik] Initial poll: process_existing=true, populating cache only, not processing routers")
		return nil
	}

	// Detect new and updated routers
	for name, state := range currentMap {
		prev, exists := p.routerCache[name]
		if !exists {
			// New router
			log.Info("[poll/traefik] New router detected: %s", name)
			p.processRouterAdd(state)
		} else if !routerStatesEqual(prev, state) {
			// Updated router
			log.Info("[poll/traefik] Router updated: %s", name)
			p.processRouterUpdate(state)
		}
	}

	// Detect removed routers
	for name := range p.routerCache {
		if _, exists := currentMap[name]; !exists {
			log.Info("[poll/traefik] Router removed: %s", name)
			if p.recordRemoveOnStop {
				p.processRouterRemove(p.routerCache[name])
			}
		}
	}

	// Update cache
	p.routerCache = currentMap
	return nil
}

// processRouterAdd processes a router add event and triggers DNS actions
func (t *TraefikProvider) processRouterAdd(state domain.RouterState) {
	hosts := extractHostsFromRule(state.Rule)
	for _, fqdn := range hosts {
		err := domain.EnsureDNSForRouterState(getDomainFromHostname(fqdn), fqdn, state)
		if err != nil {
			//log.Error("%s Failed to ensure DNS for '%s': %v", t.logPrefix, fqdn, err)
		}
	}
}

func (t *TraefikProvider) processRouterUpdate(state domain.RouterState) {
	hosts := extractHostsFromRule(state.Rule)
	if len(hosts) == 0 {
		log.Debug("%s No hostnames to update for router '%s'", t.logPrefix, state.Name)
		return
	}
	for _, fqdn := range hosts {
		err := domain.EnsureDNSForRouterState(getDomainFromHostname(fqdn), fqdn, state)
		if err != nil {
			log.Error("%s Failed to update DNS for '%s': %v", t.logPrefix, fqdn, err)
		}
	}
}

func (t *TraefikProvider) processRouterRemove(state domain.RouterState) {
	hosts := extractHostsFromRule(state.Rule)
	if len(hosts) == 0 {
		log.Debug("%s No hostnames to remove for router '%s'", t.logPrefix, state.Name)
		return
	}
	for _, fqdn := range hosts {
		if t.recordRemoveOnStop {
			err := domain.EnsureDNSRemoveForRouterState(getDomainFromHostname(fqdn), fqdn, state)
			if err != nil {
				log.Error("%s Failed to remove DNS for '%s': %v", t.logPrefix, fqdn, err)
			}
		} else {
			log.Debug("%s Skipping DNS removal for '%s' (record_remove_on_stop is false)", t.logPrefix, fqdn)
		}
	}
}

// extractHostsFromRule extracts hostnames from Traefik router rules
func extractHostsFromRule(rule string) []string {
	log.Trace("[poll/traefik] Extracting hosts from rule: '%s'", rule)
	var hostnames []string

	// Helper to parse host args (handles single or multiple, with/without quotes)
	parseHosts := func(arg string) []string {
		var hosts []string
		for _, h := range strings.Split(arg, ",") {
			h = strings.TrimSpace(h)
			h = strings.Trim(h, "'\"` ")
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		return hosts
	}

	// Host(...)
	for _, match := range hostRuleRegex.FindAllStringSubmatch(rule, -1) {
		if len(match) > 1 {
			hostnames = append(hostnames, parseHosts(match[1])...)
		}
	}
	// HostSNI(...)
	for _, match := range hostSniRuleRegex.FindAllStringSubmatch(rule, -1) {
		if len(match) > 1 {
			hostnames = append(hostnames, parseHosts(match[1])...)
		}
	}
	// HostRegexp(...)
	for _, match := range hostRegexpRuleRegex.FindAllStringSubmatch(rule, -1) {
		if len(match) > 1 {
			hostnames = append(hostnames, parseHosts(match[1])...)
		}
	}

	return hostnames
}

// getDomainFromHostname extracts the domain from a FQDN
func getDomainFromHostname(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// getDNSProvider returns a DNS provider by name
func getDNSProvider(name string) (dns.Provider, error) {
	return dns.GetProvider(name, nil)
}

// GetDNSEntries returns all DNS entries from the provider (stub for interface compliance)
func (t *TraefikProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
	return nil, nil
}
