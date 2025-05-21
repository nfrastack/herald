// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package traefik

import (
	"container-dns-companion/pkg/log"
	"container-dns-companion/pkg/poll"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// Regular expression to extract hostnames from Traefik router rules
var hostRuleRegex = regexp.MustCompile(`Host\(\s*(?:\x60|')([^\x60']+)(?:\x60|')\s*\)`)

// TraefikProvider is a poll provider that monitors Traefik routers
type TraefikProvider struct {
	pollURL      string
	pollInterval time.Duration
	running      bool
	ctx          context.Context
	cancel       context.CancelFunc
	callback     func(hostnames []string) error
	configPath   string
	options      map[string]string
	ticker       *time.Ticker
}

// NewProvider creates a new Traefik poll provider
func NewProvider(options map[string]string) (poll.Provider, error) {
	log.Debug("[poll/traefik] Creating new Traefik provider with options: %+v", options)

	// Get poll URL from options
	pollURL := options["url"]
	if pollURL == "" {
		pollURL = "http://localhost:8080/api/http/routers"
		log.Debug("[poll/traefik] No URL specified, using default: %s", pollURL)
	} else {
		log.Debug("[poll/traefik] Using configured URL: %s", pollURL)
	}

	// Get poll interval from options
	pollInterval := 60 * time.Second
	if interval := options["interval"]; interval != "" {
		log.Debug("[poll/traefik] Found interval option: %s", interval)
		dur, err := time.ParseDuration(interval)
		if err == nil && dur > 0 {
			pollInterval = dur
			log.Debug("[poll/traefik] Setting poll interval from duration: %s", pollInterval)
		} else if parsed, err := strconv.Atoi(interval); err == nil && parsed > 0 {
			pollInterval = time.Duration(parsed) * time.Second
			log.Debug("[poll/traefik] Setting poll interval from seconds: %s", pollInterval)
		} else {
			log.Debug("[poll/traefik] Invalid interval format, using default: %s", pollInterval)
		}
	} else {
		log.Debug("[poll/traefik] No interval specified, using default: %s", pollInterval)
	}

	configPath := options["config_path"]
	if configPath != "" {
		var err error
		log.Debug("[poll/traefik] Found config_path option: %s", configPath)
		configPath, err = filepath.Abs(configPath)
		if err != nil {
			log.Error("[poll/traefik] Failed to resolve config path: %v", err)
			return nil, fmt.Errorf("[poll/traefik] invalid config path: %v", err)
		}
		log.Debug("[poll/traefik] Resolved config path to: %s", configPath)
	} else {
		log.Debug("[poll/traefik] No config_path specified")
	}

	ctx, cancel := context.WithCancel(context.Background())
	log.Trace("[poll/traefik] Created context with cancel function")

	provider := &TraefikProvider{
		pollURL:      pollURL,
		pollInterval: pollInterval,
		running:      false,
		ctx:          ctx,
		cancel:       cancel,
		configPath:   configPath,
		options:      options,
	}

	log.Debug("[poll/traefik] Successfully created new Traefik provider instance")
	log.Trace("[poll/traefik] Provider details: URL=%s, interval=%s, config_path=%s",
		provider.pollURL, provider.pollInterval, provider.configPath)

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
	log.Debug("[poll/traefik] StartPolling called")
	log.Info("[poll/traefik] Starting polling (interval: %s)", t.pollInterval)

	if t.running {
		log.Debug("[poll/traefik] Already running, skipping start")
		return nil
	}

	t.running = true
	log.Debug("[poll/traefik] Starting poll loop in goroutine")
	go t.pollLoop()
	log.Debug("[poll/traefik] Poll loop started")

	return nil
}

// StopPolling stops polling Traefik
func (t *TraefikProvider) StopPolling() error {
	log.Debug("[poll/traefik] StopPolling called")
	log.Info("[poll/traefik] Stopping polling")

	if !t.running {
		log.Debug("[poll/traefik] Not running, skipping stop")
		return nil
	}

	log.Debug("[poll/traefik] Setting running flag to false")
	t.running = false

	log.Debug("[poll/traefik] Canceling context")
	t.cancel()

	if t.ticker != nil {
		log.Debug("[poll/traefik] Stopping ticker")
		t.ticker.Stop()
	}

	log.Debug("[poll/traefik] Successfully stopped polling")
	return nil
}

// IsRunning returns whether the provider is running
func (t *TraefikProvider) IsRunning() bool {
	log.Trace("[poll/traefik] IsRunning check, current value: %v", t.running)
	return t.running
}

// MonitorTraefik sets the callback and starts polling
func (t *TraefikProvider) MonitorTraefik(callback func(hostnames []string) error) error {
	log.Debug("[poll/traefik] MonitorTraefik called with callback function")
	t.callback = callback
	log.Debug("[poll/traefik] Callback function set, starting polling")
	return t.StartPolling()
}

// pollLoop continuously polls the Traefik API at the specified interval
func (t *TraefikProvider) pollLoop() {
	log.Debug("[poll/traefik] Starting poll loop")

	// Process existing routers first
	log.Trace("[poll/traefik] Performing initial processing of Traefik routers")
	if err := t.processTraefikRouters(); err != nil {
		log.Error("[poll/traefik] Error processing Traefik routers: %v", err)
	} else {
		log.Debug("[poll/traefik] Initial processing of Traefik routers completed successfully")
	}

	// Create ticker for regular polling
	log.Trace("[poll/traefik] Creating ticker with interval: %s", t.pollInterval)
	ticker := time.NewTicker(t.pollInterval)
	t.ticker = ticker
	defer ticker.Stop()

	log.Debug("[poll/traefik] Entering main poll loop")
	for {
		select {
		case <-t.ctx.Done():
			log.Debug("[poll/traefik] Polling stopped due to context cancellation")
			return
		case <-ticker.C:
			log.Trace("[poll/traefik] Ticker triggered, processing Traefik routers")
			if err := t.processTraefikRouters(); err != nil {
				log.Error("[poll/traefik] Error processing Traefik routers: %v", err)
			} else {
				log.Trace("[poll/traefik] Successfully processed Traefik routers")
			}
		}
	}
}

// processTraefikRouters polls the Traefik API for routers
func (t *TraefikProvider) processTraefikRouters() error {
	log.Debug("[poll/traefik] Processing Traefik routers from API")

	// Skip if no callback is set
	if t.callback == nil {
		log.Debug("[poll/traefik] No callback set, skipping processing")
		return nil
	}

	// Create HTTP request
	log.Trace("[poll/traefik] Creating HTTP request to %s", t.pollURL)
	req, err := http.NewRequestWithContext(t.ctx, "GET", t.pollURL, nil)
	if err != nil {
		log.Error("[poll/traefik] Failed to create HTTP request: %v", err)
		return fmt.Errorf("[poll/traefik] failed to create request: %w", err)
	}

	// Send request
	log.Trace("[poll/traefik] Sending HTTP request to Traefik API")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("[poll/traefik] Failed to send HTTP request: %v", err)
		return fmt.Errorf("[poll/traefik] failed to send request: %w", err)
	}
	defer resp.Body.Close()
	log.Trace("[poll/traefik] Received HTTP response with status code: %d", resp.StatusCode)

	// Read response
	log.Trace("[poll/traefik] Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("[poll/traefik] Failed to read response body: %v", err)
		return fmt.Errorf("[poll/traefik] failed to read response: %w", err)
	}
	log.Trace("[poll/traefik] Response body size: %d bytes", len(body))

	// Check response status
	if resp.StatusCode != http.StatusOK {
		log.Error("[poll/traefik] Unexpected HTTP status code: %d", resp.StatusCode)
		return fmt.Errorf("[poll/traefik] unexpected status code: %d", resp.StatusCode)
	}

	// Parse JSON response
	log.Trace("[poll/traefik] Parsing JSON response")
	var routers map[string]interface{}
	if err := json.Unmarshal(body, &routers); err != nil {
		log.Error("[poll/traefik] Failed to parse JSON response: %v", err)
		return fmt.Errorf("[poll/traefik] failed to parse JSON: %w", err)
	}
	log.Debug("[poll/traefik] Found %d routers in API response", len(routers))

	// Extract hostnames from router rules
	var hostnames []string
	for routerName, routerData := range routers {
		log.Trace("[poll/traefik] Processing router: %s", routerName)

		router, ok := routerData.(map[string]interface{})
		if !ok {
			log.Trace("[poll/traefik] Router data is not a map, skipping: %v", routerData)
			continue
		}

		rule, ok := router["rule"].(string)
		if !ok {
			log.Trace("[poll/traefik] No rule found for router %s or not a string", routerName)
			continue
		}

		log.Trace("[poll/traefik] Router %s has rule: %s", routerName, rule)

		// Extract hostnames from rule
		extracted := extractHostsFromRule(rule)
		if len(extracted) > 0 {
			log.Trace("[poll/traefik] Extracted %d hostnames from router %s: %v", len(extracted), routerName, extracted)
			hostnames = append(hostnames, extracted...)
		} else {
			log.Trace("[poll/traefik] No hostnames extracted from router %s rule", routerName)
		}
	}

	// Call callback with extracted hostnames
	if len(hostnames) > 0 {
		log.Debug("[poll/traefik] Found %d hostnames in Traefik routers: %v", len(hostnames), hostnames)
		err := t.callback(hostnames)
		if err != nil {
			log.Error("[poll/traefik] Error in callback: %v", err)
			return fmt.Errorf("[poll/traefik] callback error: %w", err)
		}
		log.Debug("[poll/traefik] Successfully processed %d hostnames with callback", len(hostnames))
		return nil
	}

	log.Debug("[poll/traefik] No hostnames found in Traefik routers")
	return nil
}

// extractHostsFromRule extracts hostnames from Traefik router rules
func extractHostsFromRule(rule string) []string {
	log.Trace("[poll/traefik] Extracting hosts from rule: %s", rule)
	matches := hostRuleRegex.FindAllStringSubmatch(rule, -1)

	if len(matches) == 0 {
		log.Trace("[poll/traefik] No hosts found in rule")
		return nil
	}

	var hostnames []string
	for i, match := range matches {
		log.Trace("[poll/traefik] Processing match %d: %v", i, match)
		if len(match) > 1 {
			log.Trace("[poll/traefik] Adding hostname: %s", match[1])
			hostnames = append(hostnames, match[1])
		}
	}

	log.Trace("[poll/traefik] Extracted %d hostnames: %v", len(hostnames), hostnames)
	return hostnames
}

// GetDNSEntries returns DNS entries from Traefik configuration
func (t *TraefikProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
	log.Debug("[poll/traefik] GetDNSEntries called, reading Traefik configuration")

	if t.configPath == "" {
		log.Debug("[poll/traefik] No config path configured, returning empty DNS entries")
		return []poll.DNSEntry{}, nil
	}

	// Read Traefik configuration files
	log.Trace("[poll/traefik] Reading Traefik config from: %s", t.configPath)
	entries, err := t.readTraefikConfig()
	if err != nil {
		log.Error("[poll/traefik] Error reading Traefik config: %v", err)
		return nil, fmt.Errorf("[poll/traefik] failed to read config: %w", err)
	}

	log.Info("[poll/traefik] Found %d DNS entries from Traefik config", len(entries))
	return entries, nil
}

// readTraefikConfig reads Traefik configuration files and extracts DNS entries
func (t *TraefikProvider) readTraefikConfig() ([]poll.DNSEntry, error) {
	log.Debug("[poll/traefik] Reading Traefik configuration files")

	// For now, return an empty slice
	log.Debug("[poll/traefik] Placeholder implementation, returning empty slice")

	// Actual implementation would:
	log.Trace("[poll/traefik] TODO: Implement actual config file reading")
	// 1. Read Traefik config files
	// 2. Parse them to find hostnames/routes
	// 3. Extract target services/endpoints
	// 4. Create DNS entries
	return []poll.DNSEntry{}, nil
}
