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
	// Get poll URL from options
	pollURL := options["url"]
	if pollURL == "" {
		pollURL = "http://localhost:8080/api/http/routers"
	}

	// Get poll interval from options
	pollInterval := 60 * time.Second
	if interval := options["interval"]; interval != "" {
		dur, err := time.ParseDuration(interval)
		if err == nil && dur > 0 {
			pollInterval = dur
		} else if parsed, err := strconv.Atoi(interval); err == nil && parsed > 0 {
			pollInterval = time.Duration(parsed) * time.Second
		}
	}

	configPath := options["config_path"]
	if configPath != "" {
		var err error
		configPath, err = filepath.Abs(configPath)
		if err != nil {
			return nil, fmt.Errorf("[poll/traefik] invalid config path: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TraefikProvider{
		pollURL:      pollURL,
		pollInterval: pollInterval,
		running:      false,
		ctx:          ctx,
		cancel:       cancel,
		configPath:   configPath,
		options:      options,
	}, nil
}

// Register the Traefik provider
func init() {
	poll.RegisterProvider("traefik", NewProvider)
}

// StartPolling starts polling Traefik for routers
func (t *TraefikProvider) StartPolling() error {
	log.Info("[poll/traefik] Starting polling (interval: %s)", t.pollInterval)

	if t.running {
		return nil
	}

	t.running = true
	go t.pollLoop()

	return nil
}

// StopPolling stops polling Traefik
func (t *TraefikProvider) StopPolling() error {
	log.Info("[poll/traefik] Stopping polling")

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
	return t.running
}

// MonitorTraefik sets the callback and starts polling
func (t *TraefikProvider) MonitorTraefik(callback func(hostnames []string) error) error {
	t.callback = callback
	return t.StartPolling()
}

// pollLoop continuously polls the Traefik API at the specified interval
func (t *TraefikProvider) pollLoop() {
	// Process existing routers first
	if err := t.processTraefikRouters(); err != nil {
		log.Error("[poll/traefik] Error processing Traefik routers: %v", err)
	}

	// Create ticker for regular polling
	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			log.Debug("[poll/traefik] Polling stopped due to context cancellation")
			return
		case <-ticker.C:
			if err := t.processTraefikRouters(); err != nil {
				log.Error("[poll/traefik] Error processing Traefik routers: %v", err)
			}
		}
	}
}

// processTraefikRouters polls the Traefik API for routers
func (t *TraefikProvider) processTraefikRouters() error {
	// Skip if no callback is set
	if t.callback == nil {
		return nil
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(t.ctx, "GET", t.pollURL, nil)
	if err != nil {
		return fmt.Errorf("[poll/traefik] failed to create request: %w", err)
	}

	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("[poll/traefik] failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("[poll/traefik] failed to read response: %w", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[poll/traefik] unexpected status code: %d", resp.StatusCode)
	}

	// Parse JSON response
	var routers map[string]interface{}
	if err := json.Unmarshal(body, &routers); err != nil {
		return fmt.Errorf("[poll/traefik] failed to parse JSON: %w", err)
	}

	// Extract hostnames from router rules
	var hostnames []string
	for _, routerData := range routers {
		router, ok := routerData.(map[string]interface{})
		if !ok {
			continue
		}

		rule, ok := router["rule"].(string)
		if !ok {
			continue
		}

		// Extract hostnames from rule
		extracted := extractHostsFromRule(rule)
		if len(extracted) > 0 {
			hostnames = append(hostnames, extracted...)
		}
	}

	// Call callback with extracted hostnames
	if len(hostnames) > 0 {
		log.Debug("[poll/traefik] Found %d hostnames in Traefik routers", len(hostnames))
		return t.callback(hostnames)
	}

	return nil
}

// extractHostsFromRule extracts hostnames from Traefik router rules
func extractHostsFromRule(rule string) []string {
	matches := hostRuleRegex.FindAllStringSubmatch(rule, -1)
	if len(matches) == 0 {
		return nil
	}

	var hostnames []string
	for _, match := range matches {
		if len(match) > 1 {
			hostnames = append(hostnames, match[1])
		}
	}

	return hostnames
}

// GetDNSEntries returns DNS entries from Traefik configuration
func (t *TraefikProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
	// Read Traefik configuration files
	entries, err := t.readTraefikConfig()
	if err != nil {
		return nil, err
	}

	log.Info("[poll/traefik] Found %d DNS entries from Traefik config", len(entries))
	return entries, nil
}

// pollTraefikConfig polls Traefik configuration files for DNS entries
func (t *TraefikProvider) pollTraefikConfig() {
	log.Debug("[poll/traefik] Polling Traefik configuration files in %s", t.configPath)

	// Implementation would read Traefik config files and extract DNS entries
	// For now, just a placeholder
	_, err := t.readTraefikConfig()
	if err != nil {
		log.Error("[poll/traefik] Error reading Traefik config: %v", err)
	}
}

// readTraefikConfig reads Traefik configuration files and extracts DNS entries
func (t *TraefikProvider) readTraefikConfig() ([]poll.DNSEntry, error) {
	// For now, return an empty slice
	// Actual implementation would:
	// 1. Read Traefik config files
	// 2. Parse them to find hostnames/routes
	// 3. Extract target services/endpoints
	// 4. Create DNS entries
	return []poll.DNSEntry{}, nil
}
