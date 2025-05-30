// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"
)

type TailscaleProvider struct {
	apiURL             string
	apiKey             string
	apiAuthID          string
	tailnet            string
	domain             string
	interval           time.Duration
	processExisting    bool
	recordRemoveOnStop bool
	filterConfig       pollCommon.FilterConfig
	hostnameFormat     string
	ctx                context.Context
	cancel             context.CancelFunc
	running            bool
	logPrefix          string
	profileName        string
	logger             *log.ScopedLogger
	lastKnownRecords   map[string]string // hostname:recordType -> target, to track changes
	lastEntries        []poll.DNSEntry   // Track last poll entries like ZeroTier

	// Token management
	tokenMutex    sync.RWMutex
	accessToken   string
	tokenExpiry   time.Time
	refreshToken  string
	clientID      string
	clientSecret  string
	tlsConfig     pollCommon.TLSConfig
}

type TailscaleDevice struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Hostname        string    `json:"hostname"`
	Addresses       []string  `json:"addresses"`
	User            string    `json:"user"`
	OS              string    `json:"os"`
	Online          bool      `json:"online"`
	LastSeen        time.Time `json:"lastSeen"`
	Tags            []string  `json:"tags"`
	MachineKey      string    `json:"machineKey"`
	NodeKey         string    `json:"nodeKey"`
	ClientVersion   string    `json:"clientVersion"`
	UpdateAvailable bool      `json:"updateAvailable"`
}

type TailscaleDevicesResponse struct {
	Devices []TailscaleDevice `json:"devices"`
}

// TokenResponse represents the OAuth token response from Tailscale
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// refreshAccessToken obtains a new access token using OAuth client credentials
func (t *TailscaleProvider) refreshAccessToken() error {
	if t.clientID == "" || t.clientSecret == "" {
		return fmt.Errorf("OAuth client credentials not configured")
	}

	// Create HTTP client with TLS configuration
	httpClient, err := t.tlsConfig.CreateHTTPClient()
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Prepare OAuth request
	tokenURL := "https://api.tailscale.com/api/v2/oauth/token"
	data := neturl.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {t.clientID},
		"client_secret": {t.clientSecret},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	log.Debug("[tailscale] Requesting OAuth access token")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("OAuth token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OAuth token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Update token information with proper locking
	t.tokenMutex.Lock()
	defer t.tokenMutex.Unlock()

	t.accessToken = tokenResp.AccessToken
	t.refreshToken = tokenResp.RefreshToken

	// Calculate expiry time (subtract 60 seconds for safety margin)
	expiryDuration := time.Duration(tokenResp.ExpiresIn-60) * time.Second
	t.tokenExpiry = time.Now().Add(expiryDuration)

	log.Info("[tailscale] OAuth access token refreshed, expires at %s", t.tokenExpiry.Format(time.RFC3339))
	return nil
}

// getValidAccessToken returns a valid access token, refreshing if necessary
func (t *TailscaleProvider) getValidAccessToken() (string, error) {
	t.tokenMutex.RLock()

	// Check if token needs refresh (within 5 minutes of expiry)
	needsRefresh := time.Now().Add(5 * time.Minute).After(t.tokenExpiry)
	currentToken := t.accessToken

	t.tokenMutex.RUnlock()

	// Refresh token if needed
	if needsRefresh && t.clientID != "" && t.clientSecret != "" {
		log.Debug("[tailscale] Access token expiring soon, refreshing...")
		if err := t.refreshAccessToken(); err != nil {
			log.Warn("[tailscale] Failed to refresh access token: %v", err)
			// Continue with current token if refresh fails
			return currentToken, nil
		}

		t.tokenMutex.RLock()
		currentToken = t.accessToken
		t.tokenMutex.RUnlock()
	}

	if currentToken == "" {
		return "", fmt.Errorf("no valid access token available")
	}

	return currentToken, nil
}

// NewTailscaleProvider creates a new Tailscale provider with token management
func NewTailscaleProvider(options map[string]string) (*TailscaleProvider, error) {
	// Parse TLS configuration
	tlsConfig := pollCommon.ParseTLSConfigFromOptions(options)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	provider := &TailscaleProvider{
		tlsConfig: tlsConfig,
	}

	// Initialize OAuth credentials if provided
	if clientID, ok := options["api_auth_id"]; ok {
		provider.clientID = clientID
	}
	if clientSecret, ok := options["api_auth_token"]; ok {
		provider.clientSecret = clientSecret
	}

	// If we have OAuth credentials, get initial token
	if provider.clientID != "" && provider.clientSecret != "" {
		if err := provider.refreshAccessToken(); err != nil {
			return nil, fmt.Errorf("failed to get initial access token: %w", err)
		}
	} else if apiKey, ok := options["api_key"]; ok {
		// Use static API key
		provider.accessToken = apiKey
		// Set a far future expiry for static tokens
		provider.tokenExpiry = time.Now().Add(365 * 24 * time.Hour)
	}

	return provider, nil
}

func NewProvider(options map[string]string) (poll.Provider, error) {
	parsed := pollCommon.ParsePollProviderOptions(options, pollCommon.PollProviderOptions{
		Interval:           120 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "tailscale",
	})

	logPrefix := pollCommon.BuildLogPrefix("tailscale", parsed.Name)
	profileName := parsed.Name

	// Handle different authentication methods
	var apiKey string
	var apiAuthID string

	// Method 1: Direct API key
	apiKey = pollCommon.GetOptionOrEnv(options, "api_key", "TAILSCALE_API_KEY", "")

	// Method 2: Auth token + Auth ID (need to exchange for access token)
	if apiKey == "" {
		authToken := pollCommon.GetOptionOrEnv(options, "api_auth_token", "TAILSCALE_API_AUTH_TOKEN", "")
		apiAuthID = pollCommon.GetOptionOrEnv(options, "api_auth_id", "TAILSCALE_API_AUTH_ID", "")

		if authToken != "" && apiAuthID != "" {
			// Exchange auth token for access token
			exchangedKey, err := exchangeAuthToken(authToken, apiAuthID, logPrefix)
			if err != nil {
				return nil, fmt.Errorf("%s failed to exchange auth token: %v", logPrefix, err)
			}
			apiKey = exchangedKey
		}
	}

	// Support both network and tailnet for flexibility
	tailnet := pollCommon.GetOptionOrEnv(options, "tailnet", "TAILSCALE_TAILNET", "")
	if tailnet == "" {
		tailnet = pollCommon.GetOptionOrEnv(options, "network", "TAILSCALE_NETWORK", "")
	}

	domain := pollCommon.GetOptionOrEnv(options, "domain", "TAILSCALE_DOMAIN", "")

	// Hostname format options: "simple", "tailscale", "full"
	hostnameFormat := pollCommon.GetOptionOrEnv(options, "hostname_format", "TAILSCALE_HOSTNAME_FORMAT", "simple")

	// Auto-detect API URL - default to Tailscale, assume Headscale if custom URL
	apiURL := pollCommon.GetOptionOrEnv(options, "api_url", "TAILSCALE_API_URL", "")
	if apiURL == "" {
		apiURL = "https://api.tailscale.com/api/v2"
		log.Debug("%s Using Tailscale API (default)", logPrefix)
	} else {
		log.Debug("%s Using custom API URL: %s", logPrefix, apiURL)
	}

	if apiKey == "" || domain == "" {
		return nil, fmt.Errorf("%s api_key and domain are required", logPrefix)
	}

	// If no network/tailnet specified, we'll use "-" which is Tailscale's shorthand for default tailnet
	if tailnet == "" {
		tailnet = "-"
		log.Debug("%s Using default tailnet", logPrefix)
	}

	// Parse filter configuration using standard syntax
	filterConfig, err := pollCommon.NewFilterFromOptions(options)
	if err != nil {
		return nil, fmt.Errorf("%s failed to parse filter configuration: %v", logPrefix, err)
	}

	// Add default online=true filter if no filters are configured
	if len(filterConfig.Filters) == 0 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == pollCommon.FilterTypeNone) {
		log.Debug("%s Adding default online=true filter", logPrefix)
		filterConfig.Filters = []pollCommon.Filter{
			{
				Type:      pollCommon.FilterTypeOnline,
				Value:     "true",
				Operation: "equals",
				Negate:    false,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	logLevel := options["log_level"]

	// Create scoped logger
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	// Log filter configuration
	if len(filterConfig.Filters) > 1 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type != pollCommon.FilterTypeNone) {
		log.Debug("%s Filter configuration: %d filters", logPrefix, len(filterConfig.Filters))
		for i, filter := range filterConfig.Filters {
			log.Trace("%s Filter %d: type=%s value=%s operation=%s negate=%t",
				logPrefix, i, filter.Type, filter.Value, filter.Operation, filter.Negate)
		}
	} else {
		log.Debug("%s No filters configured, processing all devices", logPrefix)
	}

	return &TailscaleProvider{
		apiURL:             apiURL,
		apiKey:             apiKey,
		apiAuthID:          apiAuthID,
		tailnet:            tailnet,
		domain:             domain,
		interval:           parsed.Interval,
		processExisting:    parsed.ProcessExisting,
		recordRemoveOnStop: parsed.RecordRemoveOnStop,
		filterConfig:       filterConfig,
		hostnameFormat:     hostnameFormat,
		ctx:                ctx,
		cancel:             cancel,
		logPrefix:          logPrefix,
		profileName:        profileName,
		logger:             scopedLogger,
		lastKnownRecords:   make(map[string]string),
		lastEntries:        make([]poll.DNSEntry, 0),
	}, nil
}

func (p *TailscaleProvider) StartPolling() error {
	if p.running {
		return nil
	}
	p.running = true

	p.logger.Debug("%s Starting Tailscale polling with interval: %v", p.logPrefix, p.interval)

	go p.pollLoop()

	return nil
}

func (p *TailscaleProvider) StopPolling() error {
	p.running = false
	p.cancel()
	return nil
}

func (p *TailscaleProvider) IsRunning() bool {
	return p.running
}

// logMemberAdded logs when a member is added with appropriate message based on filter type
func (p *TailscaleProvider) logMemberAdded(fqdn string) {
	p.logger.Info("%s Device added: %s", p.logPrefix, fqdn)
}

// logMemberRemoved logs when a member is removed with appropriate message based on filter type
func (p *TailscaleProvider) logMemberRemoved(fqdn string) {
	p.logger.Info("%s Device removed: %s", p.logPrefix, fqdn)
}

// logMemberChanged logs when a member's IP changes
func (p *TailscaleProvider) logMemberChanged(fqdn, oldIP, newIP string) {
	p.logger.Info("%s Device changed: %s (%s -> %s)", p.logPrefix, fqdn, oldIP, newIP)
}

func (p *TailscaleProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
	devices, err := p.fetchTailscaleDevices()
	if err != nil {
		p.logger.Error("%s Failed to fetch devices: %v", p.logPrefix, err)
		return nil, fmt.Errorf("failed to fetch devices: %v", err)
	}

	p.logger.Debug("%s Fetched %d devices from Tailscale API", p.logPrefix, len(devices))

	var entries []poll.DNSEntry
	for _, device := range devices {
		// Apply filters
		if !EvaluateTailscaleFilters(p.filterConfig, device) {
			continue
		}

		hostname := p.formatHostname(device)
		if hostname == "" {
			p.logger.Warn("%s Skipping device %s - no name or hostname available", p.logPrefix, device.ID)
			continue
		}

		if len(device.Addresses) == 0 {
			p.logger.Debug("%s Skipping device %s (no IP addresses)", p.logPrefix, hostname)
			continue
		}

		for _, ip := range device.Addresses {
			// Clean up IP address - remove CIDR notation if present
			cleanIP := ip
			if strings.Contains(ip, "/") {
				cleanIP = strings.Split(ip, "/")[0]
			}

			recordType := "A"
			if strings.Contains(cleanIP, ":") {
				recordType = "AAAA"
				p.logger.Debug("%s IPv6 address detected for device %s", p.logPrefix, hostname)
			}

			p.logger.Debug("%s Creating DNS entry - hostname: %s, ip: %s, type: %s, source: %s",
				p.logPrefix, hostname, cleanIP, recordType, p.profileName)

			entry := poll.DNSEntry{
				Hostname:   hostname,
				Domain:     p.domain,
				RecordType: recordType,
				Target:     cleanIP,
				TTL:        120,
				SourceName: p.profileName,
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func (p *TailscaleProvider) fetchTailscaleDevices() ([]TailscaleDevice, error) {
	// Get valid access token (will refresh if needed)
	accessToken, err := p.getValidAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get valid access token: %w", err)
	}

	url := fmt.Sprintf("%s/tailnet/%s/devices", p.apiURL, p.tailnet)

	p.logger.Trace("%s Fetching devices from URL: %s", p.logPrefix, url)
	p.logger.Trace("%s Using tailnet: %s", p.logPrefix, p.tailnet)

	// Create HTTP client with TLS configuration
	httpClient, err := p.tlsConfig.CreateHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	if p.apiAuthID != "" {
		req.Header.Set("Tailscale-Auth-User", p.apiAuthID)
		p.logger.Trace("%s Using auth ID: %s", p.logPrefix, p.apiAuthID)
	}

	p.logger.Trace("%s Making HTTP request to Tailscale API", p.logPrefix)
	resp, err := httpClient.Do(req)
	if err != nil {
		p.logger.Error("%s API request failed: %v", p.logPrefix, err)
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			// Token might be expired, try to refresh
			if p.clientID != "" && p.clientSecret != "" {
				p.logger.Debug("%s Received 401, attempting token refresh", p.logPrefix)
				if refreshErr := p.refreshAccessToken(); refreshErr != nil {
					return nil, fmt.Errorf("HTTP %d and failed to refresh token: %s", resp.StatusCode, string(body))
				}
				// Retry the request with new token
				return p.fetchTailscaleDevices()
			}
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	p.logger.Trace("%s Received %d bytes from Tailscale API", p.logPrefix, len(data))
	p.logger.Trace("%s Parsing JSON response", p.logPrefix)
	var response TailscaleDevicesResponse
	if err := json.Unmarshal(data, &response); err != nil {
		p.logger.Error("%s Failed to parse JSON response: %v", p.logPrefix, err)
		p.logger.Debug("%s Raw response: %s", p.logPrefix, string(data))
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	p.logger.Verbose("%s Successfully fetched %d devices from Tailscale", p.logPrefix, len(response.Devices))
	return response.Devices, nil
}

func (p *TailscaleProvider) formatHostname(device TailscaleDevice) string {
	p.logger.Trace("%s Device %s - Name: '%s', Hostname: '%s', Format: '%s'",
		p.logPrefix, device.ID, device.Name, device.Hostname, p.hostnameFormat)

	switch p.hostnameFormat {
	case "simple":
		// Use just the device name, removing .tail suffix if present
		hostname := device.Name
		if hostname == "" {
			hostname = device.Hostname
		}

		p.logger.Trace("%s Before processing: '%s'", p.logPrefix, hostname)

		// Remove .tail... suffix if present for simple mode
		if idx := strings.Index(hostname, ".tail"); idx != -1 {
			hostname = hostname[:idx]
			p.logger.Trace("%s After removing .tail suffix: '%s'", p.logPrefix, hostname)
		}

		result := sanitizeHostname(hostname)
		p.logger.Trace("%s Final hostname for device %s: '%s'", p.logPrefix, device.ID, result)
		return result

	case "tailscale":
		// Use device name but sanitize it for DNS
		hostname := device.Name
		if hostname == "" {
			hostname = device.Hostname
		}
		if hostname == "" {
			return ""
		}

		// Remove .tail... suffix if present and sanitize
		if idx := strings.Index(hostname, ".tail"); idx != -1 {
			hostname = hostname[:idx]
		}

		// Replace any non-DNS safe characters with hyphens
		hostname = strings.ReplaceAll(hostname, ".", "-")
		hostname = strings.ReplaceAll(hostname, "_", "-")

		result := sanitizeHostname(hostname)
		p.logger.Trace("%s Final hostname for device %s: '%s'", p.logPrefix, device.ID, result)
		return result

	case "full":
		// Use the full Tailscale hostname as-is
		hostname := device.Hostname
		if hostname == "" {
			hostname = device.Name
		}
		result := sanitizeHostname(hostname)
		p.logger.Trace("%s Final hostname for device %s: '%s'", p.logPrefix, device.ID, result)
		return result

	default:
		// Fallback to simple
		hostname := device.Name
		if hostname == "" {
			hostname = device.Hostname
		}

		// Remove .tail... suffix if present for simple mode
		if idx := strings.Index(hostname, ".tail"); idx != -1 {
			hostname = hostname[:idx]
		}

		result := sanitizeHostname(hostname)
		p.logger.Trace("%s Final hostname for device %s: '%s'", p.logPrefix, device.ID, result)
		return result
	}
}

func sanitizeHostname(hostname string) string {
	// Remove invalid characters and make lowercase
	hostname = strings.ToLower(hostname)
	hostname = strings.ReplaceAll(hostname, "_", "-")
	hostname = strings.ReplaceAll(hostname, " ", "-")

	// Remove any characters that aren't alphanumeric or hyphens
	result := ""
	for _, r := range hostname {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result += string(r)
		}
	}

	// Remove leading/trailing hyphens
	result = strings.Trim(result, "-")

	return result
}

// EvaluateTailscaleFilters evaluates standard filters against a Tailscale device
func EvaluateTailscaleFilters(filterConfig pollCommon.FilterConfig, device TailscaleDevice) bool {
	// If no filters or only FilterTypeNone, pass everything
	if len(filterConfig.Filters) == 0 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == pollCommon.FilterTypeNone) {
		return true
	}

	for i, filter := range filterConfig.Filters {
		log.Trace("[tailscale] Evaluating filter %d: type=%s value=%s operation=%s negate=%t against device %s",
			i, filter.Type, filter.Value, filter.Operation, filter.Negate, device.Name)

		result := evaluateTailscaleFilter(filter, device)
		if filter.Negate {
			result = !result
		}

		log.Trace("[tailscale] Filter %d result: %t (after negate=%t)", i, result, filter.Negate)

		if !result {
			log.Trace("[tailscale] Device %s filtered out by filter %d", device.Name, i)
			return false // All filters must pass
		}
	}

	log.Trace("[tailscale] Device %s passed all filters", device.Name)
	return true
}

func evaluateTailscaleFilter(filter pollCommon.Filter, device TailscaleDevice) bool {
	switch filter.Type {
	case pollCommon.FilterTypeOnline:
		expected := filter.Value == "true"
		return device.Online == expected

	case pollCommon.FilterTypeName:
		return evaluateStringMatch(device.Name, filter.Value, filter.Operation)

	case "hostname":
		return evaluateStringMatch(device.Hostname, filter.Value, filter.Operation)

	case pollCommon.FilterTypeTag:
		// Check if any of the device's tags match the filter
		for _, tag := range device.Tags {
			if evaluateStringMatch(tag, filter.Value, filter.Operation) {
				return true
			}
		}
		return false

	case "id":
		return evaluateStringMatch(device.ID, filter.Value, filter.Operation)

	case "address":
		// Check if any of the device's addresses match the filter
		for _, addr := range device.Addresses {
			if evaluateStringMatch(addr, filter.Value, filter.Operation) {
				return true
			}
		}
		return false

	case "user":
		return evaluateStringMatch(device.User, filter.Value, filter.Operation)

	case "os":
		return evaluateStringMatch(device.OS, filter.Value, filter.Operation)

	case pollCommon.FilterTypeNone:
		return true // No filter always passes

	default:
		// Unknown filter type - log warning and pass
		return true
	}
}

// evaluateStringMatch handles string matching with different operations
func evaluateStringMatch(value, filterValue, operation string) bool {
	switch operation {
	case "equals":
		return strings.EqualFold(value, filterValue)
	case "contains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(filterValue))
	case "starts_with":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(filterValue))
	case "ends_with":
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(filterValue))
	case "regex":
		// For now, treat regex as contains for simplicity
		return strings.Contains(strings.ToLower(value), strings.ToLower(filterValue))
	default:
		return strings.Contains(strings.ToLower(value), strings.ToLower(filterValue))
	}
}

// exchangeAuthToken exchanges an auth token for an access token
func exchangeAuthToken(authToken, authID, logPrefix string) (string, error) {
	log.Debug("%s Exchanging auth token for access token", logPrefix)
	log.Debug("%s Client ID: %s", logPrefix, authID)
	log.Debug("%s Client Secret length: %d", logPrefix, len(authToken))

	url := "https://api.tailscale.com/api/v2/oauth/token"

	// OAuth2 client credentials grant with credentials in form data
	formData := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials",
		neturl.QueryEscape(authID), neturl.QueryEscape(authToken))
	log.Debug("%s Form data: client_id=%s&client_secret=[REDACTED]&grant_type=client_credentials", logPrefix, authID)

	// Create HTTP client with default TLS settings
	tlsConfig := pollCommon.DefaultTLSConfig()
	client, err := tlsConfig.CreateHTTPClient()
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP client: %w", err)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(formData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to exchange auth token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%s HTTP %d %s: %s for %s", logPrefix, resp.StatusCode, resp.Status, string(body), url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(data, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("no access token received from OAuth exchange")
	}

	log.Debug("%s Successfully exchanged auth token for access token", logPrefix)
	return tokenResponse.AccessToken, nil
}

func (p *TailscaleProvider) pollLoop() {
	p.logger.Verbose("%s Starting poll loop (interval: %v)", p.logPrefix, p.interval)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Do initial poll if processExisting is enabled
	if p.processExisting {
		p.logger.Verbose("%s Processing existing Tailscale devices on startup", p.logPrefix)
		p.processDevices()
	}

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.logger.Trace("%s Ticker triggered, processing Tailscale devices", p.logPrefix)
			p.processDevices()
		}
	}
}

func (p *TailscaleProvider) processDevices() {
	p.logger.Trace("%s Starting device processing cycle", p.logPrefix)
	devices, err := p.fetchTailscaleDevices()
	if err != nil {
		p.logger.Error("%s Failed to fetch devices: %v", p.logPrefix, err)
		return
	}

	p.logger.Trace("%s Processing devices and building current records map", p.logPrefix)

	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(p.logPrefix)
	current := make(map[string]string) // hostname:recordType -> target

	p.logger.Trace("%s Processing %d devices from Tailscale", p.logPrefix, len(devices))
	processedCount := 0
	filteredCount := 0

	for i, device := range devices {
		p.logger.Trace("%s Processing device %d/%d: %s (%s)", p.logPrefix, i+1, len(devices), device.Name, device.ID)

		// Apply filters
		if !EvaluateTailscaleFilters(p.filterConfig, device) {
			filteredCount++
			p.logger.Trace("%s Device %s filtered out", p.logPrefix, device.Name)
			continue
		}

		hostname := p.formatHostname(device)
		if hostname == "" {
			p.logger.Warn("%s Skipping device %s - no name or hostname available", p.logPrefix, device.ID)
			continue
		}

		if len(device.Addresses) == 0 {
			p.logger.Debug("%s Skipping device %s (no IP addresses)", p.logPrefix, hostname)
			continue
		}

		p.logger.Trace("%s Device %s has %d IP addresses", p.logPrefix, hostname, len(device.Addresses))
		processedCount++

		// Process each IP address
		for addrIdx, ip := range device.Addresses {
			p.logger.Trace("%s Processing IP %d/%d: %s for device %s", p.logPrefix, addrIdx+1, len(device.Addresses), ip, hostname)

			// Clean up IP address - remove CIDR notation if present
			cleanIP := ip
			if strings.Contains(ip, "/") {
				cleanIP = strings.Split(ip, "/")[0]
				p.logger.Trace("%s Cleaned IP %s -> %s", p.logPrefix, ip, cleanIP)
			}

			recordType := "A"
			if strings.Contains(cleanIP, ":") {
				recordType = "AAAA"
				p.logger.Trace("%s IPv6 address detected: %s", p.logPrefix, cleanIP)
			}

			// Create FQDN
			fqdn := hostname + "." + p.domain
			key := hostname + ":" + recordType
			current[key] = cleanIP

			p.logger.Trace("%s Checking record %s (%s) -> %s", p.logPrefix, fqdn, recordType, cleanIP)

			// Check if this is a new or changed record
			if lastTarget, exists := p.lastKnownRecords[key]; !exists || lastTarget != cleanIP {
				if !exists {
					p.logMemberAdded(fqdn)
				} else {
					p.logMemberChanged(fqdn, lastTarget, cleanIP)
				}

				// Extract domain and subdomain
				domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdn, p.logPrefix)
				p.logger.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s'", p.logPrefix, domainKey, subdomain, fqdn)

				if domainKey == "" {
					p.logger.Error("%s No domain config found for '%s' (tried to match domain from FQDN)", p.logPrefix, fqdn)
					continue
				}

				domainCfg, ok := config.GlobalConfig.Domains[domainKey]
				if !ok {
					p.logger.Error("%s Domain '%s' not found in config for fqdn='%s'", p.logPrefix, domainKey, fqdn)
					continue
				}

				realDomain := domainCfg.Name
				p.logger.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s')", p.logPrefix, realDomain, domainKey)

				state := domain.RouterState{
					SourceType:           "tailscale",
					Name:                 p.profileName,
					Service:              cleanIP,
					RecordType:           recordType,
					ForceServiceAsTarget: true, // VPN providers always use Service IP as target
				}

				p.logger.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdn, state)
				err := batchProcessor.ProcessRecord(realDomain, fqdn, state)
				if err != nil {
					p.logger.Error("%s Failed to ensure DNS for '%s': %v", p.logPrefix, fqdn, err)
				}
			} else {
				p.logger.Trace("%s Record unchanged: %s (%s) -> %s", p.logPrefix, fqdn, recordType, cleanIP)
			}
		}
	}

	if filteredCount > 0 {
		p.logger.Verbose("%s Filtered out %d devices, processed %d devices", p.logPrefix, filteredCount, processedCount)
	} else {
		p.logger.Verbose("%s Processed %d devices (no filtering applied)", p.logPrefix, processedCount)
	}

	p.logger.Trace("%s Checking for removed records (recordRemoveOnStop=%t)", p.logPrefix, p.recordRemoveOnStop)
	// Process removals if recordRemoveOnStop is enabled
	if p.recordRemoveOnStop {
		removedCount := 0
		for key, oldTarget := range p.lastKnownRecords {
			if _, exists := current[key]; !exists {
				removedCount++
				// Parse the key to get hostname and record type
				parts := strings.Split(key, ":")
				if len(parts) != 2 {
					continue
				}
				hostname, recordType := parts[0], parts[1]
				fqdn := hostname + "." + p.domain

				p.logMemberRemoved(fqdn)

				// Extract domain and subdomain
				domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdn, p.logPrefix)
				p.logger.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s' (removal)", p.logPrefix, domainKey, subdomain, fqdn)

				if domainKey == "" {
					p.logger.Error("%s No domain config found for '%s' (removal, tried to match domain from FQDN)", p.logPrefix, fqdn)
					continue
				}

				domainCfg, ok := config.GlobalConfig.Domains[domainKey]
				if !ok {
					p.logger.Error("%s Domain '%s' not found in config for fqdn='%s' (removal)", p.logPrefix, domainKey, fqdn)
					continue
				}

				realDomain := domainCfg.Name
				p.logger.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s') (removal)", p.logPrefix, realDomain, domainKey)

				state := domain.RouterState{
					SourceType:           "tailscale",
					Name:                 p.profileName,
					Service:              oldTarget,
					RecordType:           recordType,
					ForceServiceAsTarget: true, // VPN providers always use Service IP as target
				}

				p.logger.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdn, state)
				err := batchProcessor.ProcessRecordRemoval(realDomain, fqdn, state)
				if err != nil {
					p.logger.Error("%s Failed to remove DNS for '%s': %v", p.logPrefix, fqdn, err)
				}
			}
		}
		if removedCount > 0 {
			p.logger.Verbose("%s Processed %d record removals", p.logPrefix, removedCount)
		}
	} else {
		p.logger.Trace("%s Record removal disabled (recordRemoveOnStop=false)", p.logPrefix)
	}

	// Update the cache
	p.lastKnownRecords = current
	p.logger.Trace("%s Updated lastKnownRecords cache with %d entries", p.logPrefix, len(current))

	// Finalize the batch - this will sync output files only if there were changes
	//p.logger.Trace("%s Finalizing batch processor", p.logPrefix)
	batchProcessor.FinalizeBatch()
}

func init() {
	poll.RegisterProvider("tailscale", NewProvider)
}
