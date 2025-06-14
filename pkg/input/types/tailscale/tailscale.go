// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"herald/pkg/config"
	"herald/pkg/domain"
	"herald/pkg/input/common"
	"herald/pkg/log"

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

// TailscaleDevice represents a device in a Tailscale network
type TailscaleDevice struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Hostname          string    `json:"hostname"`
	ClientVersion     string    `json:"clientVersion"`
	OS                string    `json:"os"`
	User              string    `json:"user"`
	Created           time.Time `json:"created"`
	LastSeen          time.Time `json:"lastSeen"`
	Online            bool      `json:"online"`
	Addresses         []string  `json:"addresses"`
	TailscaleIPs      []string  `json:"tailscaleIPs"`
	AllowedIPs        []string  `json:"allowedIPs"`
	Blocked           bool      `json:"blocked"`
	Tags              []string  `json:"tags"`
	KeyExpiryDisabled bool      `json:"keyExpiryDisabled"`
	Expires           time.Time `json:"expires"`
	IsExternal        bool      `json:"isExternal"`
	MachineKey        string    `json:"machineKey"`
	NodeKey           string    `json:"nodeKey"`
	UpdateAvailable   bool      `json:"updateAvailable"`
}

// HeadscaleDevice represents a device in a Headscale network
type HeadscaleDevice struct {
	ID                   uint64     `json:"id"`
	MachineKey           string     `json:"machineKey"`
	NodeKey              string     `json:"nodeKey"`
	DiscoKey             string     `json:"discoKey"`
	IPAddresses          []string   `json:"ipAddresses"`
	Name                 string     `json:"name"`
	User                 User       `json:"user"`
	LastSeen             time.Time  `json:"lastSeen"`
	LastSuccessfulUpdate time.Time  `json:"lastSuccessfulUpdate"`
	Expiry               time.Time  `json:"expiry"`
	PreAuthKey           PreAuthKey `json:"preAuthKey"`
	CreatedAt            time.Time  `json:"createdAt"`
	RegisterMethod       string     `json:"registerMethod"`
	Online               bool       `json:"online"`
	InvalidTags          []string   `json:"invalidTags"`
	ValidTags            []string   `json:"validTags"`
	GivenName            string     `json:"givenName"`
	ForcedTags           []string   `json:"forcedTags"`
}

// User represents a Headscale user
type User struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

// PreAuthKey represents a Headscale pre-auth key
type PreAuthKey struct {
	Key        string    `json:"key"`
	ID         uint64    `json:"id"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	ACLTags    []string  `json:"aclTags"`
}

// TailscaleAPIResponse represents the response from the Tailscale API
type TailscaleAPIResponse struct {
	Devices []TailscaleDevice `json:"devices"`
}

// HeadscaleAPIResponse represents the response from the Headscale API
type HeadscaleAPIResponse struct {
	Machines []HeadscaleDevice `json:"machines"`
}

// TailscaleProvider implements the polling interface for Tailscale networks
type TailscaleProvider struct {
	apiURL             string
	apiKey             string
	tailnet            string
	domain             string
	interval           time.Duration
	processExisting    bool
	recordRemoveOnStop bool
	filterConfig       common.FilterConfig
	hostnameFormat     string
	ctx                context.Context
	cancel             context.CancelFunc
	running            bool
	logPrefix          string
	profileName        string
	logger             *log.ScopedLogger
	lastKnownRecords   map[string]string // hostname:recordType -> target, to track changes
	lastEntries        []DNSEntry        // Track last poll entries like ZeroTier

	// Token management
	tokenMutex   sync.RWMutex
	accessToken  string
	tokenExpiry  time.Time
	refreshToken string
	clientID     string
	clientSecret string
	tlsConfig    common.TLSConfig
	name         string
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

	t.logger.Debug("Requesting OAuth access token")
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

	t.logger.Verbose("%s OAuth access token refreshed, expires at %s", t.logPrefix, t.tokenExpiry.Format(time.RFC3339))
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
		t.logger.Debug("%s Access token expiring soon, refreshing...", t.logPrefix)
		if err := t.refreshAccessToken(); err != nil {
			t.logger.Warn("%s Failed to refresh access token: %v", t.logPrefix, err)
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

func NewProvider(options map[string]string) (Provider, error) {
	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           120 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "tailscale",
	})

	logPrefix := common.BuildLogPrefix("tailscale", parsed.Name)
	profileName := parsed.Name

	// Parse TLS configuration
	tlsConfig := common.ParseTLSConfigFromOptions(options)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("%s invalid TLS configuration: %w", logPrefix, err)
	}

	// Handle different authentication methods with file:// and env:// support
	var apiKey string
	var clientID string
	var clientSecret string

	// Method 1: Direct API key (traditional method) - supports file:// and env://
	apiKey = common.ReadFileValue(options["api_key"])

	// Method 2: OAuth client credentials (new method) - supports file:// and env://
	if apiKey == "" {
		clientID = common.ReadFileValue(options["api_auth_id"])
		clientSecret = common.ReadFileValue(options["api_auth_token"])

		// Also check for client_id/client_secret aliases
		if clientID == "" {
			clientID = common.ReadFileValue(options["client_id"])
		}
		if clientSecret == "" {
			clientSecret = common.ReadFileValue(options["client_secret"])
		}
	}

	// Method 3: Legacy auth token exchange (for backwards compatibility)
	if apiKey == "" && clientID == "" && clientSecret == "" {
		authToken := options["api_auth_token"]
		authID := options["api_auth_id"]

		if authToken != "" && authID != "" {
			// Exchange auth token for access token using the old method
			exchangedKey, err := exchangeAuthToken(authToken, authID, logPrefix)
			if err != nil {
				return nil, fmt.Errorf("%s failed to exchange auth token: %v", logPrefix, err)
			}
			apiKey = exchangedKey
		}
	}

	// Validate authentication
	if apiKey == "" && (clientID == "" || clientSecret == "") {
		return nil, fmt.Errorf("%s authentication required: provide either api_key OR (client_id + client_secret)", logPrefix)
	}

	// Support both network and tailnet for flexibility - supports file:// and env://
	tailnet := options["tailnet"]
	if tailnet == "" {
		tailnet = options["network"]
	}

	domain := options["domain"]

	// Hostname format options: "simple", "tailscale", "full"
	hostnameFormat := options["hostname_format"]
	if hostnameFormat == "" {
		hostnameFormat = "simple"
	}

	// Auto-detect API URL - default to Tailscale, assume Headscale if custom URL
	apiURL := options["api_url"]
	if apiURL == "" {
		apiURL = "https://api.tailscale.com/api/v2"
		log.Debug("%s Using Tailscale API (default)", logPrefix)
	} else {
		log.Debug("%s Using custom API URL: %s", logPrefix, apiURL)
	}

	if domain == "" {
		return nil, fmt.Errorf("%s domain is required", logPrefix)
	}

	// If no network/tailnet specified, we'll use "-" which is Tailscale's shorthand for default tailnet
	if tailnet == "" {
		tailnet = "-"
		log.Debug("%s Using default tailnet", logPrefix)
	}

	// Convert string options to structured options for filtering
	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	// Parse filter configuration using structured format
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions)
	if err != nil {
		log.Debug("%s Error creating filter configuration: %v, using default", logPrefix, err)
		filterConfig = common.DefaultFilterConfig()
	}

	// Add default online=true filter if no filters are configured
	if len(filterConfig.Filters) == 0 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == common.FilterTypeNone) {
		log.Debug("%s Adding default online=true filter", logPrefix)
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

	ctx, cancel := context.WithCancel(context.Background())
	logLevel := options["log_level"]

	// Create scoped logger
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	// Log filter configuration
	if len(filterConfig.Filters) > 1 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type != common.FilterTypeNone) {
		log.Debug("%s Filter configuration: %d filters", logPrefix, len(filterConfig.Filters))
		for i, filter := range filterConfig.Filters {
			log.Trace("%s Filter %d: type=%s value=%s operation=%s negate=%t",
				logPrefix, i, filter.Type, filter.Value, filter.Operation, filter.Negate)
		}
	} else {
		log.Debug("%s No filters configured, processing all devices", logPrefix)
	}

	provider := &TailscaleProvider{
		apiURL:             apiURL,
		apiKey:             apiKey,
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
		lastEntries:        make([]DNSEntry, 0),
		tlsConfig:          tlsConfig,
		clientID:           clientID,
		clientSecret:       clientSecret,
	}

	// Set initial token state
	if apiKey != "" {
		// Static API key - set far future expiry
		provider.accessToken = apiKey
		provider.tokenExpiry = time.Now().Add(365 * 24 * time.Hour)
		log.Debug("%s Using static API key", logPrefix)
	} else {
		// OAuth credentials - will get token on first API call
		log.Debug("%s Using OAuth client credentials (client_id: %s)", logPrefix, clientID)
	}

	return provider, nil
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
	p.logger.Info("Device added: %s", fqdn)
}

// logMemberRemoved logs when a member is removed with appropriate message based on filter type
func (p *TailscaleProvider) logMemberRemoved(fqdn string) {
	p.logger.Info("Device removed: %s", fqdn)
}

// logMemberChanged logs when a member's IP changes
func (p *TailscaleProvider) logMemberChanged(fqdn, oldIP, newIP string) {
	p.logger.Info("Device changed: %s (%s -> %s)", fqdn, oldIP, newIP)
}

func (p *TailscaleProvider) GetDNSEntries() ([]DNSEntry, error) {
	devices, err := p.fetchTailscaleDevices()
	if err != nil {
		p.logger.Error("%s Failed to fetch devices: %v", p.logPrefix, err)
		return nil, fmt.Errorf("failed to fetch devices: %v", err)
	}

	p.logger.Debug("%s Fetched %d devices from Tailscale API", p.logPrefix, len(devices))

	var entries []DNSEntry
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

			entry := DNSEntry{
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

// EvaluateTailscaleFilters evaluates structured filters against a Tailscale device
func EvaluateTailscaleFilters(filterConfig common.FilterConfig, device TailscaleDevice) bool {
	return filterConfig.Evaluate(device, func(filter common.Filter, entry any) bool {
		dev := entry.(TailscaleDevice)
		return evaluateTailscaleFilter(filter, dev)
	})
}

func evaluateTailscaleFilter(filter common.Filter, device TailscaleDevice) bool {
	switch filter.Type {
	case common.FilterTypeOnline:
		for _, condition := range filter.Conditions {
			expected := strings.ToLower(condition.Value) == "true"
			if device.Online != expected {
				return false
			}
		}
		return true

	case common.FilterTypeName:
		for _, condition := range filter.Conditions {
			if !common.RegexMatch(condition.Value, device.Name) {
				return false
			}
		}
		return true

	case "hostname":
		for _, condition := range filter.Conditions {
			if !common.RegexMatch(condition.Value, device.Hostname) {
				return false
			}
		}
		return true

	case common.FilterTypeTag:
		for _, condition := range filter.Conditions {
			found := false
			for _, tag := range device.Tags {
				if common.RegexMatch(condition.Value, tag) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true

	case "id":
		for _, condition := range filter.Conditions {
			if !common.RegexMatch(condition.Value, device.ID) {
				return false
			}
		}
		return true

	case "address":
		for _, condition := range filter.Conditions {
			found := false
			for _, addr := range device.Addresses {
				if common.RegexMatch(condition.Value, addr) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true

	case common.FilterTypeUser:
		for _, condition := range filter.Conditions {
			if !common.RegexMatch(condition.Value, device.User) {
				return false
			}
		}
		return true

	case common.FilterTypeOS:
		for _, condition := range filter.Conditions {
			if !common.RegexMatch(condition.Value, device.OS) {
				return false
			}
		}
		return true

	default:
		return true
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
	tlsConfig := common.DefaultTLSConfig()
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
				domainKey, subdomain := common.ExtractDomainAndSubdomain(fqdn)
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
				domainKey, subdomain := common.ExtractDomainAndSubdomain(fqdn)
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
}

// GetName returns the provider name
func (tp *TailscaleProvider) GetName() string {
	return "tailscale"
}
