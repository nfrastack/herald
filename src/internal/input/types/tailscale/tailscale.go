// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input/common"
	"github.com/nfrastack/herald/internal/log"
	heraldstate "github.com/nfrastack/herald/internal/state"

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

type User struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

type PreAuthKey struct {
	Key        string    `json:"key"`
	ID         uint64    `json:"id"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	ACLTags    []string  `json:"aclTags"`
}

type TailscaleAPIResponse struct {
	Devices []TailscaleDevice `json:"devices"`
}

type HeadscaleAPIResponse struct {
	Machines []HeadscaleDevice `json:"machines"`
}

type TailscaleProvider struct {
	apiURL             string
	apiKey             string
	tailnet            string
	domain             string
	additionalDomains  []string // extra domains to publish each device under (single poll, N writes)
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
	lastKnownRecords   map[string]string   // hostname:recordType -> target, to track changes
	lastEntries        []DNSEntry          // Track last poll entries like ZeroTier
	outputWriter       domain.OutputWriter // Injected dependency
	outputSyncer       domain.OutputSyncer // Injected dependency

	tokenMutex   sync.RWMutex
	accessToken  string
	tokenExpiry  time.Time
	refreshToken string
	clientID     string
	clientSecret string
	tlsConfig    common.TLSConfig
	name         string

	domainConfigs map[string]config.DomainConfig // Add domain configs for domain matching
}

type TailscaleDevicesResponse struct {
	Devices []TailscaleDevice `json:"devices"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (t *TailscaleProvider) refreshAccessToken() error {
	if t.clientID == "" || t.clientSecret == "" {
		return fmt.Errorf("OAuth client credentials not configured")
	}

	httpClient, err := t.tlsConfig.CreateHTTPClient()
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

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

	t.logger.With("action", "auth.accept").Debug("oauth access token request")
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

	t.tokenMutex.Lock()
	defer t.tokenMutex.Unlock()

	t.accessToken = tokenResp.AccessToken
	t.refreshToken = tokenResp.RefreshToken

	expiryDuration := time.Duration(tokenResp.ExpiresIn-60) * time.Second
	t.tokenExpiry = time.Now().Add(expiryDuration)

	t.logger.With("action", "auth.accept").Verbose("oauth access token refreshed, expires at %s", t.tokenExpiry.Format(time.RFC3339))
	return nil
}

func (t *TailscaleProvider) getValidAccessToken() (string, error) {
	t.tokenMutex.RLock()

	needsRefresh := time.Now().Add(5 * time.Minute).After(t.tokenExpiry)
	currentToken := t.accessToken

	t.tokenMutex.RUnlock()

	if needsRefresh && t.clientID != "" && t.clientSecret != "" {
		t.logger.With("action", "auth.accept").Debug("access token expiring soon, refreshing...")
		if err := t.refreshAccessToken(); err != nil {
			t.logger.With("action", "auth.reject").Warn("failed to refresh access token: %v", err)
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

func NewProvider(options map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           120 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "tailscale",
	})

	logPrefix := common.BuildLogPrefix("tailscale", parsed.Name)
	profileName := parsed.Name

	tlsConfig := common.ParseTLSConfigFromOptions(options)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("%s invalid TLS configuration: %w", logPrefix, err)
	}

	var apiKey string
	var clientID string
	var clientSecret string

	apiKey = common.ReadFileValue(options["api_key"])

	if apiKey == "" {
		clientID = common.ReadFileValue(options["api_auth_id"])
		clientSecret = common.ReadFileValue(options["api_auth_token"])

		if clientID == "" {
			clientID = common.ReadFileValue(options["client_id"])
		}
		if clientSecret == "" {
			clientSecret = common.ReadFileValue(options["client_secret"])
		}
	}

	if apiKey == "" && clientID == "" && clientSecret == "" {
		authToken := options["api_auth_token"]
		authID := options["api_auth_id"]

		if authToken != "" && authID != "" {
			exchangedKey, err := exchangeAuthToken(authToken, authID, logPrefix)
			if err != nil {
				return nil, fmt.Errorf("%s failed to exchange auth token: %v", logPrefix, err)
			}
			apiKey = exchangedKey
		}
	}

	if apiKey == "" && (clientID == "" || clientSecret == "") {
		return nil, fmt.Errorf("%s authentication required: provide either api_key OR (client_id + client_secret)", logPrefix)
	}

	tailnet := options["tailnet"]
	if tailnet == "" {
		tailnet = options["network"]
	}

	domain := options["domain"]
	additionalDomains := common.ParseDomainList(common.ReadFileValue(options["additional_domains"]))

	hostnameFormat := options["hostname_format"]
	if hostnameFormat == "" {
		hostnameFormat = "simple"
	}

	apiURL := options["api_url"]
	if apiURL == "" {
		apiURL = "https://api.tailscale.com/api/v2"
		log.NewScopedLogger(logPrefix, "").With("action", "config.load").Debug("tailscale API (default)")
	} else {
		log.NewScopedLogger(logPrefix, "").With("action", "config.load").Debug("custom API URL: %s", apiURL)
	}

	if domain == "" {
		return nil, fmt.Errorf("%s domain is required", logPrefix)
	}

	if tailnet == "" {
		tailnet = "-"
		log.NewScopedLogger(logPrefix, "").With("action", "config.load").Debug("default tailnet")
	}

	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	filterLogPrefix := logPrefix + "/filter"
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions, filterLogger)
	if err != nil {
		log.NewScopedLogger(logPrefix, "").With("action", "config.error").Debug("creating filter configuration: %v, using default", err)
		filterConfig = common.DefaultFilterConfig()
	}

	if len(filterConfig.Filters) == 0 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == common.FilterTypeNone) {
		log.NewScopedLogger(logPrefix, "").With("action", "input.filter").Debug("default online=true filter")
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

	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		log.NewScopedLogger(logPrefix, "").With("action", "config.load").Info("provider log_level set to: '%s'", logLevel)
	}

	if len(filterConfig.Filters) > 1 || (len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type != common.FilterTypeNone) {
		log.NewScopedLogger(logPrefix, "").With("action", "input.filter").Debug("filter configuration: %d filters", len(filterConfig.Filters))
		for i, filter := range filterConfig.Filters {
			log.NewScopedLogger(logPrefix, "").With("action", "input.filter").Trace("filter %d: type=%s value=%s operation=%s negate=%t", i, filter.Type, filter.Value, filter.Operation, filter.Negate)
		}
	} else {
		log.NewScopedLogger(logPrefix, "").With("action", "input.filter").Debug("no filters configured, processing all devices")
	}

	provider := &TailscaleProvider{
		apiURL:             apiURL,
		apiKey:             apiKey,
		tailnet:            tailnet,
		domain:             domain,
		additionalDomains:  additionalDomains,
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
		outputWriter:       outputWriter,
		outputSyncer:       outputSyncer,
		clientID:           clientID,
		clientSecret:       clientSecret,
	}

	if apiKey != "" {
		provider.accessToken = apiKey
		provider.tokenExpiry = time.Now().Add(365 * 24 * time.Hour)
		log.NewScopedLogger(logPrefix, "").With("action", "auth.accept").Debug("static API key")
	} else {
		log.NewScopedLogger(logPrefix, "").With("action", "auth.accept").Debug("oauth client credentials (client_id: %s)", clientID)
	}

	return provider, nil
}

func (p *TailscaleProvider) StartPolling() error {
	if p.running {
		return nil
	}
	p.running = true

	p.logger.With("action", "provider.poll").Debug("tailscale polling with interval: %v", p.interval)

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

func (p *TailscaleProvider) logMemberAdded(fqdn string) {
	p.logger.With("action", "provider.event", "device", fqdn).Info("added")
}

func (p *TailscaleProvider) logMemberRemoved(fqdn string) {
	p.logger.With("action", "provider.event", "device", fqdn).Info("removed")
}

func (p *TailscaleProvider) logMemberChanged(fqdn, oldIP, newIP string) {
	p.logger.With("action", "provider.event", "device", fqdn).Info("changed: %s -> %s", oldIP, newIP)
}

func (p *TailscaleProvider) GetDNSEntries() ([]DNSEntry, error) {
	devices, err := p.fetchTailscaleDevices()
	if err != nil {
		p.logger.With("action", "sync.fail").Error("failed to fetch devices: %v", err)
		return nil, fmt.Errorf("failed to fetch devices: %v", err)
	}

	p.logger.With("action", "provider.poll").Debug("%d devices from Tailscale API", len(devices))

	var entries []DNSEntry
	for _, device := range devices {
		if !EvaluateTailscaleFilters(p.filterConfig, device) {
			continue
		}

		hostname := p.formatHostname(device)
		if hostname == "" {
			p.logger.With("action", "input.filter", "device", device.ID).Warn("no name or hostname available")
			continue
		}

		if len(device.Addresses) == 0 {
			p.logger.With("action", "input.filter").Debug("%s (no IP addresses)", hostname)
			continue
		}

		for _, ip := range device.Addresses {
			cleanIP := ip
			if strings.Contains(ip, "/") {
				cleanIP = strings.Split(ip, "/")[0]
			}

			recordType := "A"
			if strings.Contains(cleanIP, ":") {
				recordType = "AAAA"
				p.logger.With("action", "input.pass").Debug("ipv6 address for device %s", hostname)
			}

			p.logger.With("action", "record.create").Debug("dns entry - hostname: %s, ip: %s, type: %s, source: %s",
				hostname, cleanIP, recordType, p.profileName)

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
	accessToken, err := p.getValidAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get valid access token: %w", err)
	}

	url := fmt.Sprintf("%s/tailnet/%s/devices", p.apiURL, p.tailnet)

	p.logger.With("action", "provider.poll").Trace("devices from URL: %s", url)
	p.logger.With("action", "provider.poll").Trace("tailnet: %s", p.tailnet)

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

	p.logger.With("action", "provider.poll").Trace("http request to Tailscale API")
	resp, err := httpClient.Do(req)
	if err != nil {
		p.logger.With("action", "sync.fail").Error("api request failed: %v", err)
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			if p.clientID != "" && p.clientSecret != "" {
				p.logger.With("action", "auth.accept").Debug("401, attempting token refresh")
				if refreshErr := p.refreshAccessToken(); refreshErr != nil {
					return nil, fmt.Errorf("HTTP %d and failed to refresh token: %s", resp.StatusCode, string(body))
				}
				return p.fetchTailscaleDevices()
			}
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	p.logger.With("action", "provider.poll").Trace("%d bytes from Tailscale API", len(data))
	p.logger.With("action", "provider.poll").Trace("json response")
	var response TailscaleDevicesResponse
	if err := json.Unmarshal(data, &response); err != nil {
		p.logger.With("action", "sync.fail").Error("parse JSON response: %v", err)
		p.logger.With("action", "sync.fail").Debug("raw response: %s", string(data))
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	p.logger.With("action", "sync.done").Verbose("%d devices from Tailscale", len(response.Devices))
	return response.Devices, nil
}

func (p *TailscaleProvider) formatHostname(device TailscaleDevice) string {
	p.logger.With("action", "domain.match").Trace("device %s - name: '%s', hostname: '%s', format: '%s'",
		device.ID, device.Name, device.Hostname, p.hostnameFormat)

	switch p.hostnameFormat {
	case "simple":
		hostname := device.Name
		if hostname == "" {
			hostname = device.Hostname
		}

		p.logger.With("action", "domain.match").Trace("processing: '%s'", hostname)

		if idx := strings.Index(hostname, ".tail"); idx != -1 {
			hostname = hostname[:idx]
			p.logger.With("action", "domain.match").Trace("'.tail' suffix removed: '%s'", hostname)
		}

		result := sanitizeHostname(hostname)
		p.logger.With("action", "domain.match").Trace("hostname for device %s: '%s'", device.ID, result)
		return result

	case "tailscale":
		hostname := device.Name
		if hostname == "" {
			hostname = device.Hostname
		}
		if hostname == "" {
			return ""
		}

		if idx := strings.Index(hostname, ".tail"); idx != -1 {
			hostname = hostname[:idx]
		}

		hostname = strings.ReplaceAll(hostname, ".", "-")
		hostname = strings.ReplaceAll(hostname, "_", "-")

		result := sanitizeHostname(hostname)
		p.logger.With("action", "domain.match").Trace("hostname for device %s: '%s'", device.ID, result)
		return result

	case "full":
		hostname := device.Hostname
		if hostname == "" {
			hostname = device.Name
		}
		result := sanitizeHostname(hostname)
		p.logger.With("action", "domain.match").Trace("hostname for device %s: '%s'", device.ID, result)
		return result

	default:
		hostname := device.Name
		if hostname == "" {
			hostname = device.Hostname
		}

		if idx := strings.Index(hostname, ".tail"); idx != -1 {
			hostname = hostname[:idx]
		}

		result := sanitizeHostname(hostname)
		p.logger.With("action", "domain.match").Trace("hostname for device %s: '%s'", device.ID, result)
		return result
	}
}

func sanitizeHostname(hostname string) string {
	hostname = strings.ToLower(hostname)
	hostname = strings.ReplaceAll(hostname, "_", "-")
	hostname = strings.ReplaceAll(hostname, " ", "-")

	result := ""
	for _, r := range hostname {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result += string(r)
		}
	}

	result = strings.Trim(result, "-")

	return result
}

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

func exchangeAuthToken(authToken, authID, logPrefix string) (string, error) {
	log.NewScopedLogger(logPrefix, "").With("action", "auth.accept").Debug("auth token for access token")
	log.NewScopedLogger(logPrefix, "").With("action", "auth.accept").Debug("client ID: %s", authID)
	log.NewScopedLogger(logPrefix, "").With("action", "auth.accept").Debug("client secret length: %d", len(authToken))

	url := "https://api.tailscale.com/api/v2/oauth/token"

	formData := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials",
		neturl.QueryEscape(authID), neturl.QueryEscape(authToken))
	log.NewScopedLogger(logPrefix, "").With("action", "auth.accept").Debug("form data: client_id=%s&client_secret=[REDACTED]&grant_type=client_credentials", authID)

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

	log.NewScopedLogger(logPrefix, "").With("action", "auth.accept").Debug("exchanged auth token for access token")
	return tokenResponse.AccessToken, nil
}

func (p *TailscaleProvider) pollLoop() {
	if p.processExisting {
		p.logger.With("action", "sync.start").Trace("existing Tailscale devices on startup (process_existing=true)")
		p.processDevices()
	} else {
		p.logger.With("action", "sync.start").Trace("poll on startup (process_existing=false), inventory only")
		devices, err := p.fetchTailscaleDevices()
		if err == nil {
			current := make(map[string]string) // hostname:recordType -> target
			for _, device := range devices {
				hostname := p.formatHostname(device)
				if hostname == "" || len(device.Addresses) == 0 {
					continue
				}
				for _, ip := range device.Addresses {
					cleanIP := ip
					if strings.Contains(ip, "/") {
						cleanIP = strings.Split(ip, "/")[0]
					}
					recordType := "A"
					if strings.Contains(cleanIP, ":") {
						recordType = "AAAA"
					}
					key := hostname + ":" + recordType
					current[key] = cleanIP
				}
			}
			p.lastKnownRecords = current
		}
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for p.running {
		<-ticker.C
		p.processDevices()
	}
}

func (p *TailscaleProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

func (p *TailscaleProvider) getParentDomainForFQDN(fqdn string) string {
	var bestMatch string
	for _, cfg := range p.domainConfigs {
		if strings.HasSuffix(fqdn, cfg.Name) {
			if len(cfg.Name) > len(bestMatch) {
				bestMatch = cfg.Name
			}
		}
	}
	return bestMatch
}

func (p *TailscaleProvider) targetDomains() []string {
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

func (p *TailscaleProvider) processDevices() {
	p.logger.With("action", "sync.start").Trace("device processing cycle")
	devices, err := p.fetchTailscaleDevices()
	if err != nil {
		p.logger.With("action", "sync.fail").Error("failed to fetch devices: %v", err)
		return
	}

	p.logger.With("action", "sync.start").Trace("building current records map")

	batchProcessor := domain.NewBatchProcessor(p.logPrefix, p.outputWriter, p.outputSyncer)
	current := make(map[string]string) // hostname:recordType -> target

	p.logger.With("action", "sync.start").Trace("%d devices from Tailscale", len(devices))
	processedCount := 0
	filteredCount := 0

	for i, device := range devices {
		p.logger.With("action", "provider.event").Trace("device %d/%d: %s (%s)", i+1, len(devices), device.Name, device.ID)

		if !EvaluateTailscaleFilters(p.filterConfig, device) {
			filteredCount++
			p.logger.With("action", "input.filter").Trace("%s filtered out", device.Name)
			continue
		}

		hostname := p.formatHostname(device)
		if hostname == "" {
			p.logger.With("action", "input.filter", "device", device.ID).Warn("no name or hostname available")
			continue
		}

		if len(device.Addresses) == 0 {
			p.logger.With("action", "input.filter").Debug("%s (no IP addresses)", hostname)
			continue
		}

		p.logger.With("action", "provider.event").Trace("%s has %d IP addresses", hostname, len(device.Addresses))
		processedCount++

		for addrIdx, ip := range device.Addresses {
			p.logger.With("action", "provider.event").Trace("ip %d/%d: %s for device %s", addrIdx+1, len(device.Addresses), ip, hostname)

			cleanIP := ip
			if strings.Contains(ip, "/") {
				cleanIP = strings.Split(ip, "/")[0]
				p.logger.With("action", "provider.event").Trace("ip %s -> %s", ip, cleanIP)
			}

			recordType := "A"
			if strings.Contains(cleanIP, ":") {
				recordType = "AAAA"
				p.logger.With("action", "input.pass").Trace("ipv6 address: %s", cleanIP)
			}

			key := hostname + ":" + recordType
			current[key] = cleanIP

			lastTarget, known := p.lastKnownRecords[key]
			changed := !known || lastTarget != cleanIP
			if changed {
				if !known {
					p.logMemberAdded(hostname + "." + p.domain)
				} else {
					p.logMemberChanged(hostname+"."+p.domain, lastTarget, cleanIP)
				}
			}

			for _, targetDomain := range p.targetDomains() {
				fqdn := hostname + "." + targetDomain
				p.logger.With("action", "record.sync").Trace("record %s (%s) -> %s", fqdn, recordType, cleanIP)

				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				realDomain := p.getParentDomainForFQDN(fqdnNoDot)
				p.logger.With("action", "domain.route").Trace("real domain name '%s' for DNS provider", realDomain)

				if changed {
					state := domain.RouterState{
						SourceType:           "tailscale",
						Name:                 p.profileName,
						Service:              cleanIP,
						RecordType:           recordType,
						ForceServiceAsTarget: true, // VPN providers always use Service IP as target
					}

					p.logger.With("action", "record.create").Trace("processRecord(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdn, state)
					err := batchProcessor.ProcessRecord(realDomain, fqdn, state)
					if err != nil {
						p.logger.With("action", "record.reject", "device", fqdn).Error("ensure DNS: %v", err)
					}
				} else {
					p.logger.With("action", "record.skip").Trace("unchanged: %s (%s) -> %s", fqdn, recordType, cleanIP)
				}
				heraldstate.Touch(realDomain, hostname, recordType, cleanIP, p.profileName, "")
			}
		}
	}

	if filteredCount > 0 {
		p.logger.With("action", "sync.done").Verbose("%d devices filtered out, %d processed", filteredCount, processedCount)
	} else {
		p.logger.With("action", "sync.done").Verbose("%d devices (no filtering applied)", processedCount)
	}

	p.logger.With("action", "record.delete").Trace("removed records (recordRemoveOnStop=%t)", p.recordRemoveOnStop)
	if p.recordRemoveOnStop {
		removedCount := 0
		for key, oldTarget := range p.lastKnownRecords {
			if _, exists := current[key]; !exists {
				removedCount++
				parts := strings.Split(key, ":")
				if len(parts) != 2 {
					continue
				}
				hostname, recordType := parts[0], parts[1]
				for _, targetDomain := range p.targetDomains() {
					fqdn := hostname + "." + targetDomain
					fqdnNoDot := strings.TrimSuffix(fqdn, ".")
					realDomain := p.getParentDomainForFQDN(fqdnNoDot)
					p.logger.With("action", "domain.route").Trace("real domain name '%s' for DNS provider (removal)", realDomain)

					p.logMemberRemoved(fqdn) // This log is fine
					state := domain.RouterState{
						SourceType:           "tailscale",
						Name:                 p.profileName,
						Service:              oldTarget,
						RecordType:           recordType,
						ForceServiceAsTarget: true, // VPN providers always use Service IP as target
					}

					p.logger.With("action", "record.delete").Trace("processRecordRemoval(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdn, state)
					err := batchProcessor.ProcessRecordRemoval(realDomain, fqdn, state)
					if err != nil {
						p.logger.With("action", "record.reject", "device", fqdn).Error("remove DNS: %v", err)
					} else {
						heraldstate.Remove(realDomain, hostname, recordType)
					}
				}
			}
		}
		if removedCount > 0 {
			p.logger.With("action", "sync.done").Verbose("%d record removals", removedCount)
		}
	} else {
		p.logger.With("action", "record.skip").Trace("removal disabled (recordRemoveOnStop=false)")
	}

	p.lastKnownRecords = current
	p.logger.With("action", "state.save").Trace("lastKnownRecords cache with %d entries", len(current))

	batchProcessor.FinalizeBatch()
}

func init() {
}

func (tp *TailscaleProvider) GetName() string {
	return "tailscale"
}
