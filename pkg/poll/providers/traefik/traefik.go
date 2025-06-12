// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package traefik

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/dns"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"
	"dns-companion/pkg/poll/providers/traefik/filter"
	"dns-companion/pkg/utils"

	"context"
	"encoding/json"
	"fmt"
	"regexp"

	//"strconv"
	"strings"
	"time"
)

// Enhanced regex to support Host(), HostSNI(), HostRegexp(), and multiple hosts
var (
	hostRuleRegex       = regexp.MustCompile(`Host\(([^)]*)\)`)
	hostSniRuleRegex    = regexp.MustCompile(`HostSNI\(([^)]*)\)`)
	hostRegexpRuleRegex = regexp.MustCompile(`HostRegexp\(([^)]*)\)`)
)

// TraefikProvider is a poll provider that monitors Traefik routers
type TraefikProvider struct {
	apiURL       string
	pollInterval time.Duration
	running      bool
	ctx          context.Context
	cancel       context.CancelFunc
	callback     func(hostnames []string) error
	options      map[string]string
	routerCache  map[string]domain.RouterState
	ticker       *time.Ticker
	authUser     string
	authPass     string
	profileName  string                // Store profile name for logs
	logPrefix    string                // Store log prefix for consistent logging
	tlsConfig    *pollCommon.TLSConfig // Store TLS configuration

	// Filters
	filterConfig pollCommon.FilterConfig

	initialPollDone bool // Track if initial poll is complete

	opts pollCommon.PollProviderOptions // Add parsed options struct

	logger *log.ScopedLogger // provider-specific logger
}

// NewProviderFromStructured creates a new Traefik poll provider from structured options
func NewProviderFromStructured(options map[string]interface{}) (poll.Provider, error) {
	// Parse the filter configuration BEFORE converting to strings to preserve structured data
	filterConfig, err := pollCommon.NewFilterFromStructuredOptions(options)
	if err != nil {
		log.Info("Error creating filter configuration: %v, using default", err)
		filterConfig = pollCommon.DefaultFilterConfig()
	}

	// Convert interface{} options to string options for compatibility with existing functions
	stringOptions := make(map[string]string)
	for key, value := range options {
		if strValue, ok := value.(string); ok {
			stringOptions[key] = strValue
		}
	}

	parsed := pollCommon.ParsePollProviderOptions(stringOptions, pollCommon.PollProviderOptions{
		Interval:           30 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "traefik",
	})
	profileName := pollCommon.GetOptionOrEnv(stringOptions, "name", "TRAEFIK_PROFILE_NAME", parsed.Name)
	logPrefix := pollCommon.BuildLogPrefix("traefik", profileName)

	// Trace all options keys at the start to help troubleshoot
	log.Trace("%s Provider options received: %+v", logPrefix, options)

	log.Trace("%s Resolved profile name: %s", logPrefix, profileName)

	// Get api URL from options
	apiURL := pollCommon.GetOptionOrEnv(stringOptions, "api_url", "TRAEFIK_API_URL", "http://localhost:8080/api/http/routers")
	log.Debug("%s Using configured URL: %s", logPrefix, apiURL)

	// Get basic auth credentials if provided
	authUser := pollCommon.GetOptionOrEnv(stringOptions, "api_auth_user", "TRAEFIK_API_AUTH_USER", "")
	authPass := pollCommon.GetOptionOrEnv(stringOptions, "api_auth_pass", "TRAEFIK_API_AUTH_PASS", "")

	// Log whether auth credentials were found
	if authUser != "" {
		log.Trace("%s Basic auth user configured: %s", logPrefix, authUser)
		if authPass != "" {
			log.Trace("%s Basic auth password configured: %s", logPrefix, utils.MaskSensitiveValue(authPass))
		} else {
			log.Warn("%s Basic auth user provided without password", logPrefix)
		}
	} else {
		log.Debug("%s No basic auth user found in options or environment", logPrefix)
	}

	ctx, cancel := context.WithCancel(context.Background())
	log.Trace("%s Created context with cancel function", logPrefix)

	// Parse TLS configuration
	tlsConfig := pollCommon.ParseTLSConfigFromOptions(stringOptions)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("%s invalid TLS configuration: %w", logPrefix, err)
	}

	// Log TLS configuration
	if !tlsConfig.Verify {
		log.Debug("%s TLS certificate verification disabled", logPrefix)
	}
	if tlsConfig.CA != "" {
		log.Debug("%s Using custom CA certificate: %s", logPrefix, tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		log.Debug("%s Using client certificate authentication", logPrefix)
	}

	// Check if we have active filters (not just "none" filter)
	hasActiveFilters := len(filterConfig.Filters) > 0 && !(len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == pollCommon.FilterTypeNone)

	if hasActiveFilters {
		// Log active filter details for user awareness in verbose mode
		var filterDescription strings.Builder
		for i, filter := range filterConfig.Filters {
			if filter.Type == pollCommon.FilterTypeNone || filter.Type == "" {
				continue
			}

			if i > 0 {
				filterDescription.WriteString(fmt.Sprintf(" %s ", filter.Operation))
			}

			if filter.Negate {
				filterDescription.WriteString("NOT ")
			}

			switch filter.Type {
			case pollCommon.FilterTypeName:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("names(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			case pollCommon.FilterTypeService:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("services(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			case pollCommon.FilterTypeProvider:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("providers(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			case pollCommon.FilterTypeRule:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("rules(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			}
		}

		if filterDescription.Len() > 0 {
			log.Verbose("%s Active filter: %s", logPrefix, filterDescription.String())
		}

		log.Debug("%s Filter configuration: %d active filters", logPrefix, len(filterConfig.Filters))
		for i, f := range filterConfig.Filters {
			log.Debug("%s   Filter %d: Type=%s, Value=%s, Operation=%s, Negate=%v, Conditions=%d",
				logPrefix, i, f.Type, f.Value, f.Operation, f.Negate, len(f.Conditions))
			for j, condition := range f.Conditions {
				log.Debug("%s     Condition %d: Key='%s', Value='%s', Logic='%s'",
					logPrefix, j, condition.Key, condition.Value, condition.Logic)
			}
		}
	} else {
		log.Verbose("%s Active filter: none (all routers will be processed)", logPrefix)
		log.Debug("%s No active filters configured, processing all routers", logPrefix)
	}

	logLevel := stringOptions["log_level"] // Get provider-specific log level

	// Create scoped logger
	scopedLogger := pollCommon.CreateScopedLogger("traefik", profileName, stringOptions)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	provider := &TraefikProvider{
		apiURL:          apiURL,
		pollInterval:    parsed.Interval,
		running:         false,
		ctx:             ctx,
		cancel:          cancel,
		options:         stringOptions,
		routerCache:     make(map[string]domain.RouterState),
		authUser:        authUser,
		authPass:        authPass,
		profileName:     profileName,
		logPrefix:       logPrefix,
		tlsConfig:       &tlsConfig,
		filterConfig:    filterConfig,
		initialPollDone: false,
		opts:            parsed,
		logger:          scopedLogger,
	}

	// Log the actual filterConfig.Filters slice for diagnosis
	log.Debug("%s Filter Configuration: %+v", logPrefix, filterConfig.Filters)
	// Only show a count if there are real, user-configured filters
	filterSummary := "none"
	realFilterCount := 0
	for _, f := range filterConfig.Filters {
		if (f.Type != "none" && f.Type != "") || f.Value != "" || len(f.Conditions) > 0 {
			realFilterCount++
		}
	}
	if realFilterCount > 0 {
		filterSummary = fmt.Sprintf("%d", realFilterCount)
	}

	log.Info("%s Successfully created new Traefik provider with filters=%s", logPrefix, filterSummary)
	log.Debug("%s Provider details: URL=%s, interval=%s",
		logPrefix, provider.apiURL, provider.pollInterval)

	return provider, nil
}

// NewProvider creates a new Traefik poll provider
func NewProvider(options map[string]string) (poll.Provider, error) {
	// Convert string options to interface{} for structured parsing
	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	// Parse the filter configuration BEFORE other processing to preserve structured data
	filterConfig, err := pollCommon.NewFilterFromStructuredOptions(structuredOptions)
	if err != nil {
		log.Debug("Error creating filter configuration: %v, using default", err)
		filterConfig = pollCommon.DefaultFilterConfig()
	}

	parsed := pollCommon.ParsePollProviderOptions(options, pollCommon.PollProviderOptions{
		Interval:           30 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "traefik",
	})
	profileName := pollCommon.GetOptionOrEnv(options, "name", "TRAEFIK_PROFILE_NAME", parsed.Name)
	logPrefix := pollCommon.BuildLogPrefix("traefik", profileName)

	// Get api URL from options
	apiURL := pollCommon.GetOptionOrEnv(options, "api_url", "TRAEFIK_API_URL", "http://localhost:8080/api/http/routers")
	log.Debug("%s Using configured URL: %s", logPrefix, apiURL)

	// Get basic auth credentials if provided
	authUser := pollCommon.GetOptionOrEnv(options, "api_auth_user", "TRAEFIK_API_AUTH_USER", "")
	authPass := pollCommon.GetOptionOrEnv(options, "api_auth_pass", "TRAEFIK_API_AUTH_PASS", "")

	// Log whether auth credentials were found
	if authUser != "" {
		log.Debug("%s Using basic auth user: %s", logPrefix, authUser)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Parse TLS configuration
	tlsConfig := pollCommon.ParseTLSConfigFromOptions(options)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("%s invalid TLS configuration: %w", logPrefix, err)
	}

	// Log TLS configuration
	if !tlsConfig.Verify {
		log.Debug("%s TLS certificate verification disabled", logPrefix)
	}
	if tlsConfig.CA != "" {
		log.Debug("%s Using custom CA certificate: %s", logPrefix, tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		log.Debug("%s Using client certificate authentication", logPrefix)
	}

	// Check if we have active filters (not just "none" filter)
	hasActiveFilters := len(filterConfig.Filters) > 0 && !(len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == pollCommon.FilterTypeNone)

	if hasActiveFilters {
		// Log active filter details for user awareness in verbose mode
		var filterDescription strings.Builder
		for i, filter := range filterConfig.Filters {
			if filter.Type == pollCommon.FilterTypeNone || filter.Type == "" {
				continue
			}

			if i > 0 {
				filterDescription.WriteString(fmt.Sprintf(" %s ", filter.Operation))
			}

			if filter.Negate {
				filterDescription.WriteString("NOT ")
			}

			switch filter.Type {
			case pollCommon.FilterTypeName:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("names(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			case pollCommon.FilterTypeService:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("services(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			case pollCommon.FilterTypeProvider:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("providers(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			case pollCommon.FilterTypeRule:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("rules(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			}
		}

		if filterDescription.Len() > 0 {
			log.Verbose("%s Active filter: %s", logPrefix, filterDescription.String())
		}

		log.Debug("%s Filter configuration: %d active filters", logPrefix, len(filterConfig.Filters))
		for i, f := range filterConfig.Filters {
			log.Debug("%s   Filter %d: Type=%s, Value=%s, Operation=%s, Negate=%v",
				logPrefix, i, f.Type, f.Value, f.Operation, f.Negate)
		}
	} else {
		log.Verbose("%s Active filter: none (all routers will be processed)", logPrefix)
		log.Debug("%s No active filters configured, processing all routers", logPrefix)
	}

	logLevel := options["log_level"] // Get provider-specific log level

	// Create scoped logger
	scopedLogger := pollCommon.CreateScopedLogger("traefik", profileName, options)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	provider := &TraefikProvider{
		apiURL:          apiURL,
		pollInterval:    parsed.Interval,
		running:         false,
		ctx:             ctx,
		cancel:          cancel,
		options:         options,
		routerCache:     make(map[string]domain.RouterState),
		authUser:        authUser,
		authPass:        authPass,
		profileName:     profileName,
		logPrefix:       logPrefix,
		tlsConfig:       &tlsConfig,
		filterConfig:    filterConfig,
		initialPollDone: false,
		opts:            parsed,
		logger:          scopedLogger,
	}

	log.Info("%s Successfully created new Traefik provider", logPrefix)
	log.Debug("%s Provider details: URL=%s, interval=%s",
		logPrefix, provider.apiURL, provider.pollInterval)

	return provider, nil
}

// Register the Traefik provider
func init() {
	logPrefix := pollCommon.BuildLogPrefix("traefik", "default")
	log.Debug("%s Registering Traefik provider", logPrefix)
	poll.RegisterProvider("traefik", NewProvider)
	log.Debug("%s Successfully registered Traefik provider", logPrefix)
}

// StartPolling starts polling Traefik for routers
func (t *TraefikProvider) StartPolling() error {
	log.Info("%s Starting polling for routers (interval: %s)", t.logPrefix, t.pollInterval)

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
	log.Verbose("%s Performing initial processing of Traefik routers", t.logPrefix)
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
	t.logger.Debug("Processing Traefik routers from API")

	// Fetch data from Traefik API using pollCommon.FetchRemoteResource
	body, err := t.fetchTraefikAPI(t.apiURL, t.authUser, t.authPass, t.logPrefix)
	if err != nil {
		log.Error("%s Failed to fetch data from Traefik API: %v", t.logPrefix, err)
		return fmt.Errorf("%s failed to fetch data: %w", t.logPrefix, err)
	}

	// Parse JSON response
	t.logger.Debug("Parsing JSON response")

	// Try to parse as an array first (which is what the Traefik API returns)
	var routersArray []map[string]interface{}
	if err := json.Unmarshal(body, &routersArray); err != nil {
		// If parsing as array fails, try as a map (older API versions or different formats)
		var routersMap map[string]interface{}
		if err := json.Unmarshal(body, &routersMap); err != nil {
			log.Error("%s Failed to parse JSON response: %v", t.logPrefix, err)
			return fmt.Errorf("%s failed to parse JSON: %w", t.logPrefix, err)
		}
		t.logger.Debug("Found %d routers in API response (map format)", len(routersMap))

		// Process the map format (convert to our array format for processing)
		routersArray = make([]map[string]interface{}, 0, len(routersMap))
		for name, router := range routersMap {
			if r, ok := router.(map[string]interface{}); ok {
				r["name"] = name
				routersArray = append(routersArray, r)
			}
		}
	}

	t.logger.Debug("Found %d routers in API response", len(routersArray))

	filteredRouters := make([]map[string]interface{}, 0, len(routersArray))
	initialLog := !t.initialPollDone
	for _, router := range routersArray {
		shouldProcess, _ := filter.ShouldProcessRouter(t.filterConfig, router)
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
				t.logger.Debug("Router PASSED filter: %s | Hostnames: %v", routerName, hosts)
			}
		} else if initialLog {
			t.logger.Debug("Router FILTERED OUT: %s", routerName)
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
			SourceType:  "router",
			RecordType:  "CNAME", // Traefik routers typically create CNAME records
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
			log.Info("%s No routers to process", t.logPrefix)
		} else {
			// Build a slice of 'routerName (hostname)' strings
			var routerHostPairs []string
			for _, h := range currentHostnames {
				state := hostnameToRouter[h]
				routerLabel := state.Name
				if routerLabel == "" {
					routerLabel = "unknown-router"
				}
				pair := fmt.Sprintf("%s (%s)", routerLabel, h)
				routerHostPairs = append(routerHostPairs, pair)
			}
			log.Info("%s Initial routers to process [%s]", t.logPrefix, strings.Join(routerHostPairs, ", "))
			// Initial run: process all routers and hostnames as adds
			for _, h := range currentHostnames {
				state := hostnameToRouter[h]
				log.Trace("%s Preparing to add DNS for hostname: %s | RouterState: %+v", t.logPrefix, h, state)
				t.processRouterAdd(state)
				t.routerCache[h] = state
			}
		}
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
			log.Info("%s Routers detected: %v", t.logPrefix, added)
			for _, h := range added {
				t.processRouterAdd(hostnameToRouter[h])
			}
		}
		if len(removed) > 0 {
			// Build a slice of 'routerName (hostname)' strings for removed routers
			var removedRouterHostPairs []string
			for _, h := range removed {
				if prevState, ok := t.routerCache[h]; ok {
					routerLabel := prevState.Name
					if routerLabel == "" {
						routerLabel = "unknown-router"
					}
					pair := fmt.Sprintf("%s (%s)", routerLabel, h)
					removedRouterHostPairs = append(removedRouterHostPairs, pair)
				} else {
					pair := fmt.Sprintf("unknown-router (%s)", h)
					removedRouterHostPairs = append(removedRouterHostPairs, pair)
				}
			}
			log.Info("%s Routers removed [%s]", t.logPrefix, strings.Join(removedRouterHostPairs, ", "))
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

// fetchTraefikAPI fetches data from the Traefik API using pollCommon.FetchRemoteResource
func (p *TraefikProvider) fetchTraefikAPI(url, user, pass, logPrefix string) ([]byte, error) {
	// Parse TLS configuration using pollCommon utilities
	tlsConfig := pollCommon.ParseTLSConfigFromOptions(p.options)

	// Log TLS configuration details
	if !tlsConfig.Verify {
		log.Debug("%s TLS certificate verification disabled", logPrefix)
	}
	if tlsConfig.CA != "" {
		log.Debug("%s Using custom CA certificate: %s", logPrefix, tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		log.Debug("%s Using client certificate authentication", logPrefix)
	}

	return pollCommon.FetchRemoteResourceWithTLSConfig(url, user, pass, nil, &tlsConfig, logPrefix)
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

	// On first run, if opts.ProcessExisting is true, just populate cache
	if len(p.routerCache) == 0 && p.opts.ProcessExisting {
		for k, v := range currentMap {
			p.routerCache[k] = v
		}
		log.Info("%s Initial poll: process_existing=true, populating cache only, not processing routers", p.logPrefix)
		return nil
	}

	// Detect new and updated routers
	for name, state := range currentMap {
		prev, exists := p.routerCache[name]
		if !exists {
			// New router
			log.Info("%s New router detected: %s", p.logPrefix, name)
			p.processRouterAdd(state)
		} else if !routerStatesEqual(prev, state) {
			// Updated router
			log.Info("%s Router updated: %s", p.logPrefix, name)
			p.processRouterUpdate(state)
		}
	}

	// Detect removed routers
	for name := range p.routerCache {
		if _, exists := currentMap[name]; !exists {
			log.Info("%s Router removed: %s", p.logPrefix, name)
			if p.opts.RecordRemoveOnStop {
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
	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(t.logPrefix)

	hostnames := pollCommon.ExtractHostsFromRule(state.Rule)
	for _, hostname := range hostnames {
		fqdnNoDot := strings.TrimSuffix(hostname, ".")
		domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, t.logPrefix)
		log.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s'", t.logPrefix, domainKey, subdomain, fqdnNoDot)

		if domainKey == "" {
			log.Error("%s No domain config found for '%s' (tried to match domain from FQDN)", t.logPrefix, fqdnNoDot)
			continue
		}

		domainCfg, ok := config.GlobalConfig.Domains[domainKey]
		if !ok {
			log.Error("%s Domain '%s' not found in config for fqdn='%s'", t.logPrefix, domainKey, fqdnNoDot)
			continue
		}

		realDomain := domainCfg.Name
		log.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s')", t.logPrefix, realDomain, domainKey)

		log.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", t.logPrefix, realDomain, fqdnNoDot, state)
		err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
		if err != nil {
			log.Error("%s Failed to ensure DNS for '%s': %v", t.logPrefix, fqdnNoDot, err)
		}
	}

	// Finalize the batch - this will sync output files only if there were changes
	batchProcessor.FinalizeBatch()
}

func (t *TraefikProvider) processRouterUpdate(state domain.RouterState) {
	// For updates, use the same logic as add
	t.processRouterAdd(state)
}

func (t *TraefikProvider) processRouterRemove(state domain.RouterState) {
	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(t.logPrefix)

	hostnames := pollCommon.ExtractHostsFromRule(state.Rule)
	for _, hostname := range hostnames {
		fqdnNoDot := strings.TrimSuffix(hostname, ".")
		domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, t.logPrefix)
		log.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s' (removal)", t.logPrefix, domainKey, subdomain, fqdnNoDot)

		if domainKey == "" {
			log.Error("%s No domain config found for '%s' (removal, tried to match domain from FQDN)", t.logPrefix, fqdnNoDot)
			continue
		}

		domainCfg, ok := config.GlobalConfig.Domains[domainKey]
		if !ok {
			log.Error("%s Domain '%s' not found in config for fqdn='%s' (removal)", t.logPrefix, domainKey, fqdnNoDot)
			continue
		}

		realDomain := domainCfg.Name
		log.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s') (removal)", t.logPrefix, realDomain, domainKey)

		log.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", t.logPrefix, realDomain, fqdnNoDot, state)
		err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
		if err != nil {
			log.Error("%s Failed to remove DNS for '%s': %v", t.logPrefix, fqdnNoDot, err)
		}
	}

	// Finalize the batch - this will sync output files only if there were changes
	batchProcessor.FinalizeBatch()
}

// extractHostsFromRule extracts hostnames from Traefik router rules
func extractHostsFromRule(rule string) []string {
	logPrefix := pollCommon.BuildLogPrefix("traefik", "default") // or pass t.logPrefix if available
	log.Trace("%s Extracting hosts from rule: '%s'", logPrefix, rule)
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
