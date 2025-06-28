// SPDX-FileCopyrightText: © 2024 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package caddy

import (
	"herald/pkg/domain"
	"herald/pkg/input/common"
	"herald/pkg/log"

	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Provider interface {
	StartPolling() error
	StopPolling() error
	GetName() string
}

type CaddyProvider struct {
	apiURL       string
	interval     time.Duration
	opts         common.PollProviderOptions
	running      bool
	lastHosts    map[string]domain.RouterState
	logPrefix    string
	options      map[string]string
	logger       *log.ScopedLogger
	filterConfig common.FilterConfig
	name         string              // Profile name
	outputWriter domain.OutputWriter // Injected dependency
	outputSyncer domain.OutputSyncer // Injected dependency
}

func NewProvider(profileName string, config map[string]interface{}, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	// Convert interface{} config back to string map for compatibility
	options := make(map[string]string)
	for k, v := range config {
		options[k] = fmt.Sprintf("%v", v)
	}

	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           60 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               profileName,
	})
	apiURL := common.ReadFileValue(options["api_url"])
	if apiURL == "" {
		return nil, fmt.Errorf("%s api_url option (URL) is required", parsed.Name)
	}
	logPrefix := common.BuildLogPrefix("caddy", parsed.Name)

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

	// Check if we have active filters
	hasActiveFilters := len(filterConfig.Filters) > 0 && !(len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == common.FilterTypeNone)

	if hasActiveFilters {
		log.Debug("%s Filter configuration: %d active filters", logPrefix, len(filterConfig.Filters))
		for i, f := range filterConfig.Filters {
			log.Debug("%s   Filter %d: Type=%s, Value=%s, Operation=%s, Negate=%v",
				logPrefix, i, f.Type, f.Value, f.Operation, f.Negate)
		}
	} else {
		log.Debug("%s No active filters configured, processing all routes", logPrefix)
	}

	// Create scoped logger using common helper
	scopedLogger := common.CreateScopedLogger("caddy", parsed.Name, options)

	return &CaddyProvider{
		apiURL:       apiURL,
		interval:     parsed.Interval,
		opts:         parsed,
		logPrefix:    logPrefix,
		options:      options,
		logger:       scopedLogger,
		filterConfig: filterConfig,
		outputWriter: outputWriter,
		outputSyncer: outputSyncer,
	}, nil
}

func (p *CaddyProvider) StartPolling() error {
	if p.running {
		return nil
	}
	if p.lastHosts == nil {
		p.lastHosts = make(map[string]domain.RouterState)
	}
	p.running = true
	go p.pollLoop()
	return nil
}

func (p *CaddyProvider) StopPolling() error {
	p.running = false
	return nil
}

func (p *CaddyProvider) IsRunning() bool {
	return p.running
}

func (p *CaddyProvider) pollLoop() {
	// Always perform an initial poll immediately on startup
	if p.opts.ProcessExisting {
		p.logger.Trace("Processing existing Caddy config on startup (process_existing=true)")
		p.processCaddy()
	} else {
		p.logger.Trace("Initial poll on startup (process_existing=false), inventory only, no processing")
		// Inventory the current state without processing/updates
		hosts, err := p.readCaddy()
		if err == nil {
			current := make(map[string]domain.RouterState)
			for _, h := range hosts {
				fqdn := h.FQDN
				key := fqdn + ":A"
				state := domain.RouterState{
					Name:       h.FQDN,
					Service:    h.Service,
					RecordType: "A",
				}
				current[key] = state
			}
			p.lastHosts = current
		}
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for p.running {
		<-ticker.C
		p.processCaddy()
	}
}

func (p *CaddyProvider) processCaddy() {
	isInitialLoad := len(p.lastHosts) == 0
	hosts, err := p.readCaddy()
	if err != nil {
		p.logger.Error("Failed to read Caddy config: %v", err)
		return
	}
	p.logger.Debug("Processing %d hosts from Caddy", len(hosts))

	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(p.logPrefix, p.outputWriter, p.outputSyncer)
	current := make(map[string]domain.RouterState)

	for _, h := range hosts {
		fqdn := h.FQDN
		key := fqdn + ":A"
		state := domain.RouterState{
			Name:       h.FQDN,
			Service:    h.Service,
			RecordType: "A",
		}
		current[key] = state
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		if _, ok := p.lastHosts[key]; !ok {
			if isInitialLoad {
				p.logger.Info("Initial record detected: %s (A)", fqdnNoDot)
			} else {
				p.logger.Info("New record detected: %s (A)", fqdnNoDot)
			}
			realDomain, _ := common.ExtractDomainAndSubdomain(fqdnNoDot) // This is just for logging, actual domain resolution is in domain package
			// The domain.EnsureDNSForRouterStateWithProvider will handle domain config lookup and input provider validation.
			// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
			p.logger.Trace("Using real domain name '%s' for DNS provider", realDomain)
			state := domain.RouterState{
				SourceType: "caddy",
				Name:       p.opts.Name, // Use the actual provider name
				Service:    h.Service,
				RecordType: "A",
			}
			p.logger.Trace("Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(fqdnNoDot, fqdnNoDot, state) // Pass fqdnNoDot as domain, it will be resolved later
			if err != nil {
				p.logger.Error("Failed to ensure DNS for '%s': %v", fqdnNoDot, err)
			}
		}
	}
	if p.opts.RecordRemoveOnStop {
		for key, old := range p.lastHosts {
			if _, ok := current[key]; !ok {
				fqdn := old.Name
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				p.logger.Info("Record removed: %s (A)", fqdnNoDot)           // This log is fine
				realDomain, _ := common.ExtractDomainAndSubdomain(fqdnNoDot) // This is just for logging, actual domain resolution is in domain package
				// The domain.EnsureDNSRemoveForRouterStateWithProvider will handle domain config lookup and input provider validation.
				// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
				p.logger.Trace("Using real domain name '%s' for DNS provider", realDomain)
				state := domain.RouterState{
					SourceType: "caddy",
					Name:       p.opts.Name, // Use the actual provider name
					Service:    old.Service,
					RecordType: "A",
				}
				p.logger.Trace("Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
				err := batchProcessor.ProcessRecordRemoval(fqdnNoDot, fqdnNoDot, state) // Pass fqdnNoDot as domain, it will be resolved later
				if err != nil {
					p.logger.Error("Failed to remove DNS for '%s': %v", fqdnNoDot, err)
				}
			}
		}
	}
	p.lastHosts = current

	batchProcessor.FinalizeBatch()
}

type caddyConfig struct {
	Apps struct {
		HTTP struct {
			Servers map[string]caddyServer `json:"servers"`
		} `json:"http"`
	} `json:"apps"`
}

type caddyServer struct {
	Routes []caddyRoute `json:"routes"`
}

type caddyRoute struct {
	Match    []caddyMatch  `json:"match"`
	Handle   []caddyHandle `json:"handle"`
	Terminal bool          `json:"terminal"`
}

type caddyMatch struct {
	Host []string `json:"host"`
}

type caddyHandle struct {
	Handler   string          `json:"handler"`
	Routes    []caddyRoute    `json:"routes,omitempty"`
	Root      string          `json:"root,omitempty"`
	Body      string          `json:"body,omitempty"`
	Status    int             `json:"status_code,omitempty"`
	Upstreams []caddyUpstream `json:"upstreams,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

type caddyHost struct {
	FQDN    string
	Service string
	Route   caddyRoute // Store the full route for filtering
	Server  string     // Server name
}

func (p *CaddyProvider) readCaddy() ([]caddyHost, error) {
	p.logger.Debug("Fetching Caddy config: %s", p.apiURL)
	httpUser := common.ReadFileValue(p.options["api_auth_user"])
	httpPass := common.ReadFileValue(p.options["api_auth_pass"])

	// Parse TLS configuration using common utilities
	tlsConfig := common.ParseTLSConfigFromOptions(p.options)

	// Log TLS configuration details
	if !tlsConfig.Verify {
		p.logger.Debug("TLS certificate verification disabled")
	}
	if tlsConfig.CA != "" {
		p.logger.Debug("Using custom CA certificate: %s", tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		p.logger.Debug("Using client certificate authentication")
	}

	body, err := common.FetchRemoteResourceWithTLSConfig(p.apiURL, httpUser, httpPass, nil, &tlsConfig, p.logPrefix)
	if err != nil {
		p.logger.Error("Failed to fetch data from Caddy API: %v", err)
		return nil, fmt.Errorf("%s failed to fetch data: %w", p.logPrefix, err)
	}

	p.logger.Trace("Caddy API response: %s", string(body))

	var cfg caddyConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		p.logger.Error("Failed to parse JSON response: %v", err)
		return nil, fmt.Errorf("%s failed to parse JSON: %w", p.logPrefix, err)
	}

	var allHosts []caddyHost
	for serverName, server := range cfg.Apps.HTTP.Servers {
		p.logger.Trace("Processing server '%s' with %d routes", serverName, len(server.Routes))
		for routeIdx, route := range server.Routes {
			p.logger.Trace("Processing route %d (terminal=%v, matches=%d, handlers=%d)",
				routeIdx, route.Terminal, len(route.Match), len(route.Handle))

			for _, match := range route.Match {
				for _, host := range match.Host {
					caddyHost := caddyHost{
						FQDN:    host,
						Service: "caddy",
						Route:   route,
						Server:  serverName,
					}

					// Apply filtering
					if p.matchesFilter(caddyHost) {
						p.logger.Trace("Host '%s' matches filter criteria", host)
						allHosts = append(allHosts, caddyHost)
					} else {
						p.logger.Trace("Host '%s' filtered out", host)
					}
				}
			}
		}
	}

	p.logger.Debug("Found %d filtered hosts in Caddy config", len(allHosts))
	return allHosts, nil
}

// matchesFilter checks if a Caddy host/route matches the configured filters
func (p *CaddyProvider) matchesFilter(host caddyHost) bool {
	if len(p.filterConfig.Filters) == 0 {
		return true // No filters, match all
	}

	// If we only have a "none" filter, match all
	if len(p.filterConfig.Filters) == 1 && p.filterConfig.Filters[0].Type == common.FilterTypeNone {
		return true
	}

	// Use unified filtering system
	return p.filterConfig.Evaluate(host, func(filter common.Filter, entry any) bool {
		return evaluateCaddyFilter(filter, entry)
	})
}

// evaluateCaddyFilter evaluates a single filter against a Caddy host using conditions
func evaluateCaddyFilter(filter common.Filter, entry any) bool {
	host, ok := entry.(caddyHost)
	if !ok {
		return false
	}

	switch filter.Type {
	case common.FilterTypeNone:
		return true
	case "host":
		for _, condition := range filter.Conditions {
			if !common.RegexMatch(condition.Value, host.FQDN) {
				return false
			}
		}
		return true
	case "handler":
		for _, condition := range filter.Conditions {
			if !routeHasHandler(host.Route, condition.Value) {
				return false
			}
		}
		return true
	case "upstream":
		for _, condition := range filter.Conditions {
			if !routeHasUpstream(host.Route, condition.Value) {
				return false
			}
		}
		return true
	case "server":
		for _, condition := range filter.Conditions {
			if !common.RegexMatch(condition.Value, host.Server) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

// Helper functions for route inspection
func routeHasHandler(route caddyRoute, handlerType string) bool {
	return inspectHandlers(route.Handle, func(handler caddyHandle) bool {
		return handler.Handler == handlerType
	})
}

func routeHasUpstream(route caddyRoute, upstreamPattern string) bool {
	return inspectHandlers(route.Handle, func(handler caddyHandle) bool {
		for _, upstream := range handler.Upstreams {
			if common.RegexMatch(upstreamPattern, upstream.Dial) {
				return true
			}
		}
		return false
	})
}

// inspectHandlers recursively inspects all handlers in a route (including subroutes)
func inspectHandlers(handlers []caddyHandle, predicate func(caddyHandle) bool) bool {
	for _, handler := range handlers {
		if predicate(handler) {
			return true
		}
		// Recursively check subroute handlers
		if handler.Handler == "subroute" && len(handler.Routes) > 0 {
			for _, subroute := range handler.Routes {
				if inspectHandlers(subroute.Handle, predicate) {
					return true
				}
			}
		}
	}
	return false
}

func (p *CaddyProvider) GetDNSEntries() ([]interface{}, error) {
	return nil, nil
}

// GetName returns the provider name
func (cp *CaddyProvider) GetName() string {
	return "caddy"
}
