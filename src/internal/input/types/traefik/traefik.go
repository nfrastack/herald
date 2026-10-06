// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package traefik

import (
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input/common"
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/util"

	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"strings"
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

var (
	hostRuleRegex       = regexp.MustCompile(`Host\(([^)]*)\)`)
	hostSniRuleRegex    = regexp.MustCompile(`HostSNI\(([^)]*)\)`)
	hostRegexpRuleRegex = regexp.MustCompile(`HostRegexp\(([^)]*)\)`)
)

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
	profileName  string            // Store profile name for logs
	logPrefix    string            // Store log prefix for consistent logging
	tlsConfig    *common.TLSConfig // Store TLS configuration

	filterConfig common.FilterConfig

	initialPollDone bool // Track if initial poll is complete

	opts         common.PollProviderOptions // Add parsed options struct
	outputWriter domain.OutputWriter        // Injected dependency
	outputSyncer domain.OutputSyncer        // Injected dependency

	logger *log.ScopedLogger // provider-specific logger

	domainConfigs map[string]config.DomainConfig // Add domain configs for domain matching
}

func (p *TraefikProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

func (p *TraefikProvider) getParentDomainForFQDN(fqdn string) string {
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

func evaluateTraefikFilter(filter common.Filter, entry any) bool {
	router, ok := entry.(map[string]interface{})
	if !ok {
		return false
	}

	switch filter.Type {
	case common.FilterTypeNone:
		return true
	case common.FilterTypeName:
		for _, condition := range filter.Conditions {
			if name, ok := router["name"].(string); ok {
				if !common.WildcardMatch(condition.Value, name) {
					return false
				}
			}
		}
		return true
	case common.FilterTypeService:
		for _, condition := range filter.Conditions {
			if service, ok := router["service"].(string); ok {
				if !common.WildcardMatch(condition.Value, service) {
					return false
				}
			}
		}
		return true
	case common.FilterTypeProvider:
		for _, condition := range filter.Conditions {
			if provider, ok := router["provider"].(string); ok {
				if !common.WildcardMatch(condition.Value, provider) {
					return false
				}
			}
		}
		return true
	case common.FilterTypeEntrypoint:
		for _, condition := range filter.Conditions {
			if entryPoints, ok := router["entryPoints"].([]interface{}); ok {
				found := false
				for _, ep := range entryPoints {
					if epStr, ok := ep.(string); ok {
						if common.WildcardMatch(condition.Value, epStr) {
							found = true
							break
						}
					}
				}
				if !found {
					return false
				}
			}
		}
		return true
	case common.FilterTypeStatus:
		for _, condition := range filter.Conditions {
			if status, ok := router["status"].(string); ok {
				if !common.WildcardMatch(condition.Value, status) {
					return false
				}
			}
		}
		return true
	case common.FilterTypeRule:
		for _, condition := range filter.Conditions {
			if rule, ok := router["rule"].(string); ok {
				if !common.WildcardMatch(condition.Value, rule) {
					return false
				}
			}
		}
		return true
	default:
		return true // Unknown filter types pass through
	}
}

func NewProviderFromStructured(options map[string]interface{}) (Provider, error) {
	filterLogPrefix := "[input/traefik/filter]"
	if name, ok := options["name"]; ok && name != "" {
		if strName, ok := name.(string); ok {
			filterLogPrefix = "[input/traefik/" + strName + "/filter]"
		}
	} else if name, ok := options["profile_name"]; ok && name != "" {
		if strName, ok := name.(string); ok {
			filterLogPrefix = "[input/traefik/" + strName + "/filter]"
		}
	}
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")
	filterConfig, err := common.NewFilterFromStructuredOptions(options, filterLogger)
	if err != nil {
		log.Info("Error creating filter configuration: %v, using default", err)
		filterConfig = common.DefaultFilterConfig()
	}

	stringOptions := make(map[string]string)
	for key, value := range options {
		if strValue, ok := value.(string); ok {
			stringOptions[key] = strValue
		}
	}

	parsed := common.ParsePollProviderOptions(stringOptions, common.PollProviderOptions{
		Interval:           30 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "traefik",
	})
	profileName := stringOptions["name"]
	if profileName == "" {
		profileName = stringOptions["profile_name"]
	}
	if profileName == "" {
		profileName = parsed.Name
	}
	logPrefix := common.BuildLogPrefix("traefik", profileName)

	log.NewScopedLogger("", "").With("provider", profileName).Trace("Provider options received: %+v", options)

	log.NewScopedLogger("", "").With("provider", profileName).Trace("Resolved profile name: %s", profileName)

	apiURL := common.ReadFileValue(stringOptions["api_url"])
	if apiURL == "" {
		apiURL = "http://localhost:8080/api/http/routers"
	}
	log.NewScopedLogger("", "").With("provider", profileName).Debug("Using configured URL: %s", apiURL)

	authUser := common.ReadFileValue(stringOptions["api_auth_user"])
	authPass := common.ReadFileValue(stringOptions["api_auth_pass"])

	if authUser != "" {
		log.NewScopedLogger("", "").With("provider", profileName).Trace("Basic auth user configured: %s", authUser)
		if authPass != "" {
			log.NewScopedLogger("", "").With("provider", profileName).Trace("Basic auth password configured: %s", util.MaskSensitiveValue(authPass))
		} else {
			log.NewScopedLogger("", "").With("provider", profileName).Warn("Basic auth user provided without password")
		}
	} else {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("No basic auth user found in options or environment")
	}

	tlsConfig := common.ParseTLSConfigFromOptions(stringOptions)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	if !tlsConfig.Verify {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("TLS certificate verification disabled")
	}
	if tlsConfig.CA != "" {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("Using custom CA certificate: %s", tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("Using client certificate authentication")
	}

	hasActiveFilters := len(filterConfig.Filters) > 0 && !(len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == common.FilterTypeNone)

	if hasActiveFilters {
		var filterDescription strings.Builder
		for i, filter := range filterConfig.Filters {
			if filter.Type == common.FilterTypeNone || filter.Type == "" {
				continue
			}

			if i > 0 {
				filterDescription.WriteString(fmt.Sprintf(" %s ", filter.Operation))
			}

			if filter.Negate {
				filterDescription.WriteString("NOT ")
			}

			switch filter.Type {
			case common.FilterTypeName:
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
			case common.FilterTypeService:
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
			case common.FilterTypeProvider:
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
			case common.FilterTypeRule:
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
			log.NewScopedLogger("", "").With("provider", profileName).Verbose("Active filter: %s", filterDescription.String())
		}

		log.NewScopedLogger("", "").With("provider", profileName).Debug("Filter configuration: %d active filters", len(filterConfig.Filters))
		for i, f := range filterConfig.Filters {
			log.NewScopedLogger("", "").With("provider", profileName).Debug("  Filter %d: Type=%s, Value=%s, Operation=%s, Negate=%v, Conditions=%d",
				i, f.Type, f.Value, f.Operation, f.Negate, len(f.Conditions))
			for j, condition := range f.Conditions {
				log.NewScopedLogger("", "").With("provider", profileName).Debug("    Condition %d: Key='%s', Value='%s', Logic='%s'",
					j, condition.Key, condition.Value, condition.Logic)
			}
		}
	} else {
		log.NewScopedLogger("", "").With("provider", profileName).Verbose("Active filter: none (all routers will be processed)")
		log.NewScopedLogger("", "").With("provider", profileName).Debug("No active filters configured, processing all routers")
	}

	logLevel := stringOptions["log_level"] // Get provider-specific log level

	scopedLogger := common.CreateScopedLogger("traefik", profileName, stringOptions)

	if logLevel != "" {
		scopedLogger.Info("Provider log_level set to: '%s'", logLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())

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
		outputWriter:    nil, // Will be set by SetDomainConfigs
		outputSyncer:    nil, // Will be set by SetDomainConfigs
	}

	scopedLogger.Debug("Filter Configuration: %+v", filterConfig.Filters)
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

	scopedLogger.Info("Successfully created new Traefik provider with filters=%s", filterSummary)
	scopedLogger.Debug("Provider details: URL=%s, interval=%s",
		provider.apiURL, provider.pollInterval)

	return provider, nil
}

func NewProvider(options map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	profileName := options["name"]
	if profileName == "" {
		profileName = options["profile_name"]
	}
	if profileName == "" {
		parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
			Interval:           30 * time.Second,
			ProcessExisting:    false,
			RecordRemoveOnStop: false,
			Name:               "traefik",
		})
		profileName = parsed.Name
	}
	filterLogPrefix := common.BuildLogPrefix("traefik", profileName) + "/filter"
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions, filterLogger)
	if err != nil {
		log.Debug("Error creating filter configuration: %v, using default", err)
		filterConfig = common.DefaultFilterConfig()
	}

	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           30 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "traefik",
	})
	profileName = options["name"]
	if profileName == "" {
		profileName = options["profile_name"]
	}
	if profileName == "" {
		profileName = parsed.Name
	}
	logPrefix := common.BuildLogPrefix("traefik", profileName)

	apiURL := common.ReadFileValue(options["api_url"])
	if apiURL == "" {
		apiURL = "http://localhost:8080/api/http/routers"
	}
	log.NewScopedLogger("", "").With("provider", profileName).Debug("Using configured URL: %s", apiURL)

	authUser := common.ReadFileValue(options["api_auth_user"])
	authPass := common.ReadFileValue(options["api_auth_pass"])

	if authUser != "" {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("Using basic auth user: %s", authUser)
	}

	tlsConfig := common.ParseTLSConfigFromOptions(options)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	if !tlsConfig.Verify {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("TLS certificate verification disabled")
	}
	if tlsConfig.CA != "" {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("Using custom CA certificate: %s", tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		log.NewScopedLogger("", "").With("provider", profileName).Debug("Using client certificate authentication")
	}

	hasActiveFilters := len(filterConfig.Filters) > 0 && !(len(filterConfig.Filters) == 1 && filterConfig.Filters[0].Type == common.FilterTypeNone)

	if hasActiveFilters {
		var filterDescription strings.Builder
		for i, filter := range filterConfig.Filters {
			if filter.Type == common.FilterTypeNone || filter.Type == "" {
				continue
			}

			if i > 0 {
				filterDescription.WriteString(fmt.Sprintf(" %s ", filter.Operation))
			}

			if filter.Negate {
				filterDescription.WriteString("NOT ")
			}

			switch filter.Type {
			case common.FilterTypeName:
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
			case common.FilterTypeService:
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
			case common.FilterTypeProvider:
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
			case common.FilterTypeRule:
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
			log.NewScopedLogger("", "").With("provider", profileName).Verbose("Active filter: %s", filterDescription.String())
		}

		log.NewScopedLogger("", "").With("provider", profileName).Debug("Filter configuration: %d active filters", len(filterConfig.Filters))
		for i, f := range filterConfig.Filters {
			log.NewScopedLogger("", "").With("provider", profileName).Debug("  Filter %d: Type=%s, Value=%s, Operation=%s, Negate=%v, Conditions=%d",
				i, f.Type, f.Value, f.Operation, f.Negate, len(f.Conditions))
			for j, condition := range f.Conditions {
				log.NewScopedLogger("", "").With("provider", profileName).Debug("    Condition %d: Key='%s', Value='%s', Logic='%s'",
					j, condition.Key, condition.Value, condition.Logic)
			}
		}
	} else {
		log.NewScopedLogger("", "").With("provider", profileName).Verbose("Active filter: none (all routers will be processed)")
		log.NewScopedLogger("", "").With("provider", profileName).Debug("No active filters configured, processing all routers")
	}

	logLevel := options["log_level"] // Get provider-specific log level

	scopedLogger := common.CreateScopedLogger("traefik", profileName, options)

	if logLevel != "" {
		scopedLogger.Info("Provider log_level set to: '%s'", logLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())

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
		outputWriter:    outputWriter,
		outputSyncer:    outputSyncer,
	}

	scopedLogger.Info("Successfully created new Traefik provider")
	scopedLogger.Debug("Provider details: URL=%s, interval=%s",
		provider.apiURL, provider.pollInterval)

	return provider, nil
}

func (t *TraefikProvider) GetDNSEntries() ([]DNSEntry, error) {
	return nil, nil
}

func (tp *TraefikProvider) GetName() string {
	return "traefik"
}
func (t *TraefikProvider) StartPolling() error {
	t.logger.Info("Starting polling for routers (interval: %s)", t.pollInterval)

	if t.running {
		t.logger.Debug("Already running, skipping start")
		return nil
	}

	t.running = true
	go t.pollLoop()
	return nil
}

func (t *TraefikProvider) DiscoverHosts(callback func(hostnames []string) error) error {
	t.logger.Debug("DiscoverHosts called with callback function")
	return t.MonitorTraefik(callback)
}

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

func (t *TraefikProvider) IsRunning() bool {
	t.logger.Trace("IsRunning check, current value: %v", t.running)
	return t.running
}

func (t *TraefikProvider) MonitorTraefik(callback func(hostnames []string) error) error {
	t.logger.Debug("MonitorTraefik called with callback function")
	if callback == nil {
		t.logger.Warn("Warning: Callback provided to MonitorTraefik is nil")
	}
	t.callback = callback
	t.logger.Debug("Callback function set: %v, starting polling", callback != nil)
	return t.StartPolling()
}

func (t *TraefikProvider) pollLoop() {
	if t.opts.ProcessExisting {
		t.logger.Trace("Processing existing Traefik routers on startup (process_existing=true)")
		err := t.processTraefikRouters()
		if err != nil {
			t.logger.Error("Failed to process Traefik routers: %v", err)
		}
	} else {
		t.logger.Trace("Initial poll on startup (process_existing=false), inventory only, no processing")
		err := t.processTraefikRouters()
		if err != nil {
			t.logger.Error("Failed to process Traefik routers: %v", err)
		}
	}

	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()
	for t.running {
		<-ticker.C
		err := t.processTraefikRouters()
		if err != nil {
			t.logger.Error("Failed to process Traefik routers: %v", err)
		}
	}
}

func (t *TraefikProvider) processTraefikRouters() error {
	t.logger.Debug("Processing Traefik routers from API")

	body, err := t.fetchTraefikAPI(t.apiURL, t.authUser, t.authPass, t.logPrefix)
	if err != nil {
		t.logger.Error("Failed to fetch data from Traefik API: %v", err)
		return fmt.Errorf("%s failed to fetch data: %w", t.logPrefix, err)
	}

	t.logger.Debug("Parsing JSON response")

	var routersArray []map[string]interface{}
	if err := json.Unmarshal(body, &routersArray); err != nil {
		var routersMap map[string]interface{}
		if err := json.Unmarshal(body, &routersMap); err != nil {
			t.logger.Error("Failed to parse JSON response: %v", err)
			return fmt.Errorf("%s failed to parse JSON: %w", t.logPrefix, err)
		}
		t.logger.Debug("Found %d routers in API response (map format)", len(routersMap))

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
		shouldProcess := t.filterConfig.Evaluate(router, evaluateTraefikFilter)
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

	currentHostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		currentHostnames = append(currentHostnames, h)
	}

	if initialLog {
		if len(currentHostnames) == 0 {
			t.logger.Info("No routers to process")
		} else {
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
			t.logger.Info("Initial routers to process [%s]", strings.Join(routerHostPairs, ", "))
			for _, h := range currentHostnames {
				state := hostnameToRouter[h]
				t.logger.Trace("Preparing to add DNS for hostname: %s | RouterState: %+v", h, state)
				t.processRouterAdd(state)
				t.routerCache[h] = state
			}
		}
		if !t.initialPollDone {
			t.initialPollDone = true
			t.logger.Debug("Initial poll complete, future polls will only log changes.")
		}
		return nil
	}

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
			t.logger.Info("Routers detected: %v", added)
			for _, h := range added {
				t.processRouterAdd(hostnameToRouter[h])
			}
		}
		if len(removed) > 0 {
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
			t.logger.Info("Routers removed [%s]", strings.Join(removedRouterHostPairs, ", "))
			for _, h := range removed {
				if prevState, ok := t.routerCache[h]; ok {
					t.processRouterRemove(prevState)
				} else {
					t.processRouterRemove(domain.RouterState{Rule: h})
				}
			}
		}
	}

	t.routerCache = make(map[string]domain.RouterState)
	for _, h := range currentHostnames {
		t.routerCache[h] = hostnameToRouter[h]
	}

	if !t.initialPollDone {
		t.initialPollDone = true
		t.logger.Debug("Initial poll complete, future polls will only log changes.")
	}

	return nil
}

func (p *TraefikProvider) fetchTraefikAPI(url, user, pass, logPrefix string) ([]byte, error) {
	tlsConfig := common.ParseTLSConfigFromOptions(p.options)

	if !tlsConfig.Verify {
		p.logger.Debug("TLS certificate verification disabled")
	}
	if tlsConfig.CA != "" {
		p.logger.Debug("Using custom CA certificate: %s", tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		p.logger.Debug("Using client certificate authentication")
	}

	return common.FetchRemoteResourceWithTLSConfig(url, user, pass, nil, &tlsConfig, logPrefix)
}

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

func (p *TraefikProvider) pollRouters() error {
	currentRouters := []domain.RouterState{} // Replace with real router fetching logic
	currentMap := make(map[string]domain.RouterState)
	for _, r := range currentRouters {
		currentMap[r.Name] = r
	}

	if len(p.routerCache) == 0 && p.opts.ProcessExisting {
		for k, v := range currentMap {
			p.routerCache[k] = v
		}
		p.logger.Info("Initial poll: process_existing=true, populating cache only, not processing routers")
		return nil
	}

	for name, state := range currentMap {
		prev, exists := p.routerCache[name]
		if !exists {
			p.logger.Info("New router detected: %s", name)
			p.processRouterAdd(state)
		} else if !routerStatesEqual(prev, state) {
			p.logger.Info("Router updated: %s", name)
			p.processRouterUpdate(state)
		}
	}

	for name := range p.routerCache {
		if _, exists := currentMap[name]; !exists {
			p.logger.Info("Router removed: %s", name)
			if p.opts.RecordRemoveOnStop {
				p.processRouterRemove(p.routerCache[name])
			}
		}
	}

	p.routerCache = currentMap
	return nil
}

func (t *TraefikProvider) processRouterAdd(state domain.RouterState) {
	batchProcessor := domain.NewBatchProcessor(t.logPrefix, t.outputWriter, t.outputSyncer)

	hostnames := util.ExtractHostsFromRule(state.Rule)
	for _, hostname := range hostnames {
		fqdnNoDot := strings.TrimSuffix(hostname, ".")
		realDomain := t.getParentDomainForFQDN(fqdnNoDot)
		t.logger.Trace("Using real domain name '%s' for DNS provider", realDomain)

		t.logger.Trace("Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
		err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
		if err != nil {
			t.logger.Error("Failed to ensure DNS for '%s': %v", fqdnNoDot, err)
		}
	}

	batchProcessor.FinalizeBatch()
}

func (t *TraefikProvider) processRouterUpdate(state domain.RouterState) {
	t.processRouterAdd(state)
}

func (t *TraefikProvider) processRouterRemove(state domain.RouterState) {
	batchProcessor := domain.NewBatchProcessor(t.logPrefix, t.outputWriter, t.outputSyncer)

	hostnames := util.ExtractHostsFromRule(state.Rule)
	for _, hostname := range hostnames {
		fqdnNoDot := strings.TrimSuffix(hostname, ".")
		realDomain := t.getParentDomainForFQDN(fqdnNoDot)
		t.logger.Trace("Using real domain name '%s' for DNS provider (removal)", realDomain)

		t.logger.Trace("Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
		err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
		if err != nil {
			t.logger.Error("Failed to remove DNS for '%s': %v", fqdnNoDot, err)
		}
	}

	batchProcessor.FinalizeBatch()
}

func extractHostsFromRule(rule string) []string {
	log.NewScopedLogger("", "").With("provider", "traefik").Trace("Extracting hosts from rule: '%s'", rule)
	var hostnames []string

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

	for _, match := range hostRuleRegex.FindAllStringSubmatch(rule, -1) {
		if len(match) > 1 {
			hostnames = append(hostnames, parseHosts(match[1])...)
		}
	}
	for _, match := range hostSniRuleRegex.FindAllStringSubmatch(rule, -1) {
		if len(match) > 1 {
			hostnames = append(hostnames, parseHosts(match[1])...)
		}
	}
	for _, match := range hostRegexpRuleRegex.FindAllStringSubmatch(rule, -1) {
		if len(match) > 1 {
			hostnames = append(hostnames, parseHosts(match[1])...)
		}
	}

	return hostnames
}

func getDomainFromHostname(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
