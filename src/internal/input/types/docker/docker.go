// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package docker

import (
	"github.com/nfrastack/herald/internal/config" // This import is needed for config.GlobalConfig
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input/common"
	"github.com/nfrastack/herald/internal/log" // Re-import the log package
	heraldstate "github.com/nfrastack/herald/internal/state"

	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	dcontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
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

func (d DNSEntry) GetFQDN() string {
	return d.Name
}

func (d DNSEntry) GetRecordType() string {
	return d.RecordType
}

type ContainerInfo struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	State  string            `json:"state"`
}

type DockerProvider struct {
	apiAuthPass        string
	apiAuthUser        string
	client             *client.Client
	config             Config
	domainConfigs      map[string]config.DomainConfig
	exposeContainers   bool
	filterConfig       common.FilterConfig
	lastContainerIDs   map[string]bool
	logPrefix          string
	options            map[string]interface{}
	profileName        string
	recordRemoveOnStop bool
	running            bool
	swarmMode          bool
	opts               common.PollProviderOptions
	logger             *log.ScopedLogger
	sharedConnection   *SharedConnection
	removalCache       map[string]time.Time
	removalCacheMutex  sync.Mutex
	outputWriter       domain.OutputWriter // Injected dependency
	outputSyncer       domain.OutputSyncer // Injected dependency
}

type Config struct {
	APIAuthPass      string `mapstructure:"api_auth_pass"`
	APIAuthUser      string `mapstructure:"api_auth_user"`
	APIURL           string `mapstructure:"api_url"`
	ExposeContainers bool   `mapstructure:"expose_containers"`
	ProcessExisting  bool   `mapstructure:"process_existing"`
	SwarmMode        bool   `mapstructure:"swarm_mode"`
}

type DockerContainerInfo struct {
	Hostname   string
	ID         string
	Overwrite  bool
	RecordType string
	Target     string
	TTL        int
}

func (c *DockerContainerInfo) GetID() string {
	return c.ID
}

func (c *DockerContainerInfo) GetHostname() string {
	return c.Hostname
}

func (c *DockerContainerInfo) GetTarget() string {
	return c.Target
}

func extractHostsFromRule(rule string) []string {
	hosts := []string{}
	re := regexp.MustCompile(`Host\(\s*['"` + "`" + `](.*?)['"` + "`" + `]\s*\)`)
	matches := re.FindAllStringSubmatch(rule, -1)
	for _, match := range matches {
		if len(match) > 1 {
			hosts = append(hosts, match[1])
		}
	}
	return hosts
}

func evaluateDockerFilter(filter common.Filter, entry any) bool {
	container, ok := entry.(dcontainer.InspectResponse)
	if !ok {
		return false
	}

	switch filter.Type {
	case common.FilterTypeLabel:
		return evaluateDockerLabelFilter(filter, container)
	case common.FilterTypeName:
		return evaluateDockerNameFilter(filter, container)
	case common.FilterTypeImage:
		return evaluateDockerImageFilter(filter, container)
	case common.FilterTypeNetwork:
		return evaluateDockerNetworkFilter(filter, container)
	case common.FilterTypeHealth:
		return evaluateDockerHealthFilter(filter, container)
	case common.FilterTypeStatus:
		return evaluateDockerStatusFilter(filter, container)
	default:
		return true // Unknown filter types pass through
	}
}

func evaluateDockerLabelFilter(filter common.Filter, container dcontainer.InspectResponse) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	result := false
	for i, condition := range filter.Conditions {
		match := false

		if condition.Key != "" && condition.Value != "" {
			if labelValue, exists := container.Config.Labels[condition.Key]; exists {
				match = common.WildcardMatch(condition.Value, labelValue)
			}
		} else if condition.Key != "" {
			_, match = container.Config.Labels[condition.Key]
		} else if condition.Value != "" {
			for _, labelValue := range container.Config.Labels {
				if common.WildcardMatch(condition.Value, labelValue) {
					match = true
					break
				}
			}
		}

		if i == 0 {
			result = match
		} else if condition.Logic == "or" {
			result = result || match
		} else { // default "and"
			result = result && match
		}
	}

	return result
}

func evaluateDockerNameFilter(filter common.Filter, container dcontainer.InspectResponse) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	result := false
	for i, condition := range filter.Conditions {
		match := common.WildcardMatch(condition.Value, containerName)

		if i == 0 {
			result = match
		} else if condition.Logic == "or" {
			result = result || match
		} else {
			result = result && match
		}
	}

	return result
}

func evaluateDockerImageFilter(filter common.Filter, container dcontainer.InspectResponse) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	result := false
	for i, condition := range filter.Conditions {
		match := common.WildcardMatch(condition.Value, container.Config.Image)

		if i == 0 {
			result = match
		} else if condition.Logic == "or" {
			result = result || match
		} else {
			result = result && match
		}
	}

	return result
}

func evaluateDockerNetworkFilter(filter common.Filter, container dcontainer.InspectResponse) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	result := false
	for i, condition := range filter.Conditions {
		match := false

		for networkName := range container.NetworkSettings.Networks {
			if common.WildcardMatch(condition.Value, networkName) {
				match = true
				break
			}
		}

		if i == 0 {
			result = match
		} else if condition.Logic == "or" {
			result = result || match
		} else {
			result = result && match
		}
	}

	return result
}

func evaluateDockerHealthFilter(filter common.Filter, container dcontainer.InspectResponse) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	healthStatus := "none"
	if container.State.Health != nil {
		healthStatus = container.State.Health.Status
	}

	result := false
	for i, condition := range filter.Conditions {
		match := common.WildcardMatch(condition.Value, healthStatus)

		if i == 0 {
			result = match
		} else if condition.Logic == "or" {
			result = result || match
		} else {
			result = result && match
		}
	}

	return result
}

func evaluateDockerStatusFilter(filter common.Filter, container dcontainer.InspectResponse) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	result := false
	for i, condition := range filter.Conditions {
		match := common.WildcardMatch(condition.Value, container.State.Status)

		if i == 0 {
			result = match
		} else if condition.Logic == "or" {
			result = result || match
		} else {
			result = result && match
		}
	}

	return result
}

const customHeaderPrefix = "api_header_"

func isTCPAPIURL(apiURL string) bool {
	lower := strings.ToLower(apiURL)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func hasAuthorizationHeader(headers map[string]string) bool {
	for k := range headers {
		if strings.EqualFold(k, "Authorization") {
			return true
		}
	}
	return false
}

func collectCustomHeaders(stringOptions map[string]string) map[string]string {
	headers := make(map[string]string)
	for key, value := range stringOptions {
		if !strings.HasPrefix(key, customHeaderPrefix) {
			continue
		}
		name := strings.TrimPrefix(key, customHeaderPrefix)
		if name == "" {
			continue
		}
		if resolved := common.ReadFileValue(value); resolved != "" {
			headers[name] = resolved
		}
	}
	return headers
}

func NewProvider(profileName string, config map[string]interface{}, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	options := make(map[string]string)
	for k, v := range config {
		options[k] = fmt.Sprintf("%v", v)
	}
	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	return NewProviderFromStructured(structuredOptions, outputWriter, outputSyncer)
}

func NewProviderFromStructured(options map[string]interface{}, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	profileName := ""
	if v, ok := options["name"].(string); ok && v != "" {
		profileName = v
	} else if v, ok := options["profile_name"].(string); ok && v != "" {
		profileName = v
	}
	filterLogPrefix := fmt.Sprintf("[input/docker/%s/filter]", profileName)
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")

	filterConfig, err := common.NewFilterFromStructuredOptions(options, filterLogger)
	if err != nil {
		filterLogger.With("action", "config.error").Info("filter configuration: %v, using default", err)
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
		Name:               "docker",
	})

	profileName = stringOptions["name"]
	if profileName == "" {
		profileName = stringOptions["profile_name"]
	}
	if profileName == "" {
		profileName = parsed.Name
	}
	logPrefix := common.BuildLogPrefix("docker", profileName)

	tlsConfig := common.ParseTLSConfigFromOptions(stringOptions)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	if tlsConfig.HasCustomCerts() {
		log.NewScopedLogger("", "").With("action", "tls.load", "provider", profileName).Debug("custom TLS certificates configured (verify=%t)", tlsConfig.Verify)
	} else if !tlsConfig.Verify {
		log.NewScopedLogger("", "").With("action", "tls.skip", "provider", profileName).Warn("verification disabled - ensure your Docker daemon is secure")
	}

	scopedLogger := common.CreateScopedLogger("docker", profileName, stringOptions)

	scopedLogger.With("action", "provider.init").Trace("profile name: %s", profileName)

	clientOpts := []client.Opt{client.FromEnv}

	apiURL := common.ReadFileValue(stringOptions["api_url"])
	if apiURL == "" {
		apiURL = "unix:///var/run/docker.sock"
	}
	if apiURL != "" {
		scopedLogger.With("action", "provider.init").Verbose("docker API URL: %s", apiURL)
		clientOpts = append(clientOpts, client.WithHost(apiURL))
	}

	var tlsVerifySet, tlsVerify bool
	if val, exists := stringOptions["tls.verify"]; exists {
		tlsVerifySet = true
		tlsVerify = strings.ToLower(val) == "true" || val == "1"
	}
	caPath := stringOptions["tls.ca"]
	certFile := stringOptions["tls.cert"]
	keyFile := stringOptions["tls.key"]

	if caPath != "" || certFile != "" || keyFile != "" || tlsVerifySet {
		if caPath != "" {
			clientOpts = append(clientOpts, client.WithTLSClientConfig(caPath, certFile, keyFile))
			scopedLogger.With("action", "tls.load").Debug("docker TLS config: ca=%s cert=%s key=%s", caPath, certFile, keyFile)
		}
		if tlsVerifySet && !tlsVerify {
			clientOpts = append(clientOpts, client.WithTLSClientConfig("", "", ""))
			scopedLogger.With("action", "tls.skip").Warn("docker TLS verification disabled! Not recommended for production.")
		}
	}

	apiAuthUser := common.ReadFileValue(stringOptions["api_auth_user"])
	apiAuthPass := common.ReadFileValue(stringOptions["api_auth_pass"])
	customHeaders := collectCustomHeaders(stringOptions)
	if apiAuthUser != "" {
		scopedLogger.With("action", "config.load").Debug("docker API basic auth user: %s", apiAuthUser)
		if apiAuthPass != "" {
			scopedLogger.With("action", "config.load").Debug("docker API basic auth password is set (masked)")
		} else {
			scopedLogger.With("action", "config.error").Warn("docker API basic auth user provided without password")
		}
		if !isTCPAPIURL(apiURL) {
			scopedLogger.With("action", "config.error").Warn("docker API basic auth only applies to http(s) endpoints, ignoring for '%s'", apiURL)
		} else if !hasAuthorizationHeader(customHeaders) {
			customHeaders["Authorization"] = basicAuthHeader(apiAuthUser, apiAuthPass)
		}
	}
	if len(customHeaders) > 0 {
		if !isTCPAPIURL(apiURL) {
			scopedLogger.With("action", "config.error").Warn("docker API custom headers only apply to http(s) endpoints, ignoring for '%s'", apiURL)
		} else {
			scopedLogger.With("action", "config.load").Debug("docker API custom headers: %d (values masked)", len(customHeaders))
			clientOpts = append(clientOpts, client.WithHTTPHeaders(customHeaders))
		}
	}

	client, err := client.NewClientWithOpts(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	provider := &DockerProvider{
		client:           client,
		options:          options,
		running:          false,
		lastContainerIDs: make(map[string]bool),
		profileName:      profileName,
		logPrefix:        logPrefix,
		apiAuthUser:      apiAuthUser,
		apiAuthPass:      apiAuthPass,
		opts:             parsed,
		logger:           scopedLogger,
		removalCache:     make(map[string]time.Time),
		outputWriter:     outputWriter,
		outputSyncer:     outputSyncer,
	}

	var config Config

	config.APIAuthPass = apiAuthPass
	config.APIAuthUser = apiAuthUser
	config.APIURL = apiURL
	config.ExposeContainers = false
	config.ProcessExisting = parsed.ProcessExisting
	config.SwarmMode = false

	scopedLogger.With("action", "config.load").Trace("options received: %v", options)

	if val, exists := options["expose_containers"]; exists {
		if strVal, ok := val.(string); ok {
			lowerVal := strings.ToLower(strVal)
			config.ExposeContainers = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
			scopedLogger.With("action", "config.load").Trace("option 'expose_containers': '%s', parsed as: %v", strVal, config.ExposeContainers)
		}
	} else {
		scopedLogger.With("action", "config.load").Trace("option 'expose_containers' not set, using default: %v", config.ExposeContainers)
	}

	if val, exists := options["swarm_mode"]; exists {
		if strVal, ok := val.(string); ok {
			lowerVal := strings.ToLower(strVal)
			config.SwarmMode = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
			scopedLogger.With("action", "config.load").Trace("option 'swarm_mode': '%s', parsed as: %v",
				strVal, config.SwarmMode)
		}
	} else {
		scopedLogger.With("action", "config.load").Trace("option 'swarm_mode' not set, using default: %v",
			config.SwarmMode)
	}

	if val, exists := options["process_existing"]; exists {
		if strVal, ok := val.(string); ok {
			config.ProcessExisting = strings.ToLower(strVal) == "true" || strVal == "1"
			scopedLogger.With("action", "config.load").Trace("option 'process_existing': '%s', parsed as: %v",
				strVal, config.ProcessExisting)
		}
	} else {
		envKey := fmt.Sprintf("POLL_%s_PROCESS_EXISTING", strings.ToUpper(profileName))
		if envVal := os.Getenv(envKey); envVal != "" {
			config.ProcessExisting = strings.ToLower(envVal) == "true" || envVal == "1"
			scopedLogger.With("action", "config.load").Trace("process_existing from environment variable %s: %v", envKey, config.ProcessExisting)
		}
	}

	provider.config = config
	provider.filterConfig = filterConfig

	connectionManager := GetConnectionManager()
	sharedConn, err := connectionManager.GetOrCreateConnection(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get shared connection: %w", err)
	}

	provider.sharedConnection = sharedConn
	provider.swarmMode = config.SwarmMode
	provider.exposeContainers = config.ExposeContainers
	provider.recordRemoveOnStop = parsed.RecordRemoveOnStop

	scopedLogger.With("action", "input.filter").Debug("filter config with %d filters", len(filterConfig.Filters))
	for i, filter := range filterConfig.Filters {
		scopedLogger.With("action", "input.filter").Debug("filter %d: Type='%s', Value='%s', Operation='%s', Negate=%v, Conditions=%d",
			i, filter.Type, filter.Value, filter.Operation, filter.Negate, len(filter.Conditions))
		for j, condition := range filter.Conditions {
			scopedLogger.With("action", "input.filter").Debug("  condition %d: Key='%s', Value='%s', Logic='%s'",
				j, condition.Key, condition.Value, condition.Logic)
		}
	}

	if len(filterConfig.Filters) > 0 && filterConfig.Filters[0].Type != common.FilterTypeNone {
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
			case common.FilterTypeLabel:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("labels(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						if condition.Key != "" && condition.Value != "" {
							filterDescription.WriteString(fmt.Sprintf("%s=%s", condition.Key, condition.Value))
						} else if condition.Key != "" {
							filterDescription.WriteString(condition.Key)
						}
					}
					filterDescription.WriteString(")")
				}
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
			case common.FilterTypeNetwork:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("networks(")
					for j, condition := range filter.Conditions {
						if j > 0 {
							filterDescription.WriteString(fmt.Sprintf(" %s ", condition.Logic))
						}
						filterDescription.WriteString(condition.Value)
					}
					filterDescription.WriteString(")")
				}
			case common.FilterTypeImage:
				if len(filter.Conditions) > 0 {
					filterDescription.WriteString("images(")
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
			scopedLogger.With("action", "input.filter").Verbose("filter: %s", filterDescription.String())
		}
	} else {
		scopedLogger.With("action", "input.filter").Verbose("filter: none (all containers will be processed)")
	}

	scopedLogger.With("action", "input.filter").Debug("configuration: %+v", filterConfig.Filters)
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
	scopedLogger.With("action", "provider.init").Info("'%s': filters=%s, expose_containers=%v, swarm_mode=%v, process_existing=%v, record_remove_on_stop=%v",
		"docker", filterSummary, config.ExposeContainers, config.SwarmMode, config.ProcessExisting, provider.recordRemoveOnStop)

	return provider, nil
}

func (p *DockerProvider) IsRunning() bool {
	return p.running
}

func (p *DockerProvider) handleContainerEventFiltered(ctx context.Context, event events.Message) {
	containerName := event.Actor.Attributes["name"]
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	container, err := p.client.ContainerInspect(ctx, event.Actor.ID)
	if err != nil {
		p.logger.With("action", "input.filter", "container", containerName).Debug("failed to inspect container '%s' for filtering: %v", containerName, err)
		return
	}

	if !p.shouldProcessContainer(container) {
		p.logger.With("action", "input.filter", "container", containerName).Debug("filtered out: '%s' by provider '%s'", containerName, p.profileName)
		return
	}

	p.handleContainerEvent(ctx, event)
}

func (p *DockerProvider) handleServiceEventFiltered(ctx context.Context, event events.Message) {
	p.handleServiceEvent(ctx, event)
}

func (p *DockerProvider) StopPolling() error {
	if !p.running {
		return nil
	}

	p.running = false

	connectionManager := GetConnectionManager()
	connectionManager.RemoveProvider(p)

	return nil
}

func (p *DockerProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

func (p *DockerProvider) StartPolling() error {
	if p.sharedConnection == nil {
		return fmt.Errorf("no shared connection available")
	}

	if err := p.sharedConnection.StartEventStreaming(); err != nil {
		return fmt.Errorf("failed to start shared event streaming: %w", err)
	}

	p.running = true

	if heraldstate.Default != nil {
		go p.reconcileLoop()
	}

	if p.config.ProcessExisting {
		p.logger.With("action", "sync.start").Verbose("existing containers and services")
		go p.processRunningContainers(context.Background())

		if p.swarmMode {
			go p.processRunningServices(context.Background())
		}
	} else {
		p.logger.With("action", "sync.start").Info("new containers/services")
	}

	return nil
}

func (p *DockerProvider) reconcileLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for p.running {
		<-ticker.C
		p.reconcilePresence()
	}
}

func (p *DockerProvider) reconcilePresence() {
	ctx := context.Background()
	containers, err := p.client.ContainerList(ctx, dcontainer.ListOptions{})
	if err != nil {
		p.logger.With("action", "sync.fail").Debug("failed to list containers: %v", err)
		return
	}
	for _, c := range containers {
		container, err := p.client.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}
		if !p.shouldProcessContainer(container) {
			continue
		}
		for _, entry := range p.extractDNSEntriesFromContainer(container) {
			domainKey, subdomain := config.ExtractDomainAndSubdomainForProvider(entry.Name, p.profileName, p.logPrefix)
			if domainKey == "" {
				continue
			}
			domainCfg, ok := config.GlobalConfig.Domains[domainKey]
			if !ok {
				continue
			}
			host := subdomain
			if host == "" {
				host = "@"
			}
			heraldstate.Touch(domainCfg.Name, host, entry.RecordType, entry.Target, p.profileName, "")
		}
	}
}

func (p *DockerProvider) handleContainerEvent(ctx context.Context, event events.Message) {
	if event.Type != "container" {
		return
	}

	containerID := event.Actor.ID
	containerName := event.Actor.Attributes["name"]
	if containerName == "" {
		containerName = containerID[:12]
	}

	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	switch event.Action {
	case "start", "unpause":
		p.logger.With("action", "record.create", "container", containerName).With("id", event.Actor.ID[:12]).Info("started: %s (%s), processing DNS records for this container only", containerName, event.Actor.ID[:12])
		p.processSpecificContainer(event.Actor.ID)
	case "stop", "pause", "die", "kill", "destroy":
		p.removalCacheMutex.Lock()
		if lastRemoval, found := p.removalCache[containerID]; found && time.Since(lastRemoval) < 5*time.Second {
			p.logger.With("action", "sync.skip", "container", containerName).With("id", event.Actor.ID[:12]).Trace("duplicate removal event for container %s (%s)", containerName, event.Actor.ID[:12])
			p.removalCacheMutex.Unlock()
			return
		}
		p.removalCache[containerID] = time.Now()
		p.removalCacheMutex.Unlock()

		if !p.recordRemoveOnStop {
			if event.Action == "destroy" {
				p.logger.With("action", "record.skip", "container", containerName).With("id", event.Actor.ID[:12]).Debug("destroyed: %s (%s) but record_remove_on_stop=false, skipping DNS removal", containerName, event.Actor.ID[:12])
			} else {
				p.logger.With("action", "record.skip", "container", containerName).With("id", event.Actor.ID[:12]).Info("stopped: %s (%s) but record_remove_on_stop=false, skipping DNS removal", containerName, event.Actor.ID[:12])
			}
			return
		}

		if event.Action == "destroy" {
			p.logger.With("action", "record.delete", "container", containerName).With("id", event.Actor.ID[:12]).Debug("destroyed: %s (%s), removing DNS records", containerName, event.Actor.ID[:12])
		} else {
			p.logger.With("action", "record.delete", "container", containerName).With("id", event.Actor.ID[:12]).Info("stopped: %s (%s), removing DNS records for this container only", containerName, event.Actor.ID[:12])
		}
		p.removeContainerRecords(event.Actor.ID)
	default:
		p.logger.With("action", "sync.skip", "container", containerName).With("id", event.Actor.ID[:12]).Trace("event %s for container %s (%s)", event.Action, containerName, event.Actor.ID[:12])
	}
}

func (p *DockerProvider) handleServiceEvent(ctx context.Context, event events.Message) {
	if event.Type != "service" {
		return
	}

	serviceID := event.Actor.ID
	serviceName := event.Actor.Attributes["name"]
	if serviceName == "" {
		serviceName = serviceID[:12]
	}

	switch event.Action {
	case "create", "update":
		p.processService(ctx, serviceID)
	case "remove":
		service, _, err := p.client.ServiceInspectWithRaw(ctx, serviceID, swarm.ServiceInspectOptions{})
		if err != nil {
			p.logger.With("action", "record.delete", "service", serviceName).Warn("failed to inspect service '%s' for DNS removal: '%v'", serviceName, err)
			return
		}
		entries, err := p.extractDNSEntriesFromService(service)
		if err != nil {
			p.logger.With("action", "record.delete", "service", serviceName).Warn("failed to extract DNS entries from service '%s' for removal: %v", serviceName, err)
			return
		}
		if len(entries) > 0 {
			if !p.recordRemoveOnStop {
				p.logger.With("action", "record.skip", "service", serviceName).Info("removed: '%s' but record_remove_on_stop=false, skipping DNS removal (%d entries)", serviceName, len(entries))
			} else {
				p.logger.With("action", "record.delete", "service", serviceName).Info("%d DNS entries for service %s", len(entries), serviceName)
				p.processDNSEntries(entries, true)
			}
		} else {
			p.logger.With("action", "record.skip", "service", serviceName).Debug("no DNS entries for service '%s' to remove", serviceName)
		}
	}
}

func (p *DockerProvider) processSpecificContainer(containerID string) {
	ctx := context.Background()

	container, err := p.client.ContainerInspect(ctx, containerID)
	if err != nil {
		p.logger.With("action", "sync.fail", "id", containerID[:12]).Error("failed to inspect container %s: %v", containerID[:12], err)
		return
	}

	containerName := getContainerName(container)
	p.logger.With("action", "input.pass", "container", containerName).With("id", containerID[:12]).Debug("specific container: %s (%s)", containerName, containerID[:12])

	if container.State.Running && p.shouldProcessContainer(container) {
		enableDNS, hasLabel := container.Config.Labels["nfrastack.herald.enable"]
		if hasLabel && (strings.ToLower(enableDNS) == "true" || enableDNS == "1") && !p.config.ExposeContainers {
			p.logger.With("action", "input.pass", "container", containerName).Verbose("container '%s' has 'nfrastack.herald.enable=true' label (overriding expose_containers=false)", containerName)
		}
		p.processContainer(ctx, containerID)
	} else {
		p.logger.With("action", "input.filter", "id", containerID[:12]).Debug("filtered out or not running, skipping: %s", containerID[:12])
	}
}

func (p *DockerProvider) removeContainerRecords(containerID string) {
	ctx := context.Background()

	container, err := p.client.ContainerInspect(ctx, containerID)
	if err != nil {
		p.logger.With("action", "record.delete", "id", containerID[:12]).Debug("could not inspect container %s for cleanup: %v", containerID[:12], err)
		return
	}

	containerName := getContainerName(container)
	p.logger.With("action", "record.delete", "container", containerName).With("id", containerID[:12]).Debug("DNS records for container: %s (%s)", containerName, containerID[:12])

	entries := p.extractDNSEntriesFromContainer(container)

	if len(entries) > 0 {
		p.logger.With("action", "record.delete", "container", containerName).Info("%d DNS entries for container %s", len(entries), containerName)
		p.processDNSEntries(entries, true)
	} else {
		p.logger.With("action", "record.skip", "container", containerName).Debug("no DNS entries for container %s cleanup", containerName)
	}
}

func (p *DockerProvider) processRunningContainers(ctx context.Context) {
	containers, err := p.client.ContainerList(ctx, dcontainer.ListOptions{})
	if err != nil {
		p.logger.With("action", "sync.fail").Error("failed to list containers: %v", err)
		return
	}

	p.logger.With("action", "provider.poll").Verbose("%d containers", len(containers))

	processedCount := 0

	processedIDs := make(map[string]struct{})

	for _, container := range containers {
		containerDetails, err := p.client.ContainerInspect(ctx, container.ID)
		if err != nil {
			p.logger.With("action", "sync.fail", "id", container.ID[:12]).Warn("failed to inspect container '%s': %v", container.ID[:12], err)
			continue
		}

		if p.shouldProcessContainer(containerDetails) {
			if _, already := processedIDs[container.ID]; !already {
				enableDNS, hasLabel := containerDetails.Config.Labels["nfrastack.herald.enable"]
				if hasLabel && (strings.ToLower(enableDNS) == "true" || enableDNS == "1") && !p.config.ExposeContainers {
					p.logger.With("action", "input.pass", "container", getContainerName(containerDetails)).Verbose("container '%s' has 'nfrastack.herald.enable=true' label (overriding expose_containers=false)", getContainerName(containerDetails))
				}
				processedCount++
				processedIDs[container.ID] = struct{}{}
				p.processContainer(ctx, container.ID)
			}
		}
	}

	if processedCount != len(containers) {
		p.logger.With("action", "sync.done").Verbose("%d of %d containers (filtered %d)",
			processedCount, len(containers), len(containers)-processedCount)
	}
}

func (p *DockerProvider) processRunningServices(ctx context.Context) {
	if !p.swarmMode {
		p.logger.With("action", "sync.skip").Debug("not in swarm mode, skipping service processing")
		return
	}

	p.logger.With("action", "sync.start").Info("running services (swarm mode)")

	services, err := p.client.ServiceList(ctx, swarm.ServiceListOptions{})
	if err != nil {
		p.logger.With("action", "sync.fail").Error("failed to list services: %v", err)
		return
	}

	p.logger.With("action", "provider.poll").Verbose("%d services", len(services))

	for _, service := range services {
		p.processService(ctx, service.ID)
	}
}

func (p *DockerProvider) shouldProcessContainer(container dcontainer.InspectResponse) bool {
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	if !p.filterConfig.Evaluate(container, evaluateDockerFilter) {
		p.logger.With("action", "input.filter", "container", containerName).Debug("container '%s' does not match filter criteria", containerName)
		return false
	}

	enableDNS, hasLabel := container.Config.Labels["nfrastack.herald.enable"]

	if hasLabel && (strings.ToLower(enableDNS) == "false" || enableDNS == "0") {
		p.logger.With("action", "input.filter", "container", containerName).Verbose("container '%s' has explicit 'nfrastack.herald.enable=false' label", containerName)
		return false
	}

	disableLabelKey := "nfrastack.herald.disable." + p.profileName
	if disableVal, hasDisable := container.Config.Labels[disableLabelKey]; hasDisable {
		val := strings.ToLower(disableVal)
		if val == "true" || val == "1" {
			p.logger.With("action", "input.filter", "container", containerName).Verbose("container '%s' has '%s=%s' label (disabling this provider)", containerName, disableLabelKey, disableVal)
			return false
		}
	}

	if p.config.ExposeContainers {
		p.logger.With("action", "input.pass", "container", containerName).Debug("container '%s': 'expose_containers=true' in config", containerName)
		return true
	}

	if !hasLabel {
		p.logger.With("action", "input.filter", "container", containerName).Debug("container '%s': 'expose_containers=false' in config and no 'nfrastack.herald.enable' label", containerName)
		return false
	}

	if strings.ToLower(enableDNS) == "true" || enableDNS == "1" {
		return true
	}

	p.logger.With("action", "input.filter", "container", containerName).Warn("container '%s' has 'nfrastack.herald.enable=%s' (not 'true') and 'expose_containers=false'", containerName, enableDNS)
	return false
}

func (p *DockerProvider) processContainer(ctx context.Context, containerID string) {
	container, err := p.client.ContainerInspect(ctx, containerID)
	if err != nil {
		p.logger.With("action", "sync.fail", "id", containerID[:12]).Warn("failed to inspect container '%s': %v", containerID[:12], err)
		return
	}

	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	if !p.shouldProcessContainer(container) {
		p.logger.With("action", "input.filter", "container", containerName).Debug("container '%s' filtered out", containerName)
		return
	}

	entries := p.extractDNSEntriesFromContainer(container)

	if len(entries) > 0 {
		p.processDNSEntries(entries, false)
	}
}

func (p *DockerProvider) processService(ctx context.Context, serviceID string) {
	if !p.swarmMode {
		return
	}

	service, _, err := p.client.ServiceInspectWithRaw(ctx, serviceID, swarm.ServiceInspectOptions{})
	if err != nil {
		p.logger.With("action", "sync.fail", "id", serviceID[:12]).Warn("failed to inspect service %s: %v", serviceID[:12], err)
		return
	}

	serviceName := service.Spec.Name

	entries, err := p.extractDNSEntriesFromService(service)
	if err != nil {
		p.logger.With("action", "sync.fail", "service", serviceName).Warn("failed to extract DNS entries from service %s: %v", serviceName, err)
	}

	if len(entries) > 0 {
		p.logger.With("action", "record.sync", "service", serviceName).Verbose("%d DNS entries for service %s", len(entries), serviceName)
		p.processDNSEntries(entries, false)
	} else {
		p.logger.With("action", "record.skip", "service", serviceName).Debug("no DNS entries for service %s", serviceName)
	}
}

func (p *DockerProvider) processDNSEntries(entries []DNSEntry, remove bool) error {
	batchProcessor := domain.NewBatchProcessorWithProvider(p.profileName, p.profileName, p.outputWriter, p.outputSyncer)

	for _, entry := range entries {
		var fqdn string
		if entry.Hostname == "@" || entry.Hostname == "" {
			fqdn = entry.Domain
		} else {
			fqdn = entry.Hostname + "." + entry.Domain
		}

		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		domainKey, subdomain := config.ExtractDomainAndSubdomainForProvider(fqdnNoDot, p.profileName, p.logPrefix)
		p.logger.With("action", "domain.match").Trace("domainKey='%s', subdomain='%s' from fqdn='%s'", domainKey, subdomain, fqdnNoDot)
		if domainKey == "" {
			p.logger.With("action", "domain.skip").Error("no domain config for '%s' (tried to match domain from FQDN)", fqdnNoDot)
			continue
		}
		domainCfg, ok := config.GlobalConfig.Domains[domainKey]
		if !ok {
			p.logger.With("action", "domain.skip").Error("domain '%s' not found in config for fqdn='%s'", domainKey, fqdnNoDot)
			continue
		}
		realDomain := domainCfg.Name
		p.logger.With("action", "domain.match").Trace("real domain name '%s' for DNS provider (configKey='%s')", realDomain, domainKey)

		state := domain.RouterState{
			SourceType: p.profileName, // Use the unique profile name for change tracking
			Name:       p.profileName,
			Service:    entry.Target,
			RecordType: entry.RecordType,
			Overwrite:  entry.Overwrite,
		}

		var fqdnForBatch string
		if subdomain == "@" {
			fqdnForBatch = realDomain
		} else {
			fqdnForBatch = subdomain + "." + realDomain
		}

		var err error
		trackedHost := strings.TrimSuffix(fqdnForBatch, "."+realDomain)
		if trackedHost == fqdnForBatch {
			trackedHost = "@"
		}
		if remove {
			p.logger.With("action", "record.delete").Trace("ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v, outputWriter)", realDomain, fqdnForBatch, state)
			err = batchProcessor.ProcessRecordRemoval(realDomain, fqdnForBatch, state)
			if err == nil {
				heraldstate.Remove(realDomain, trackedHost, entry.RecordType)
			}
		} else {
			p.logger.With("action", "record.sync").Trace("ProcessRecord(domain='%s', fqdn='%s', state=%+v, outputWriter)", realDomain, fqdnForBatch, state)
			err = batchProcessor.ProcessRecord(realDomain, fqdnForBatch, state)
			if err == nil {
				heraldstate.Touch(realDomain, trackedHost, entry.RecordType, entry.Target, p.profileName, "")
			}
		}

		if err != nil {
			action := "ensure"
			if remove {
				action = "remove"
			}
			p.logger.With("action", "sync.fail").Error("failed to %s DNS for '%s': %v", action, fqdnNoDot, err)
		}
	}

	batchProcessor.FinalizeBatch()
	return nil
}

func (p *DockerProvider) GetDNSEntries() ([]DNSEntry, error) {
	ctx := context.Background()

	containers, err := p.client.ContainerList(ctx, dcontainer.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []DNSEntry

	for _, c := range containers {
		if c.State != "running" {
			continue
		}

		container, err := p.client.ContainerInspect(ctx, c.ID)
		if err != nil {
			p.logger.With("action", "sync.fail").Warn("failed to inspect container '%s': %v", c.ID[:12], err)
			continue
		}

		entries := p.extractDNSEntriesFromContainer(container)
		result = append(result, entries...)
	}

	p.logger.With("action", "sync.done").Info("%d DNS entries from all containers", len(result))

	return result, nil
}

func (p *DockerProvider) GetContainersForDomain(domain string) ([]ContainerInfo, error) {
	ctx := context.Background()

	containers, err := p.client.ContainerList(ctx, dcontainer.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []ContainerInfo

	for _, c := range containers {
		if c.State != "running" {
			continue
		}

		container, err := p.client.ContainerInspect(ctx, c.ID)
		if err != nil {
			p.logger.With("action", "sync.fail").Warn("failed to inspect container '%s': %v", c.ID[:12], err)
			continue
		}

		labels := container.Config.Labels

		enableDNS := false
		if dnsEnable, ok := labels["nfrastack.herald.enable"]; ok {
			enableDNS = strings.ToLower(dnsEnable) == "true"
		} else if p.config.ExposeContainers {
			enableDNS = true
		}

		if !enableDNS {
			continue
		}

		dnsEntries := p.extractDNSInfoFromContainerForDomain(container, domain)
		for _, entry := range dnsEntries {
			containerInfo := ContainerInfo{
				ID:     entry.ID,
				Name:   entry.Hostname,
				State:  "running",
				Labels: container.Config.Labels,
			}
			result = append(result, containerInfo)
		}
	}

	p.logger.With("action", "sync.done").Info("%d containers with DNS entries for domain %s",
		len(result), domain)

	return result, nil
}

func (p *DockerProvider) extractDNSInfoFromContainerForDomain(container dcontainer.InspectResponse, domain string) []*DockerContainerInfo {
	var entries []*DockerContainerInfo

	labels := container.Config.Labels
	if len(labels) == 0 {
		return entries
	}

	shouldRegister := false
	hostnames := []string{}

	if hostLabel, exists := labels["nfrastack.herald.host"]; exists && hostLabel != "" {
		splitFunc := func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n'
		}
		for _, host := range strings.FieldsFunc(hostLabel, splitFunc) {
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				hostDomain := strings.Join(parts[len(parts)-2:], ".")
				if hostDomain == domain {
					shouldRegister = true
					hostname := "@"
					if len(parts) > 2 {
						hostname = strings.Join(parts[:len(parts)-2], ".")
					}
					hostnames = append(hostnames, hostname)
				}
			}
		}
	}

	if !shouldRegister {
		for k, v := range labels {
			if strings.HasPrefix(k, "traefik.http.routers.") && strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
				hosts := extractHostsFromRule(v)
				for _, host := range hosts {
					parts := strings.Split(host, ".")
					if len(parts) >= 2 {
						hostDomain := strings.Join(parts[len(parts)-2:], ".")
						if hostDomain == domain {
							shouldRegister = true
							hostname := "@"
							if len(parts) > 2 {
								hostname = strings.Join(parts[:len(parts)-2], ".")
							}
							hostnames = append(hostnames, hostname)
						}
					}
				}
			}
		}
	}

	if !shouldRegister || len(hostnames) == 0 {
		return entries
	}

	recordType := ""
	if rt, exists := labels["nfrastack.herald.record.type"]; exists && rt != "" {
		recordType = rt
	}

	target := ""
	if t, exists := labels["nfrastack.herald.target"]; exists && t != "" {
		target = t
	}

	if target == "" {
		p.logger.With("action", "record.skip", "id", container.ID[:12]).Warn("no target for domain %s (no label set)", domain)
		return entries
	}

	ttl := 0 // No default TTL
	if ttlStr, exists := labels["nfrastack.herald.record.ttl"]; exists && ttlStr != "" {
		parsed, err := strconv.Atoi(ttlStr)
		if err == nil {
			ttl = parsed
		}
	}

	overwrite := false // No default overwrite
	if overwriteStr, exists := labels["nfrastack.herald.record.overwrite"]; exists {
		if strings.ToLower(overwriteStr) == "true" || overwriteStr == "1" {
			overwrite = true
		}
	} // Create a DNS entry for each hostname
	for _, hostname := range hostnames {
		containerInfo := &DockerContainerInfo{
			ID:         container.ID,
			Hostname:   hostname,
			Target:     target,
			RecordType: recordType,
			TTL:        ttl,
			Overwrite:  overwrite,
		}
		entries = append(entries, containerInfo)
	}

	return entries
}

func getContainerName(container dcontainer.InspectResponse) string {
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}
	return containerName
}

func matchesPattern(subdomain string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "*" {
			return true
		}
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			if strings.Contains(subdomain, pattern[1:len(pattern)-1]) {
				return true
			}
		} else if strings.HasPrefix(pattern, "*") {
			if strings.HasSuffix(subdomain, pattern[1:]) {
				return true
			}
		} else if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(subdomain, pattern[:len(pattern)-1]) {
				return true
			}
		} else {
			if subdomain == pattern {
				return true
			}
		}
	}
	return false
}

func (p *DockerProvider) extractDNSEntriesFromContainer(container dcontainer.InspectResponse) []DNSEntry {
	p.logger.With("action", "config.load").Trace("domainConfigs map at entry: %v", p.domainConfigs)

	var entries []DNSEntry
	containerName := getContainerName(container)
	labels := container.Config.Labels
	if len(labels) == 0 {
		return entries
	}

	dnsLabel, hasDNSLabel := labels["nfrastack.herald.enable"]
	if hasDNSLabel {
		val := strings.ToLower(dnsLabel)
		if val == "false" || val == "0" {
			p.logger.With("action", "input.filter", "container", containerName).Verbose("container '%s': 'nfrastack.herald.enable' label set to false", containerName)
			return entries
		}
		if val == "true" || val == "1" {
		} else {
			p.logger.With("action", "input.filter", "container", containerName).Warn("container '%s': 'nfrastack.herald.enable' label has unknown value '%s'", containerName, dnsLabel)
			return entries
		}
	} else if !p.config.ExposeContainers {
		p.logger.With("action", "input.filter", "container", containerName).Debug("container '%s': 'expose_containers=false' and no 'nfrastack.herald.enable' label", containerName)
		return entries
	}

	var hostSource string
	var hostValues []string
	if v, ok := labels["nfrastack.herald.host"]; ok && v != "" {
		hostSource = "nfrastack.herald.host"
		hostValues = []string{v}
	} else {
		for k, v := range labels {
			if strings.HasPrefix(k, "traefik.http.routers.") && strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
				hosts := extractHostsFromRule(v)
				if len(hosts) > 0 {
					hostSource = k
					hostValues = append(hostValues, hosts...)
				}
			}
		}
	}
	if len(hostValues) == 0 {
		p.logger.With("action", "record.skip", "container", containerName).Debug("no hostname/domain for container '%s', skipping", containerName)
		return entries
	}
	for _, hostValue := range hostValues {
		p.logger.With("action", "domain.match", "container", containerName).Verbose("label '%s=%s' for hostname/domain extraction on container '%s'", hostSource, hostValue, containerName)

		if !strings.Contains(hostValue, ".") {
			p.logger.With("action", "domain.skip", "container", containerName).Debug("host value '%s' has no domain part (no dots found), skipping container '%s'", hostValue, containerName)
			continue
		}

		parts := strings.Split(hostValue, ".")
		if len(parts) < 2 {
			p.logger.With("action", "domain.skip", "container", containerName).Debug("host value '%s' does not have enough parts for domain extraction, skipping container '%s'", hostValue, containerName)
			continue
		}
		domain := strings.Join(parts[len(parts)-2:], ".")
		hostname := strings.Join(parts[:len(parts)-2], ".")
		if hostname == "" {
			hostname = "@"
		}

		p.logger.With("action", "domain.match").Debug("from FQDN '%s': hostname='%s', domain='%s'", hostValue, hostname, domain)

		if domain == "" {
			p.logger.With("action", "domain.skip", "container", containerName).Error("no domain extracted from FQDN '%s', skipping container '%s'", hostValue, containerName)
			continue
		}

		domainConfigKey, subdomain := config.ExtractDomainAndSubdomainForProvider(hostValue, p.profileName, p.logPrefix)
		if domainConfigKey == "" {
			p.logger.With("action", "domain.skip", "container", containerName).Error("no domain config for FQDN '%s', skipping container '%s'", hostValue, containerName)
			continue
		}

		p.logger.With("action", "domain.match").Debug("matching domain config '%s' for domain '%s'", domainConfigKey, domain)

		domainCfg, exists := config.GlobalConfig.Domains[domainConfigKey]
		if !exists {
			p.logger.With("action", "domain.skip").Error("domain config '%s' not found in global config", domainConfigKey)
			continue
		}

		domain = domainCfg.Name
		if subdomain != "" && subdomain != "@" {
			hostname = subdomain
		}
		subdomain = hostname
		if idx := strings.Index(hostname, "."); idx != -1 {
			subdomain = hostname[:idx]
		}
		if len(domainCfg.IncludeSubdomains) > 0 {
			if !matchesPattern(subdomain, domainCfg.IncludeSubdomains) {
				p.logger.With("action", "domain.skip").Verbose("subdomain '%s' for domain '%s' (not in include_subdomains)", subdomain, domain)
				continue
			}
		} else if len(domainCfg.ExcludeSubdomains) > 0 {
			if matchesPattern(subdomain, domainCfg.ExcludeSubdomains) {
				p.logger.With("action", "domain.skip").Verbose("subdomain '%s' for domain '%s' (in exclude_subdomains)", subdomain, domain)
				continue
			}
		}

		recordType := ""
		if rt, exists := labels["nfrastack.herald.record.type"]; exists && rt != "" {
			recordType = rt
			p.logger.With("action", "config.load", "container", containerName).Verbose("label 'nfrastack.herald.record.type=%s' on container '%s'", rt, containerName)
		}
		target := ""
		if t, exists := labels["nfrastack.herald.target"]; exists && t != "" {
			target = t
			p.logger.With("action", "config.load", "container", containerName).Verbose("label 'nfrastack.herald.target=%s' on container '%s'", t, containerName)
		}
		ttl := 0
		if ttlStr, exists := labels["nfrastack.herald.record.ttl"]; exists && ttlStr != "" {
			if parsed, err := strconv.Atoi(ttlStr); err == nil {
				p.logger.With("action", "config.load", "container", containerName).Verbose("label nfrastack.herald.record.ttl=%s on container '%s'", ttlStr, containerName)
				ttl = parsed
			}
		}
		overwrite := false
		if overwriteStr, exists := labels["nfrastack.herald.record.overwrite"]; exists {
			if strings.ToLower(overwriteStr) == "true" || overwriteStr == "1" {
				p.logger.With("action", "config.load", "container", containerName).Verbose("label 'nfrastack.herald.record.overwrite=%s' on container '%s'", overwriteStr, containerName)
				overwrite = true
			}
		}

		recordTypeAMultiple := false
		if val, exists := labels["nfrastack.herald.record.type.a.multiple"]; exists && val != "" {
			recordTypeAMultiple = strings.ToLower(val) == "true" || val == "1"
			p.logger.With("action", "config.load", "container", containerName).Verbose("label 'nfrastack.herald.record.type.a.multiple=%s' on container '%s'", val, containerName)
		}
		recordTypeAAAAMultiple := false
		if val, exists := labels["nfrastack.herald.record.type.aaaa.multiple"]; exists && val != "" {
			recordTypeAAAAMultiple = strings.ToLower(val) == "true" || val == "1"
			p.logger.With("action", "config.load", "container", containerName).Verbose("label 'nfrastack.herald.record.type.aaaa.multiple=%s' on container '%s'", val, containerName)
		}

		if target == "" && domainCfg.Record.Target != "" {
			p.logger.With("action", "config.load").Trace("domain config for '%s': value: 'target=%s'", domain, domainCfg.Record.Target)
			target = domainCfg.Record.Target
		}
		if recordType == "" && domainCfg.Record.Type != "" {
			p.logger.With("action", "config.load").Trace("domain config for '%s': value: 'record_type=%s'", domain, domainCfg.Record.Type)
			recordType = domainCfg.Record.Type
		}
		if ttl == 0 && domainCfg.Record.TTL > 0 {
			p.logger.With("action", "config.load").Trace("domain config for '%s': value: 'ttl=%d'", domain, domainCfg.Record.TTL)
			ttl = domainCfg.Record.TTL
		}
		if !overwrite && domainCfg.Record.UpdateExisting {
			p.logger.With("action", "config.load").Trace("domain config for '%s': value: 'record_update_existing=true'", domain)
			overwrite = true
		}

		if target == "" && p.options != nil {
			if globalTarget, ok := p.options["dns_record_target"]; ok {
				if strTarget, ok := globalTarget.(string); ok && strTarget != "" {
					p.logger.With("action", "config.load").Debug("global config for '%s': value: 'target=%s'", domain, strTarget)
					target = strTarget
				}
			}
		}
		if recordType == "" && p.options != nil {
			if globalType, ok := p.options["dns_record_type"]; ok {
				if strType, ok := globalType.(string); ok && strType != "" {
					p.logger.With("action", "config.load").Debug("global config for '%s': value: 'dns_record_type %s'", domain, strType)
					recordType = strType
				}
			}
		}
		if ttl == 0 && p.options != nil {
			if globalTTL, ok := p.options["dns_record_ttl"]; ok {
				if strTTL, ok := globalTTL.(string); ok && strTTL != "" {
					if parsed, err := strconv.Atoi(strTTL); err == nil {
						p.logger.With("action", "config.load").Debug("global config for '%s': value: 'dns_record_ttl=%d'", domain, parsed)
						ttl = parsed
					}
				}
			}
		}
		if !overwrite && p.options != nil {
			if globalOverwrite, ok := p.options["record_updating_existing"]; ok {
				if strOverwrite, ok := globalOverwrite.(string); ok && (strOverwrite == "true" || strOverwrite == "1") {
					p.logger.With("action", "config.load").Debug("global config for '%s': value: 'record_update_existing=true'", domain)
					overwrite = true
				}
			}
		}

		if recordType == "" && target != "" {
			ip := net.ParseIP(target)
			if ip != nil {
				if ip.To4() != nil {
					recordType = "A"
				} else if ip.To16() != nil {
					recordType = "AAAA"
				}
			}
			if recordType == "" {
				recordType = "CNAME"
			}
		}

		if recordType == "A" && target != "" {
			if ip := net.ParseIP(target); ip == nil || ip.To4() == nil {
				p.logger.With("action", "record.reject").Error("target for A record: '%s' is not an IPv4 address. Skipping DNS entry '%s.%s'", target, hostname, domain)
				continue
			}
		}
		if recordType == "AAAA" && target != "" {
			if ip := net.ParseIP(target); ip == nil || ip.To16() == nil || ip.To4() != nil {
				p.logger.With("action", "record.reject").Error("target for AAAA record: '%s' is not an IPv6 address. Skipping DNS entry '%s.%s'", target, hostname, domain)
				continue
			}
		}

		if target == "" {
			p.logger.With("action", "record.skip", "container", containerName).Warn("no target: '%s', domain '%s' (no label, domain, or global config set)", containerName, domain)
			continue
		}

		var fqdn string
		if hostname == "@" || hostname == "" {
			fqdn = domain
		} else {
			fqdn = hostname + "." + domain
		}

		entries = append(entries, DNSEntry{
			Name:                   fqdn,
			Hostname:               hostname,
			Domain:                 domain,
			RecordType:             recordType,
			Target:                 target,
			TTL:                    ttl,
			Overwrite:              overwrite,
			RecordTypeAMultiple:    recordTypeAMultiple,
			RecordTypeAAAAMultiple: recordTypeAAAAMultiple,
			SourceName:             containerName,
		})

		p.logger.With("action", "record.create").Trace("DNS entry for container '%s': hostname='%s', domain='%s', fqdn='%s.%s', target='%s'",
			containerName, hostname, domain, hostname, domain, target)
	}
	return entries
}

func (p *DockerProvider) extractDNSEntriesFromService(service swarm.Service) ([]DNSEntry, error) {
	var entries []DNSEntry
	labels := service.Spec.Labels
	if len(labels) == 0 {
		return entries, nil
	}
	serviceName := service.Spec.Name
	dnsEnabled := p.config.ExposeContainers // Default based on config setting

	if value, exists := labels["nfrastack.herald.enable"]; exists {
		explicitValue := strings.ToLower(value)
		if explicitValue == "true" || explicitValue == "1" {
			dnsEnabled = true
		} else if explicitValue == "false" || explicitValue == "0" {
			dnsEnabled = false
			p.logger.With("action", "input.filter", "service", serviceName).Debug("service '%s' has 'nfrastack.herald.enable=false' label, skipping", serviceName)
			return entries, nil // Return empty entries list
		}
	}

	if !dnsEnabled {
		return entries, nil
	}

	return entries, nil
}

func (p *DockerProvider) getServiceVIPs(service swarm.Service) []string {
	var vips []string

	if service.Endpoint.VirtualIPs != nil {
		for _, vip := range service.Endpoint.VirtualIPs {
			if strings.Contains(vip.Addr, "/") {
				ip := strings.Split(vip.Addr, "/")[0]
				vips = append(vips, ip)
			} else {
				vips = append(vips, vip.Addr)
			}
		}
	}

	return vips
}

func (dp *DockerProvider) GetName() string {
	return "docker"
}

func (dp *DockerProvider) GetContainerState(containerID string) (map[string]interface{}, error) {
	state := make(map[string]interface{})
	return state, nil
}
