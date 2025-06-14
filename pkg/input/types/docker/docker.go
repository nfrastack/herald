// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package docker

import (
	"herald/pkg/config"
	"herald/pkg/domain"
	"herald/pkg/input/common"
	"herald/pkg/log"
	"herald/pkg/output"

	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
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

// GetFQDN returns the fully qualified domain name
func (d DNSEntry) GetFQDN() string {
	return d.Name
}

// GetRecordType returns the DNS record type
func (d DNSEntry) GetRecordType() string {
	return d.RecordType
}

// ContainerInfo represents container information - local definition
type ContainerInfo struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	State  string            `json:"state"`
}

// DockerProvider implements the Provider interface for Docker
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
}

// Config defines configuration for the Docker provider
type Config struct {
	APIAuthPass      string `mapstructure:"api_auth_pass"`
	APIAuthUser      string `mapstructure:"api_auth_user"`
	APIURL           string `mapstructure:"api_url"`
	ExposeContainers bool   `mapstructure:"expose_containers"`
	ProcessExisting  bool   `mapstructure:"process_existing"`
	SwarmMode        bool   `mapstructure:"swarm_mode"`
}

// DockerContainerInfo holds information about a Docker container with labels
type DockerContainerInfo struct {
	Hostname   string
	ID         string
	Overwrite  bool
	RecordType string
	Target     string
	TTL        int
}

// GetID returns the container ID
func (c *DockerContainerInfo) GetID() string {
	return c.ID
}

// GetHostname returns the hostname for the container
func (c *DockerContainerInfo) GetHostname() string {
	return c.Hostname
}

// GetTarget returns the target for the DNS record
func (c *DockerContainerInfo) GetTarget() string {
	return c.Target
}

// extractHostsFromRule extracts all hostnames from a Traefik rule string
func extractHostsFromRule(rule string) []string {
	hosts := []string{}
	// Regex to match Host(`...`), Host('...'), or Host("...")
	re := regexp.MustCompile(`Host\(\s*['"` + "`" + `](.*?)['"` + "`" + `]\s*\)`)
	matches := re.FindAllStringSubmatch(rule, -1)
	for _, match := range matches {
		if len(match) > 1 {
			hosts = append(hosts, match[1])
		}
	}
	return hosts
}

// evaluateDockerFilter evaluates a single filter against a Docker container using conditions
func evaluateDockerFilter(filter common.Filter, entry any) bool {
	container, ok := entry.(types.ContainerJSON)
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

// evaluateDockerLabelFilter evaluates label-based filters
func evaluateDockerLabelFilter(filter common.Filter, container types.ContainerJSON) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	result := false
	for i, condition := range filter.Conditions {
		match := false

		if condition.Key != "" && condition.Value != "" {
			// Key-value pair matching
			if labelValue, exists := container.Config.Labels[condition.Key]; exists {
				match = common.WildcardMatch(condition.Value, labelValue)
			}
		} else if condition.Key != "" {
			// Key existence check
			_, match = container.Config.Labels[condition.Key]
		} else if condition.Value != "" {
			// Value search across all labels
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

// evaluateDockerNameFilter evaluates name-based filters
func evaluateDockerNameFilter(filter common.Filter, container types.ContainerJSON) bool {
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

// evaluateDockerImageFilter evaluates image-based filters
func evaluateDockerImageFilter(filter common.Filter, container types.ContainerJSON) bool {
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

// evaluateDockerNetworkFilter evaluates network-based filters
func evaluateDockerNetworkFilter(filter common.Filter, container types.ContainerJSON) bool {
	if len(filter.Conditions) == 0 {
		return true
	}

	result := false
	for i, condition := range filter.Conditions {
		match := false

		// Check all networks the container is connected to
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

// evaluateDockerHealthFilter evaluates health-based filters
func evaluateDockerHealthFilter(filter common.Filter, container types.ContainerJSON) bool {
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

// evaluateDockerStatusFilter evaluates status-based filters
func evaluateDockerStatusFilter(filter common.Filter, container types.ContainerJSON) bool {
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

// NewProvider creates a new Docker poll provider
func NewProvider(profileName string, config map[string]interface{}) (Provider, error) {
	// Convert interface{} config to string map for compatibility
	options := make(map[string]string)
	for k, v := range config {
		options[k] = fmt.Sprintf("%v", v)
	}
	// Convert string options to interface{} for structured parsing
	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	return NewProviderFromStructured(structuredOptions)
}

// NewProviderFromStructured creates a new Docker poll provider from structured options
func NewProviderFromStructured(options map[string]interface{}) (Provider, error) {
	// Parse the filter configuration BEFORE converting to strings to preserve structured data
	filterConfig, err := common.NewFilterFromStructuredOptions(options)
	if err != nil {
		log.Info("Error creating filter configuration: %v, using default", err)
		filterConfig = common.DefaultFilterConfig()
	}

	// Convert interface{} options to string options for compatibility with existing functions
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

	profileName := stringOptions["name"]
	if profileName == "" {
		profileName = stringOptions["profile_name"]
	}
	if profileName == "" {
		profileName = parsed.Name
	}
	logPrefix := common.BuildLogPrefix("docker", profileName)

	// Parse TLS configuration using common utilities for consistency
	tlsConfig := common.ParseTLSConfigFromOptions(stringOptions)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	// Log TLS configuration for consistency with other providers
	if tlsConfig.HasCustomCerts() {
		log.Debug("%s Custom TLS certificates configured (verify=%t)", logPrefix, tlsConfig.Verify)
	} else if !tlsConfig.Verify {
		log.Warn("%s TLS verification disabled - ensure your Docker daemon is secure", logPrefix)
	}

	// Create scoped logger using common helper
	scopedLogger := common.CreateScopedLogger("docker", profileName, stringOptions)

	// Log resolved profile name at trace level only
	scopedLogger.Trace("Resolved profile name: %s", profileName)

	// Setup Docker client options from environment or provided options
	clientOpts := []client.Opt{client.FromEnv}

	// Only use api_url and API_URL env var for Docker API endpoint
	apiURL := common.ReadFileValue(stringOptions["api_url"])
	if apiURL == "" {
		apiURL = "unix:///var/run/docker.sock"
	}
	if apiURL != "" {
		scopedLogger.Verbose("Using Docker API URL: %s", apiURL)
		clientOpts = append(clientOpts, client.WithHost(apiURL))
	}

	// Check for TLS options (nested under tls.*)
	var tlsVerifySet, tlsVerify bool
	if val, exists := stringOptions["tls.verify"]; exists {
		tlsVerifySet = true
		tlsVerify = strings.ToLower(val) == "true" || val == "1"
	}
	caPath := stringOptions["tls.ca"]
	certFile := stringOptions["tls.cert"]
	keyFile := stringOptions["tls.key"]

	if caPath != "" || certFile != "" || keyFile != "" || tlsVerifySet {
		// Only add CA if path exists
		if caPath != "" {
			clientOpts = append(clientOpts, client.WithTLSClientConfig(caPath, certFile, keyFile))
			scopedLogger.Debug("%s Using Docker TLS config: ca=%s cert=%s key=%s", logPrefix, caPath, certFile, keyFile)
		}
		// If tlsVerify is explicitly set to false, skip server verification (not recommended)
		if tlsVerifySet && !tlsVerify {
			clientOpts = append(clientOpts, client.WithTLSClientConfig("", "", ""))
			scopedLogger.Warn("%s Docker TLS verification is disabled! Not recommended for production.", logPrefix)
		}
	}

	// Parse API auth options
	apiAuthUser := common.ReadFileValue(stringOptions["api_auth_user"])
	apiAuthPass := common.ReadFileValue(stringOptions["api_auth_pass"])
	if apiAuthUser != "" {
		scopedLogger.Debug("%s Using Docker API basic auth user: %s", logPrefix, apiAuthUser)
		if apiAuthPass != "" {
			scopedLogger.Debug("%s Docker API basic auth password is set (masked)", logPrefix)
		} else {
			scopedLogger.Warn("%s Docker API basic auth user provided without password", logPrefix)
		}
	}

	// Create Docker client with options
	client, err := client.NewClientWithOpts(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Create provider with default config
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
	}

	// Parse configuration
	var config Config

	// Default values
	config.APIAuthPass = apiAuthPass
	config.APIAuthUser = apiAuthUser
	config.APIURL = apiURL
	config.ExposeContainers = false
	config.ProcessExisting = parsed.ProcessExisting
	config.SwarmMode = false

	// Log all available options for debugging
	scopedLogger.Trace("%s Provider options received: %v", logPrefix, options)

	// Check if we should expose all containers by default from options
	if val, exists := options["expose_containers"]; exists {
		if strVal, ok := val.(string); ok {
			lowerVal := strings.ToLower(strVal)
			config.ExposeContainers = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
			scopedLogger.Trace("%s Option 'expose_containers' found with value: '%s', parsed as: %v",
				logPrefix, strVal, config.ExposeContainers)
		}
	} else {
		scopedLogger.Trace("%s No 'expose_containers' option found, using default: %v",
			logPrefix, config.ExposeContainers)
	}

	// Check if we're running in Swarm mode
	if val, exists := options["swarm_mode"]; exists {
		if strVal, ok := val.(string); ok {
			lowerVal := strings.ToLower(strVal)
			config.SwarmMode = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
			log.Trace("%s Option 'swarm_mode' found with value: '%s', parsed as: %v",
				logPrefix, strVal, config.SwarmMode)
		}
	} else {
		log.Trace("%s No 'swarm_mode' option found, using default: %v",
			logPrefix, config.SwarmMode)
	}

	// Parse process_existing from options or env
	if val, exists := options["process_existing"]; exists {
		if strVal, ok := val.(string); ok {
			config.ProcessExisting = strings.ToLower(strVal) == "true" || strVal == "1"
			log.Trace("%s Option 'process_existing' found with value: '%s', parsed as: %v",
				logPrefix, strVal, config.ProcessExisting)
		}
	} else {
		envKey := fmt.Sprintf("POLL_%s_PROCESS_EXISTING", strings.ToUpper(profileName))
		if envVal := os.Getenv(envKey); envVal != "" {
			config.ProcessExisting = strings.ToLower(envVal) == "true" || envVal == "1"
			log.Trace("%s Using process_existing from environment variable %s: %v", logPrefix, envKey, config.ProcessExisting)
		}
	}

	// Create filter configuration with Docker-specific handling
	// Filter config was already parsed at the beginning to preserve structured data
	// filterConfig is already available from the top of the function

	// Store the config and filter config in the provider
	provider.config = config
	provider.filterConfig = filterConfig

	// Use shared connection manager instead of individual connections
	connectionManager := GetConnectionManager()
	sharedConn, err := connectionManager.GetOrCreateConnection(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get shared connection: %w", err)
	}

	// Store reference to shared connection
	provider.sharedConnection = sharedConn
	provider.swarmMode = config.SwarmMode
	provider.exposeContainers = config.ExposeContainers
	provider.recordRemoveOnStop = parsed.RecordRemoveOnStop

	// Debug: Log the actual filter configuration
	log.Debug("%s Created filter config with %d filters", logPrefix, len(filterConfig.Filters))
	for i, filter := range filterConfig.Filters {
		log.Debug("%s Filter %d: Type='%s', Value='%s', Operation='%s', Negate=%v, Conditions=%d",
			logPrefix, i, filter.Type, filter.Value, filter.Operation, filter.Negate, len(filter.Conditions))
		for j, condition := range filter.Conditions {
			log.Debug("%s   Condition %d: Key='%s', Value='%s', Logic='%s'",
				logPrefix, j, condition.Key, condition.Value, condition.Logic)
		}
	}

	// Log active filter details for user awareness in verbose mode
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
			log.Verbose("%s Active filter: %s", logPrefix, filterDescription.String())
		}
	} else {
		log.Verbose("%s Active filter: none (all containers will be processed)", logPrefix)
	}

	// Parse record_remove_on_stop option is already handled above in provider.recordRemoveOnStop

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
	log.Info("%s Provider '%s' created: filters=%s, expose_containers=%v, swarm_mode=%v, process_existing=%v, record_remove_on_stop=%v",
		logPrefix, "docker", filterSummary, config.ExposeContainers, config.SwarmMode, config.ProcessExisting, provider.recordRemoveOnStop)

	return provider, nil
}

// Remove the NewProviderFromConfig function since we don't need it with factory pattern

// IsRunning checks if the provider is running
func (p *DockerProvider) IsRunning() bool {
	return p.running
}

// handleContainerEventFiltered processes Docker container events with filtering
func (p *DockerProvider) handleContainerEventFiltered(ctx context.Context, event events.Message) {
	// Apply provider-specific filtering before processing
	containerName := event.Actor.Attributes["name"]
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// For proper filtering, we need to inspect the container to get full details
	// Only do this for 'start' events to avoid unnecessary API calls
	if event.Action == "start" {
		container, err := p.client.ContainerInspect(ctx, event.Actor.ID)
		if err != nil {
			p.logger.Debug("Failed to inspect container '%s' for filtering: %v", containerName, err)
			return
		}

		// Apply filtering to determine if this provider should handle this container
		if !p.shouldProcessContainer(container) {
			p.logger.Debug("Container '%s' filtered out by provider '%s'", containerName, p.profileName)
			return
		}
	}

	// Pass to the original handler
	p.handleContainerEvent(ctx, event)
}

// handleServiceEventFiltered processes Docker Swarm service events with filtering
func (p *DockerProvider) handleServiceEventFiltered(ctx context.Context, event events.Message) {
	// Apply provider-specific filtering if needed
	// For now, pass through to original handler
	p.handleServiceEvent(ctx, event)
}

// StopPolling stops the Docker provider polling
func (p *DockerProvider) StopPolling() error {
	if !p.running {
		return nil
	}

	p.running = false

	// Remove this provider from the shared connection
	connectionManager := GetConnectionManager()
	connectionManager.RemoveProvider(p)

	return nil
}

// SetDNSProvider is no longer needed - removed old dns package dependency
// func (p *DockerProvider) SetDNSProvider(provider dns.Provider) {
//     p.dnsProvider = provider
// }

// Add SetDomainConfigs method
func (p *DockerProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

// StartPolling starts watching Docker events for container changes
func (p *DockerProvider) StartPolling() error {
	// Use shared connection for event streaming
	if p.sharedConnection == nil {
		return fmt.Errorf("no shared connection available")
	}

	// Start shared event streaming (will only start once per connection)
	if err := p.sharedConnection.StartEventStreaming(); err != nil {
		return fmt.Errorf("failed to start shared event streaming: %w", err)
	}

	p.running = true

	// Process existing containers/services if configured
	if p.config.ProcessExisting {
		log.Verbose("%s Processing existing containers and services", p.logPrefix)
		go p.processRunningContainers(context.Background())

		if p.swarmMode {
			go p.processRunningServices(context.Background())
		}
	} else {
		log.Info("%s Waiting for new containers/services", p.logPrefix)
	}

	return nil
}

// handleContainerEvent processes Docker container events
func (p *DockerProvider) handleContainerEvent(ctx context.Context, event events.Message) {
	// Only process container events
	if event.Type != "container" {
		return
	}

	containerID := event.Actor.ID
	containerName := event.Actor.Attributes["name"]
	if containerName == "" {
		containerName = containerID[:12]
	}

	// Remove slash prefix from container name if present
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// Note: Logging is now handled by the shared connection manager
	// to avoid duplicate log messages

	// Process based on event action
	switch event.Action {
	case "start", "unpause":
		// Container started - process only this specific container
		p.logger.Info("Container started: %s (%s), processing DNS records for this container only", containerName, event.Actor.ID[:12])
		p.processSpecificContainer(event.Actor.ID)
	case "stop", "pause", "die", "kill":
		// Container stopped - remove its DNS records only
		p.logger.Info("Container stopped: %s (%s), removing DNS records for this container only", containerName, event.Actor.ID[:12])
		p.removeContainerRecords(event.Actor.ID)
	case "destroy":
		// Container destroyed - clean up any remaining records
		p.logger.Debug("Container destroyed: %s (%s)", containerName, event.Actor.ID[:12])
		p.removeContainerRecords(event.Actor.ID)
	default:
		p.logger.Trace("Ignoring event %s for container %s (%s)", event.Action, containerName, event.Actor.ID[:12])
	}
}

// handleServiceEvent processes Docker Swarm service events
func (p *DockerProvider) handleServiceEvent(ctx context.Context, event events.Message) {
	// Only process service events
	if event.Type != "service" {
		return
	}

	serviceID := event.Actor.ID
	serviceName := event.Actor.Attributes["name"]
	if serviceName == "" {
		serviceName = serviceID[:12]
	}

	// Note: Logging is now handled by the shared connection manager
	// to avoid duplicate log messages

	// Process based on event action
	switch event.Action {
	case "create", "update":
		// Service created or updated - check for DNS entries
		p.processService(ctx, serviceID)
	case "remove":
		// Service removed - remove DNS entries for this service
		service, _, err := p.client.ServiceInspectWithRaw(ctx, serviceID, types.ServiceInspectOptions{})
		if err != nil {
			log.Warn("%s Failed to inspect service '%s' for DNS removal: '%v'", p.logPrefix, serviceName, err)
			return
		}
		entries, err := p.extractDNSEntriesFromService(service)
		if err != nil {
			log.Warn("%s Failed to extract DNS entries from service '%s' for removal: %v", p.logPrefix, serviceName, err)
			return
		}
		if len(entries) > 0 {
			log.Info("%s Removing %d DNS entries for service %s", p.logPrefix, len(entries), serviceName)
			p.processDNSEntries(entries, true)
		} else {
			log.Debug("%s No DNS entries found for service '%s' to remove", p.logPrefix, serviceName)
		}
	}
}

// processSpecificContainer processes DNS records for a single container
func (p *DockerProvider) processSpecificContainer(containerID string) {
	ctx := context.Background()

	// Get the specific container
	container, err := p.client.ContainerInspect(ctx, containerID)
	if err != nil {
		p.logger.Error("Failed to inspect container %s: %v", containerID[:12], err)
		return
	}

	containerName := getContainerName(container)
	p.logger.Debug("Processing specific container: %s (%s)", containerName, containerID[:12])

	// Check if container is running and should be processed
	if container.State.Running && p.shouldProcessContainer(container) {
		// Process this container's DNS records
		p.processContainer(ctx, containerID)
	} else {
		p.logger.Debug("Container %s filtered out or not running, skipping", containerID[:12])
	}
}

// removeContainerRecords removes DNS records for a specific container
func (p *DockerProvider) removeContainerRecords(containerID string) {
	ctx := context.Background()

	// Get container info for hostname extraction
	container, err := p.client.ContainerInspect(ctx, containerID)
	if err != nil {
		p.logger.Debug("Could not inspect container %s for cleanup: %v", containerID[:12], err)
		// Container might already be gone, continue with what we know
		return
	}

	containerName := getContainerName(container)
	p.logger.Debug("Removing DNS records for container: %s (%s)", containerName, containerID[:12])

	// Extract DNS entries that would have been created for this container
	entries := p.extractDNSEntriesFromContainer(container)

	if len(entries) > 0 {
		p.logger.Info("Removing %d DNS entries for container %s", len(entries), containerName)
		// Process removal of DNS entries
		p.processDNSEntries(entries, true)
	} else {
		p.logger.Debug("No DNS entries found for container %s cleanup", containerName)
	}
}

// processRunningContainers processes all currently running containers
func (p *DockerProvider) processRunningContainers(ctx context.Context) {
	// List containers
	containers, err := p.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		log.Error("%s Failed to list containers: %v", p.logPrefix, err)
		return
	}

	log.Info("%s Found %d containers", p.logPrefix, len(containers))

	// Track how many containers actually get processed
	processedCount := 0

	// Process each container
	for _, container := range containers {
		// Get container details for filtering
		containerDetails, err := p.client.ContainerInspect(ctx, container.ID)
		if err != nil {
			log.Warn("%s Failed to inspect container '%s': %v", p.logPrefix, container.ID[:12], err)
			continue
		}

		// Check if container should be processed
		if p.shouldProcessContainer(containerDetails) {
			processedCount++
			p.processContainer(ctx, container.ID)
		}
	}

	if processedCount != len(containers) {
		log.Verbose("%s Processed %d of %d containers (filtered %d)",
			p.logPrefix, processedCount, len(containers), len(containers)-processedCount)
	}
}

// processRunningServices processes all currently running Swarm services
func (p *DockerProvider) processRunningServices(ctx context.Context) {
	if !p.swarmMode {
		log.Debug("%s Not in swarm mode, skipping service processing", p.logPrefix)
		return
	}

	log.Info("%s Processing running services (swarm mode)", p.logPrefix)

	// List services
	services, err := p.client.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		log.Error("%s Failed to list services: %v", p.logPrefix, err)
		return
	}

	log.Verbose("%s Found %d services", p.logPrefix, len(services))

	// Process each service
	for _, service := range services {
		p.processService(ctx, service.ID)
	}
}

// shouldProcessContainer determines if the container should be processed based on labels and configuration
func (p *DockerProvider) shouldProcessContainer(container types.ContainerJSON) bool {
	// Ensure container name doesn't have slash prefix
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// First, check if the container passes our filter configuration
	if !p.filterConfig.Evaluate(container, evaluateDockerFilter) {
		p.logger.Debug("Skipping container '%s' because it does not match filter criteria", containerName)
		return false
	}

	// Check if the container has the nfrastack.dns.enable label
	enableDNS, hasLabel := container.Config.Labels["nfrastack.dns.enable"]

	// If the label is explicitly set to "false", always skip the container
	if hasLabel && (strings.ToLower(enableDNS) == "false" || enableDNS == "0") {
		p.logger.Verbose("Skipping container '%s' because it has an explicit 'nfrastack.dns.enable=false' label", containerName)
		return false
	}

	// If expose_containers is true, process all containers unless explicitly disabled above
	if p.config.ExposeContainers {
		p.logger.Debug("Processing container '%s' because 'expose_containers=true' in config", containerName)
		return true
	}

	// If expose_containers is false and no label exists, skip the container due to config
	if !hasLabel {
		p.logger.Debug("Skipping container '%s' because 'expose_containers=false' in config and no 'nfrastack.dns.enable' label exists", containerName)
		return false
	}

	// If expose_containers is false but label exists and is true, process the container
	if strings.ToLower(enableDNS) == "true" || enableDNS == "1" {
		p.logger.Verbose("Processing container '%s' because it has 'nfrastack.dns.enable=true' label (overriding expose_containers=false)", containerName)
		return true
	}

	// If we get here, label exists but is not true or false (some other value)
	p.logger.Warn("Skipping container '%s' because it has 'nfrastack.dns.enable=%s' (not 'true') and 'expose_containers=false'", containerName, enableDNS)
	return false
}

// processContainer processes a single container for DNS entries
func (p *DockerProvider) processContainer(ctx context.Context, containerID string) {
	// Get container details
	container, err := p.client.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Warn("%s Failed to inspect container '%s': %v", p.logPrefix, containerID[:12], err)
		return
	}

	// Ensure container name doesn't have slash prefix
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// Extract DNS entries for this container
	if !p.shouldProcessContainer(container) {
		p.logger.Debug("%s Container '%s' filtered out", p.logPrefix, containerName)
		return
	}

	entries := p.extractDNSEntriesFromContainer(container)

	// If we found DNS entries, process them
	if len(entries) > 0 {
		p.processDNSEntries(entries, false)
	}
}

// processService processes a single Swarm service for DNS entries
func (p *DockerProvider) processService(ctx context.Context, serviceID string) {
	if !p.swarmMode {
		return
	}

	// Get service details
	service, _, err := p.client.ServiceInspectWithRaw(ctx, serviceID, types.ServiceInspectOptions{})
	if err != nil {
		log.Warn("%s Failed to inspect service %s: %v", p.logPrefix, serviceID[:12], err)
		return
	}

	serviceName := service.Spec.Name

	// Extract DNS entries for this service
	entries, err := p.extractDNSEntriesFromService(service)
	if err != nil {
		log.Warn("%s Failed to extract DNS entries from service %s: %v", p.logPrefix, serviceName, err)
	}

	// If we found DNS entries, process them
	if len(entries) > 0 {
		log.Verbose("%s Found %d DNS entries for service %s", p.logPrefix, len(entries), serviceName)
		p.processDNSEntries(entries, false)
	} else {
		log.Debug("%s No DNS entries found for service %s", p.logPrefix, serviceName)
	}
}

// processDNSEntries sends DNS entries to the DNS provider using batch processing
// If remove is true, perform DNS removal, otherwise always create/update
func (p *DockerProvider) processDNSEntries(entries []DNSEntry, remove bool) error {
	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(p.logPrefix)

	for _, entry := range entries {
		// Construct FQDN from the entry
		var fqdn string
		if entry.Hostname == "@" || entry.Hostname == "" {
			fqdn = entry.Domain
		} else {
			fqdn = entry.Hostname + "." + entry.Domain
		}

		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		domainKey, subdomain := config.ExtractDomainAndSubdomainForProvider(fqdnNoDot, p.profileName, p.logPrefix)
		p.logger.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s'", p.logPrefix, domainKey, subdomain, fqdnNoDot)
		if domainKey == "" {
			p.logger.Error("%s No domain config found for '%s' (tried to match domain from FQDN)", p.logPrefix, fqdnNoDot)
			continue
		}
		domainCfg, ok := config.GlobalConfig.Domains[domainKey]
		if !ok {
			p.logger.Error("%s Domain '%s' not found in config for fqdn='%s'", p.logPrefix, domainKey, fqdnNoDot)
			continue
		}
		realDomain := domainCfg.Name
		p.logger.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s')", p.logPrefix, realDomain, domainKey)

		state := domain.RouterState{
			SourceType: "docker",
			Name:       p.profileName,
			Service:    entry.Target,
			RecordType: entry.RecordType,
		}

		// Construct the proper FQDN for BatchProcessor
		var fqdnForBatch string
		if subdomain == "@" {
			fqdnForBatch = realDomain
		} else {
			fqdnForBatch = subdomain + "." + realDomain
		}

		var err error
		if remove {
			p.logger.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnForBatch, state)
			err = batchProcessor.ProcessRecordRemoval(realDomain, fqdnForBatch, state)
		} else {
			p.logger.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnForBatch, state)
			err = batchProcessor.ProcessRecord(realDomain, fqdnForBatch, state)
		}

		if err != nil {
			action := "ensure"
			if remove {
				action = "remove"
			}
			p.logger.Error("%s Failed to %s DNS for '%s': %v", p.logPrefix, action, fqdnNoDot, err)
		}
	}

	// Use source-specific syncing to avoid syncing other providers' changes
	p.logger.Debug("Syncing output files after processing changes")
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		// Use source-specific sync to avoid syncing other providers' changes
		err := outputManager.SyncAllFromSource(p.profileName)
		if err != nil {
			p.logger.Error("Failed to sync output files: %v", err)
		}
	}

	// Finalize the batch - this will sync output files only if there were changes
	batchProcessor.FinalizeBatch()
	return nil
}

// GetDNSEntries returns all DNS entries from all containers
func (p *DockerProvider) GetDNSEntries() ([]DNSEntry, error) {
	ctx := context.Background()

	// List containers
	containers, err := p.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []DNSEntry

	// Process each container
	for _, c := range containers {
		// Skip containers that aren't running
		if c.State != "running" {
			continue
		}

		// Get container details
		container, err := p.client.ContainerInspect(ctx, c.ID)
		if err != nil {
			log.Warn("%s Failed to inspect container '%s': %v", p.logPrefix, c.ID[:12], err)
			continue
		}

		// Extract DNS entries from this container
		entries := p.extractDNSEntriesFromContainer(container)
		result = append(result, entries...)
	}

	log.Info("%s Found %d DNS entries from all containers", p.logPrefix, len(result))

	return result, nil
}

// GetContainersForDomain returns containers with DNS entries for the given domain
func (p *DockerProvider) GetContainersForDomain(domain string) ([]ContainerInfo, error) {
	ctx := context.Background()

	// List containers
	containers, err := p.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []ContainerInfo

	// Process each container
	for _, c := range containers {
		// Skip containers that aren't running
		if c.State != "running" {
			continue
		}

		// Get container details
		container, err := p.client.ContainerInspect(ctx, c.ID)
		if err != nil {
			log.Warn("%s Failed to inspect container '%s': %v", p.logPrefix, c.ID[:12], err)
			continue
		}

		// Check if the container has the DNS configuration
		labels := container.Config.Labels

		// Logic for nfrastack.dns.enable based on expose_containers config
		enableDNS := false
		if dnsEnable, ok := labels["nfrastack.dns.enable"]; ok {
			// Explicitly set in labels
			enableDNS = strings.ToLower(dnsEnable) == "true"
		} else if p.config.ExposeContainers {
			// If expose_containers = true, assume enabled unless explicitly disabled
			enableDNS = true
		}
		// If expose_containers = false and no label, enableDNS remains false

		if !enableDNS {
			continue
		}

		// Container is enabled for DNS, process the rest of the labels
		dnsEntries := p.extractDNSInfoFromContainerForDomain(container, domain)
		for _, entry := range dnsEntries {
			// Convert DockerContainerInfo to local ContainerInfo
			containerInfo := ContainerInfo{
				ID:     entry.ID,
				Name:   entry.Hostname,
				State:  "running",
				Labels: container.Config.Labels,
			}
			result = append(result, containerInfo)
		}
	}

	log.Info("%s Found %d containers with DNS entries for domain %s",
		p.logPrefix, len(result), domain)

	return result, nil
}

// extractDNSInfoFromContainerForDomain extracts DNS information from container for a specific domain
func (p *DockerProvider) extractDNSInfoFromContainerForDomain(container types.ContainerJSON, domain string) []*DockerContainerInfo {
	var entries []*DockerContainerInfo

	// Get container labels
	labels := container.Config.Labels
	if len(labels) == 0 {
		return entries
	}

	// Check if this container should be registered for the given domain
	shouldRegister := false
	hostnames := []string{}

	// Check through nfrastack.dns.host label for the domain
	if hostLabel, exists := labels["nfrastack.dns.host"]; exists && hostLabel != "" {
		// Support multiple hostnames separated by comma or space
		splitFunc := func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n'
		}
		for _, host := range strings.FieldsFunc(hostLabel, splitFunc) {
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				hostDomain := strings.Join(parts[len(parts)-2:], ".")
				if hostDomain == domain {
					shouldRegister = true
					// Extract hostname from host label (everything before domain)
					hostname := "@"
					if len(parts) > 2 {
						hostname = strings.Join(parts[:len(parts)-2], ".")
					}
					hostnames = append(hostnames, hostname)
				}
			}
		}
	}

	// Also check Traefik rules for Host entries
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
							// Extract hostname from host (everything before domain)
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

	// Get record type from label or default
	recordType := ""
	if rt, exists := labels["nfrastack.dns.record.type"]; exists && rt != "" {
		recordType = rt
	}

	// Get target from label or default to container IP
	target := ""
	if t, exists := labels["nfrastack.dns.target"]; exists && t != "" {
		target = t
	}

	// Skip if we don't have a target
	if target == "" {
		log.Warn("%s container '%s' has no target for domain %s (no label set)",
			p.logPrefix, container.ID[:12], domain)
		return entries
	}

	// Get TTL from label or default
	ttl := 0 // No default TTL
	if ttlStr, exists := labels["nfrastack.dns.record.ttl"]; exists && ttlStr != "" {
		parsed, err := strconv.Atoi(ttlStr)
		if err == nil {
			ttl = parsed
		}
	}

	// Check for overwrite flag
	overwrite := false // No default overwrite
	if overwriteStr, exists := labels["nfrastack.dns.record.overwrite"]; exists {
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

// getContainerName returns the most descriptive container name possible
func getContainerName(container types.ContainerJSON) string {
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}
	return containerName
}

// Helper for wildcard matching
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

// extractDNSEntriesFromContainer extracts DNS entries from a Docker container
func (p *DockerProvider) extractDNSEntriesFromContainer(container types.ContainerJSON) []DNSEntry {
	log.Trace("%s domainConfigs map at entry: %v", p.logPrefix, p.domainConfigs)

	var entries []DNSEntry
	containerName := getContainerName(container)
	labels := container.Config.Labels
	if len(labels) == 0 {
		return entries
	}

	// Check for nfrastack.dns.enable label
	dnsLabel, hasDNSLabel := labels["nfrastack.dns.enable"]
	if hasDNSLabel {
		val := strings.ToLower(dnsLabel)
		if val == "false" || val == "0" {
			log.Verbose("%s Skipping container '%s' due to 'nfrastack.dns.enable' label set to false", p.logPrefix, containerName)
			return entries
		}
		if val == "true" || val == "1" {
			log.Verbose("%s DNS enabled for container '%s' due to label override", p.logPrefix, containerName)
			// continue processing
		} else {
			log.Warn("%s Skipping container '%s' due to 'nfrastack.dns.enable' label set to unknown value '%s'", p.logPrefix, containerName, dnsLabel)
			return entries
		}
	} else if !p.config.ExposeContainers {
		log.Debug("%s Skipping container '%s' because 'expose_containers=false' and no 'nfrastack.dns.enable' label is set", p.logPrefix, containerName)
		return entries
	}

	// 2. Hostname/domain extraction
	var hostSource, hostValue string
	if v, ok := labels["nfrastack.dns.host"]; ok && v != "" {
		hostSource = "nfrastack.dns.host"
		hostValue = v
	} else {
		for k, v := range labels {
			if strings.HasPrefix(k, "traefik.http.routers.") && strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
				hosts := extractHostsFromRule(v)
				for _, host := range hosts {
					hostValue = host
					hostSource = k
					break
				}
			}
		}
	}
	if hostValue == "" {
		log.Debug("%s No hostname/domain found for container '%s', skipping", p.logPrefix, containerName)
		return entries
	}
	log.Verbose("%s Using label '%s=%s' for hostname/domain extraction on container '%s'", p.logPrefix, hostSource, hostValue, containerName)

	// Extract domain from FQDN - handle cases where FQDN might be just a hostname
	if !strings.Contains(hostValue, ".") {
		log.Debug("%s Host value '%s' has no domain part (no dots found), skipping container '%s'", p.logPrefix, hostValue, containerName)
		return entries
	}

	parts := strings.Split(hostValue, ".")
	if len(parts) < 2 {
		log.Debug("%s Host value '%s' does not have enough parts for domain extraction, skipping container '%s'", p.logPrefix, hostValue, containerName)
		return entries
	}

	domain := strings.Join(parts[len(parts)-2:], ".")
	hostname := strings.Join(parts[:len(parts)-2], ".")
	if hostname == "" {
		hostname = "@"
	}

	log.Debug("%s Extracted from FQDN '%s': hostname='%s', domain='%s'", p.logPrefix, hostValue, hostname, domain)

	if domain == "" {
		log.Error("%s No domain extracted from FQDN '%s', skipping container '%s'", p.logPrefix, hostValue, containerName)
		return entries
	}

	// Use the provider-aware domain extraction method instead of manual lookup
	domainConfigKey, subdomain := config.ExtractDomainAndSubdomainForProvider(hostValue, p.profileName, p.logPrefix)
	if domainConfigKey == "" {
		log.Error("%s No domain config found for FQDN '%s', skipping container '%s'", p.logPrefix, hostValue, containerName)
		return entries
	}

	log.Debug("%s Found matching domain config '%s' for domain '%s'", p.logPrefix, domainConfigKey, domain)

	// Get the actual domain config from GlobalConfig
	domainCfg, exists := config.GlobalConfig.Domains[domainConfigKey]
	if !exists {
		log.Error("%s Domain config '%s' not found in global config", p.logPrefix, domainConfigKey)
		return entries
	}

	// Use the domain name from the config, not the extracted one
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
			log.Verbose("%s Skipping subdomain '%s' for domain '%s' (not in include_subdomains)", p.logPrefix, subdomain, domain)
			return entries
		}
	} else if len(domainCfg.ExcludeSubdomains) > 0 {
		if matchesPattern(subdomain, domainCfg.ExcludeSubdomains) {
			log.Verbose("%s Skipping subdomain '%s' for domain '%s' (in exclude_subdomains)", p.logPrefix, subdomain, domain)
			return entries
		}
	}

	// 3. Other nfrastack.dns.* labels and config precedence
	recordType := ""
	if rt, exists := labels["nfrastack.dns.record.type"]; exists && rt != "" {
		recordType = rt
		log.Verbose("%s Found label 'nfrastack.dns.record.type=%s' on container '%s'", p.logPrefix, rt, containerName)
	}
	target := ""
	if t, exists := labels["nfrastack.dns.target"]; exists && t != "" {
		target = t
		log.Verbose("%s Found label 'nfrastack.dns.target=%s' on container '%s'", p.logPrefix, t, containerName)
	}
	ttl := 0
	if ttlStr, exists := labels["nfrastack.dns.record.ttl"]; exists && ttlStr != "" {
		if parsed, err := strconv.Atoi(ttlStr); err == nil {
			log.Verbose("%s Found label nfrastack.dns.record.ttl=%s on container '%s'", p.logPrefix, ttlStr, containerName)
			ttl = parsed
		}
	}
	overwrite := false
	if overwriteStr, exists := labels["nfrastack.dns.record.overwrite"]; exists {
		if strings.ToLower(overwriteStr) == "true" || overwriteStr == "1" {
			log.Verbose("%s Found label 'nfrastack.dns.record.overwrite=%s' on container '%s'", p.logPrefix, overwriteStr, containerName)
			overwrite = true
		}
	}

	// Per-container overrides for multiple A/AAAA record support
	recordTypeAMultiple := false
	if val, exists := labels["nfrastack.dns.record.type.a.multiple"]; exists && val != "" {
		recordTypeAMultiple = strings.ToLower(val) == "true" || val == "1"
		log.Verbose("%s Found label 'nfrastack.dns.record.type.a.multiple=%s' on container '%s'", p.logPrefix, val, containerName)
	}
	recordTypeAAAAMultiple := false
	if val, exists := labels["nfrastack.dns.record.type.aaaa.multiple"]; exists && val != "" {
		recordTypeAAAAMultiple = strings.ToLower(val) == "true" || val == "1"
		log.Verbose("%s Found label 'nfrastack.dns.record.type.aaaa.multiple=%s' on container '%s'", p.logPrefix, val, containerName)
	}

	// Domain config fallback
	if p.domainConfigs != nil {
		for _, domainCfg := range p.domainConfigs {
			if domainCfg.Name == domain {
				if target == "" && domainCfg.Record.Target != "" {
					log.Trace("%s Using domain config for '%s': value: 'target=%s'", p.logPrefix, domain, domainCfg.Record.Target)
					target = domainCfg.Record.Target
				}
				if recordType == "" && domainCfg.Record.Type != "" {
					log.Trace("%s Using domain config for '%s': value: 'record_type=%s'", p.logPrefix, domain, domainCfg.Record.Type)
					recordType = domainCfg.Record.Type
				}
				if ttl == 0 && domainCfg.Record.TTL > 0 {
					log.Trace("%s Using domain config for '%s': value: 'ttl=%d'", p.logPrefix, domain, domainCfg.Record.TTL)
					ttl = domainCfg.Record.TTL
				}
				if !overwrite && domainCfg.Record.UpdateExisting {
					log.Trace("%s Using domain config for '%s': value: 'record_update_existing=true'", p.logPrefix, domain)
					overwrite = true
				}
				break
			}
		}
	} else {
		log.Trace("%s No domain configs available for fallback", p.logPrefix)
	}

	// Global config fallback (if still unset)
	if target == "" && p.options != nil {
		if globalTarget, ok := p.options["dns_record_target"]; ok {
			if strTarget, ok := globalTarget.(string); ok && strTarget != "" {
				log.Debug("%s Using global config for '%s': value: 'target=%s'", p.logPrefix, domain, strTarget)
				target = strTarget
			}
		}
	}
	if recordType == "" && p.options != nil {
		if globalType, ok := p.options["dns_record_type"]; ok {
			if strType, ok := globalType.(string); ok && strType != "" {
				log.Debug("%s Using global config for '%s': value: 'dns_record_type %s'", p.logPrefix, domain, strType)
				recordType = strType
			}
		}
	}
	if ttl == 0 && p.options != nil {
		if globalTTL, ok := p.options["dns_record_ttl"]; ok {
			if strTTL, ok := globalTTL.(string); ok && strTTL != "" {
				if parsed, err := strconv.Atoi(strTTL); err == nil {
					log.Debug("%s Using global config for '%s': value: 'dns_record_ttl=%d'", p.logPrefix, domain, parsed)
					ttl = parsed
				}
			}
		}
	}
	if !overwrite && p.options != nil {
		if globalOverwrite, ok := p.options["record_updating_existing"]; ok {
			if strOverwrite, ok := globalOverwrite.(string); ok && (strOverwrite == "true" || strOverwrite == "1") {
				log.Debug("%s Using global config for '%s': value: 'record_update_existing=true'", p.logPrefix, domain)
				overwrite = true
			}
		}
	}

	// --- AAAA record support and smart detection ---
	// If recordType is not set, auto-detect based on target
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

	// Validate target for A and AAAA records
	if recordType == "A" && target != "" {
		if ip := net.ParseIP(target); ip == nil || ip.To4() == nil {
			log.Error("%s Invalid target for A record: '%s' is not an IPv4 address. Skipping DNS entry '%s.%s'", p.logPrefix, target, hostname, domain)
			return entries
		}
	}
	if recordType == "AAAA" && target != "" {
		if ip := net.ParseIP(target); ip == nil || ip.To16() == nil || ip.To4() != nil {
			log.Error("%s Invalid target for AAAA record: '%s' is not an IPv6 address. Skipping DNS entry '%s.%s'", p.logPrefix, target, hostname, domain)
			return entries
		}
	}

	if target == "" {
		log.Warn("%s container '%s' has no target for domain '%s' (no label, domain, or global config set)", p.logPrefix, containerName, domain)
		return entries
	}

	// Construct the full FQDN for the Name field
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

	log.Trace("%s Created DNS entry for container '%s': hostname='%s', domain='%s', fqdn='%s.%s', target='%s'",
		p.logPrefix, containerName, hostname, domain, hostname, domain, target)

	return entries
}

// extractDNSEntriesFromService extracts all DNS entries from a Swarm service
func (p *DockerProvider) extractDNSEntriesFromService(service swarm.Service) ([]DNSEntry, error) {
	var entries []DNSEntry
	labels := service.Spec.Labels
	if len(labels) == 0 {
		return entries, nil
	}
	serviceName := service.Spec.Name
	// Check if DNS is explicitly enabled or disabled
	dnsEnabled := p.config.ExposeContainers // Default based on config setting

	// Check for explicit setting from service labels
	if value, exists := labels["nfrastack.dns.enable"]; exists {
		explicitValue := strings.ToLower(value)
		if explicitValue == "true" || explicitValue == "1" {
			dnsEnabled = true
		} else if explicitValue == "false" || explicitValue == "0" {
			dnsEnabled = false
			log.Debug("%s Service '%s' has 'nfrastack.dns.enable=false' label, skipping", p.logPrefix, serviceName)
			return entries, nil // Return empty entries list
		}
	}

	// If not enabled, skip processing
	if !dnsEnabled {
		return entries, nil
	}

	// The rest of the function remains unchanged
	return entries, nil
}

// getServiceVIPs gets the virtual IP addresses for a service
func (p *DockerProvider) getServiceVIPs(service swarm.Service) []string {
	var vips []string

	// Check if the service has VIPs attached to it
	if service.Endpoint.VirtualIPs != nil {
		for _, vip := range service.Endpoint.VirtualIPs {
			// Format is like "10.0.0.1/24", we need to extract just the IP
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

// GetName returns the provider name
func (dp *DockerProvider) GetName() string {
	return "docker"
}

// GetContainerState returns container state information
func (dp *DockerProvider) GetContainerState(containerID string) (map[string]interface{}, error) {
	// Implementation for container state retrieval
	state := make(map[string]interface{})
	// Add your container state logic here
	return state, nil
}
