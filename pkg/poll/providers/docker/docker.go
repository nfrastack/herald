// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package docker

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/dns"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"
	"dns-companion/pkg/utils"

	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	dfilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
)

// DockerProvider implements the Provider interface for Docker
type DockerProvider struct {
	apiAuthPass        string
	apiAuthUser        string
	client             *client.Client
	config             Config
	dnsProvider        dns.Provider
	domainConfigs      map[string]config.DomainConfig
	exposeContainers   bool
	filterConfig       pollCommon.FilterConfig
	lastContainerIDs   map[string]bool
	logPrefix          string
	options            map[string]string
	profileName        string
	recordRemoveOnStop bool
	running            bool
	swarmMode          bool
	opts               pollCommon.PollProviderOptions
	logger             *log.ScopedLogger // provider-specific logger
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

// DockerContainerInfo holds information about a Docker container with albels
type DockerContainerInfo struct {
	Hostname   string
	ID         string
	Overwrite  bool
	RecordType string
	Target     string
	TTL        int
}

// Ensure DockerProvider implements the necessary interfaces
var _ poll.Provider = (*DockerProvider)(nil)
var _ poll.ProviderWithContainer = (*DockerProvider)(nil)

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

// NewProvider creates a new Docker poll provider
func NewProvider(options map[string]string) (poll.Provider, error) {
	parsed := pollCommon.ParsePollProviderOptions(options, pollCommon.PollProviderOptions{
		Interval:           30 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "docker",
	})

	profileName := pollCommon.GetOptionOrEnv(options, "name", "DOCKER_PROFILE_NAME", parsed.Name)
	logPrefix := pollCommon.BuildLogPrefix("docker", profileName)
	logLevel := options["log_level"] // Get provider-specific log level

	// Create scoped logger
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	// Log resolved profile name at trace level only
	scopedLogger.Trace("%s Resolved profile name: %s", logPrefix, profileName)

	// Setup Docker client options from environment or provided options
	clientOpts := []client.Opt{client.FromEnv}

	// Only use api_url and API_URL env var for Docker API endpoint
	apiURL := pollCommon.GetOptionOrEnv(options, "api_url", "API_URL", "unix:///var/run/docker.sock")
	if apiURL != "" {
		scopedLogger.Verbose("%s Using Docker API URL: %s", logPrefix, apiURL)
		clientOpts = append(clientOpts, client.WithHost(apiURL))
	}

	// Check for TLS options (nested under tls.*)
	var tlsVerifySet, tlsVerify bool
	if val, exists := options["tls.verify"]; exists {
		tlsVerifySet = true
		tlsVerify = strings.ToLower(val) == "true" || val == "1"
	}
	caPath := options["tls.ca"]
	certFile := options["tls.cert"]
	keyFile := options["tls.key"]

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
	apiAuthUser := pollCommon.GetOptionOrEnv(options, "api_auth_user", "DOCKER_API_AUTH_USER", "")
	apiAuthPass := pollCommon.GetOptionOrEnv(options, "api_auth_pass", "DOCKER_API_AUTH_PASS", "")
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
		lowerVal := strings.ToLower(val)
		config.ExposeContainers = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
		scopedLogger.Trace("%s Option 'expose_containers' found with value: '%s', parsed as: %v",
			logPrefix, val, config.ExposeContainers)
	} else {
		scopedLogger.Trace("%s No 'expose_containers' option found, using default: %v",
			logPrefix, config.ExposeContainers)
	}

	// Check if we're running in Swarm mode
	if val, exists := options["swarm_mode"]; exists {
		lowerVal := strings.ToLower(val)
		config.SwarmMode = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
		log.Trace("%s Option 'swarm_mode' found with value: '%s', parsed as: %v",
			logPrefix, val, config.SwarmMode)
	} else {
		log.Trace("%s No 'swarm_mode' option found, using default: %v",
			logPrefix, config.SwarmMode)
	}

	// Parse process_existing from options or env
	if val, exists := options["process_existing"]; exists {
		config.ProcessExisting = strings.ToLower(val) == "true" || val == "1"
		log.Trace("%s Option 'process_existing' found with value: '%s', parsed as: %v",
			logPrefix, val, config.ProcessExisting)
	} else {
		envKey := fmt.Sprintf("POLL_%s_PROCESS_EXISTING", strings.ToUpper(profileName))
		if envVal := utils.GetEnvDefault(envKey, ""); envVal != "" {
			config.ProcessExisting = strings.ToLower(envVal) == "true" || envVal == "1"
			log.Trace("%s Using process_existing from environment variable %s: %v", logPrefix, envKey, config.ProcessExisting)
		}
	}

	// Create filter configuration
	filterConfig, err := pollCommon.NewFilterFromOptions(options)
	if err != nil {
		log.Info("%s Error creating filter configuration: %v, using default", logPrefix, err)
		filterConfig = pollCommon.DefaultFilterConfig()
	}

	// Store the config and filter config in the provider
	provider.config = config
	provider.filterConfig = filterConfig

	// Parse record_remove_on_stop option
	provider.recordRemoveOnStop = parsed.RecordRemoveOnStop

	// Log the actual filterConfig.Filters slice for diagnosis
	log.Debug("%s Filter Configuration: %+v", logPrefix, filterConfig.Filters)
	// Only show a count if there are real, user-configured filters
	filterSummary := "none"
	realFilterCount := 0
	for _, f := range filterConfig.Filters {
		if (f.Type != "none" && f.Type != "") || f.Value != "" {
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

// Register the Docker provider
func init() {
	poll.RegisterProvider("docker", NewProvider)
}

// IsRunning checks if the provider is running
func (p *DockerProvider) IsRunning() bool {
	return p.running
}

// StopPolling stops the Docker provider polling
func (p *DockerProvider) StopPolling() error {
	p.running = false
	return nil
}

// SetDNSProvider assigns a DNS provider for direct updates
func (p *DockerProvider) SetDNSProvider(provider dns.Provider) {
	p.dnsProvider = provider
}

// Add SetDomainConfigs method
func (p *DockerProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

// StartPolling starts watching Docker events for container changes
func (p *DockerProvider) StartPolling() error {
	ctx := context.Background()

	// Set up filters for events
	f := dfilters.NewArgs()

	// Always watch for container events
	f.Add("type", "container")
	f.Add("event", "start")
	f.Add("event", "stop")
	f.Add("event", "die")

	// Add service events when in swarm mode
	if p.swarmMode {
		f.Add("type", "service")
		f.Add("event", "create")
		f.Add("event", "update")
		f.Add("event", "remove")

		log.Debug("%s Added service events to event filters (swarm mode)", p.logPrefix)
	}

	// Get event stream
	eventChan, errChan := p.client.Events(ctx, types.EventsOptions{
		Filters: f,
	})

	p.running = true

	// Start goroutine to process events
	go func() {
		for {
			if !p.running {
				return
			}

			select {
			case err := <-errChan:
				log.Error("%s Event stream error: %v", p.logPrefix, err)
				time.Sleep(5 * time.Second)

				// Try to reconnect
				eventChan, errChan = p.client.Events(ctx, types.EventsOptions{
					Filters: f,
				})

			case event := <-eventChan:
				switch event.Type {
				case "container":
					p.handleContainerEvent(ctx, event)
				case "service":
					p.handleServiceEvent(ctx, event)
				}
			}
		}
	}()

	if p.config.ProcessExisting {
		log.Verbose("%s Processing existing containers and services", p.logPrefix)
		// Process existing containers in a goroutine to not block startup
		go p.processRunningContainers(ctx)

		// Process existing services if in swarm mode
		if p.swarmMode {
			go p.processRunningServices(ctx)
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

	log.Verbose("%s Container event: '%s' - name: '%s' - id: '%s'", p.logPrefix, event.Action, containerName, containerID[:12])

	// Process based on event action
	switch event.Action {
	case "start":
		p.processContainer(ctx, containerID)
	case "stop":
		if p.recordRemoveOnStop {
			container, err := p.client.ContainerInspect(ctx, containerID)
			if err != nil {
				log.Warn("%s Failed to inspect container '%s' for DNS removal: '%v'", p.logPrefix, containerID[:12], err)
				return
			}
			entries := p.extractDNSEntriesFromContainer(container)
			p.processDNSEntries(entries, true)
		}
	case "die":
		// Only log die events at debug level
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

	log.Debug("%s Service %s: (%s) - %s", p.logPrefix, event.Action, serviceName, serviceID[:12])

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

// processRunningContainers processes all currently running containers
func (p *DockerProvider) processRunningContainers(ctx context.Context) {
	// List containers
	containers, err := p.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		log.Error("%s Failed to list containers: %v", p.logPrefix, err)
		return
	}

	log.Info("%s Found %d containers", p.logPrefix, len(containers))

	// Process each container
	for _, container := range containers {
		p.processContainer(ctx, container.ID)
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

// matchDockerFilter is a provider-specific match function for Docker filters
func matchDockerFilter(filter pollCommon.Filter, entry any) bool {
	container, ok := entry.(types.ContainerJSON)
	if !ok {
		return false
	}
	// Implement match logic for Docker filters
	return strings.Contains(container.Name, filter.Value)
}

// shouldProcessContainer determines if the container should be processed based on labels and configuration
func (p *DockerProvider) shouldProcessContainer(container types.ContainerJSON) bool {
	// Ensure container name doesn't have slash prefix
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// First, check if the container passes our filter configuration
	if !p.filterConfig.Evaluate(container, matchDockerFilter) {
		log.Debug("%s Skipping container '%s' because it does not match filter criteria", p.logPrefix, containerName)
		return false
	}

	// Check if the container has the nfrastack.dns.enable label
	enableDNS, hasLabel := container.Config.Labels["nfrastack.dns.enable"]

	// If the label is explicitly set to "false", always skip the container
	if hasLabel && (strings.ToLower(enableDNS) == "false" || enableDNS == "0") {
		log.Verbose("%s Skipping container '%s' because it has an explicit 'nfrastack.dns.enable=false' label", p.logPrefix, containerName)
		return false
	}

	// If expose_containers is true, process all containers unless explicitly disabled above
	if p.config.ExposeContainers {
		log.Debug("%s Processing container '%s' because 'expose_containers=true' in config", p.logPrefix, containerName)
		return true
	}

	// If expose_containers is false and no label exists, skip the container due to config
	if !hasLabel {
		log.Debug("%s Skipping container '%s' because 'expose_containers=false' in config and no 'nfrastack.dns.enable' label exists", p.logPrefix, containerName)
		return false
	}

	// If expose_containers is false but label exists and is true, process the container
	if strings.ToLower(enableDNS) == "true" || enableDNS == "1" {
		log.Verbose("%s Processing container '%s' because it has 'nfrastack.dns.enable=true' label (overriding expose_containers=false)", p.logPrefix, containerName)
		return true
	}

	// If we get here, label exists but is not true or false (some other value)
	log.Warn("%s Skipping container '%s' because it has 'nfrastack.dns.enable=%s' (not 'true') and 'expose_containers=false'", p.logPrefix, containerName, enableDNS)
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
func (p *DockerProvider) processDNSEntries(entries []poll.DNSEntry, remove bool) error {
	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(p.logPrefix)
	
	for _, entry := range entries {
		fqdn := entry.GetFQDN()
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
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
		
		var err error
		if remove {
			p.logger.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err = batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
		} else {
			p.logger.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err = batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
		}
		
		if err != nil {
			action := "ensure"
			if remove {
				action = "remove"
			}
			p.logger.Error("%s Failed to %s DNS for '%s': %v", p.logPrefix, action, fqdnNoDot, err)
		}
	}
	
	// Finalize the batch - this will sync output files only if there were changes
	batchProcessor.FinalizeBatch()
	return nil
}

// GetDNSEntries returns all DNS entries from all containers
func (p *DockerProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
	ctx := context.Background()

	// List containers
	containers, err := p.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []poll.DNSEntry

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
func (p *DockerProvider) GetContainersForDomain(domain string) ([]poll.ContainerInfo, error) {
	ctx := context.Background()

	// List containers
	containers, err := p.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []poll.ContainerInfo

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
			result = append(result, entry)
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
	}

	// Create a DNS entry for each hostname
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
func (p *DockerProvider) extractDNSEntriesFromContainer(container types.ContainerJSON) []poll.DNSEntry {
	log.Trace("%s domainConfigs map at entry: %v", p.logPrefix, p.domainConfigs)

	var entries []poll.DNSEntry
	containerName := getContainerName(container)
	labels := container.Config.Labels
	if len(labels) == 0 {
		return entries
	}

	// 1. Check for nfrastack.dns.enable or legacy nfrastack.dns label
	dnsLabel, hasDNSLabel := labels["nfrastack.dns.enable"]
	if !hasDNSLabel {
		dnsLabel, hasDNSLabel = labels["nfrastack.dns"]
	}
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
	parts := strings.Split(hostValue, ".")
	if len(parts) < 2 {
		log.Verbose("%s Host value '%s' is not a valid FQDN for container '%s', skipping", p.logPrefix, hostValue, containerName)
		return entries
	}
	domain := strings.Join(parts[len(parts)-2:], ".")
	hostname := strings.Join(parts[:len(parts)-2], ".")
	if hostname == "" {
		hostname = "@"
	}

	// Apply domain-specific subdomain filtering
	domainCfg := p.domainConfigs[domain]
	subdomain := hostname
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
					//log.Debug("%s Using domain config for '%s': value: 'target=%s'", p.logPrefix, domain, domainCfg.Record.Target)
					target = domainCfg.Record.Target
				}
				if recordType == "" && domainCfg.Record.Type != "" {
					//log.Debug("%s Using domain config for '%s': value: 'record_type=%s'", p.logPrefix, domain, domainCfg.Record.Type)
					recordType = domainCfg.Record.Type
				}
				if ttl == 0 && domainCfg.Record.TTL > 0 {
					//log.Debug("%s Using domain config for '%s': value: 'ttl=%d'", p.logPrefix, domain, domainCfg.Record.TTL)
					ttl = domainCfg.Record.TTL
				}
				if !overwrite && domainCfg.Record.UpdateExisting {
					//log.Debug("%s Using domain config for '%s': value: 'record_update_existing=true'", p.logPrefix, domain)
					overwrite = true
				}
				break
			}
		}
	}

	// Global config fallback (if still unset)
	if target == "" && p.options != nil {
		if globalTarget, ok := p.options["dns_record_target"]; ok && globalTarget != "" {
			log.Debug("%s Using global config for '%s': value: 'target=%s'", p.logPrefix, domain, globalTarget)
			target = globalTarget
		}
	}
	if recordType == "" && p.options != nil {
		if globalType, ok := p.options["dns_record_type"]; ok && globalType != "" {
			log.Debug("%s Using global config for '%s': value: 'dns_record_type %s'", p.logPrefix, domain, globalType)
			recordType = globalType
		}
	}
	if ttl == 0 && p.options != nil {
		if globalTTL, ok := p.options["dns_record_ttl"]; ok && globalTTL != "" {
			if parsed, err := strconv.Atoi(globalTTL); err == nil {
				log.Debug("%s Using global config for '%s': value: 'dns_record_ttl=%d'", p.logPrefix, domain, parsed)
				ttl = parsed
			}
		}
	}
	if !overwrite && p.options != nil {
		if globalOverwrite, ok := p.options["record_updating_existing"]; ok && (globalOverwrite == "true" || globalOverwrite == "1") {
			log.Debug("%s Using global config for '%s': value: 'record_update_existing=true'", p.logPrefix, domain)
			overwrite = true
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

	entries = append(entries, poll.DNSEntry{
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
	return entries
}

// extractDNSEntriesFromService extracts all DNS entries from a Swarm service
func (p *DockerProvider) extractDNSEntriesFromService(service swarm.Service) ([]poll.DNSEntry, error) {
	var entries []poll.DNSEntry
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
