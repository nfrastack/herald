// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package docker

import (
	"container-dns-companion/pkg/config"
	"container-dns-companion/pkg/dns"
	"container-dns-companion/pkg/log"
	"container-dns-companion/pkg/poll"
	"container-dns-companion/pkg/poll/providers/docker/filter"

	"context"
	"fmt"
	"net"
	"path/filepath"
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
	client             *client.Client
	config             Config
	lastContainerIDs   map[string]bool
	options            map[string]string
	dnsProvider        dns.Provider
	running            bool
	exposeContainers   bool
	filterConfig       filter.FilterConfig
	swarmMode          bool                           // Whether to operate in Docker Swarm mode
	domainConfigs      map[string]config.DomainConfig // Add this field to hold domain configs
	recordRemoveOnStop bool                           // Add this field for record removal on stop
}

// Config defines configuration for the Docker provider
type Config struct {
	ExposeContainers bool `mapstructure:"expose_containers"`
	SwarmMode        bool `mapstructure:"swarm_mode"`
}

// DockerContainerInfo holds information about a Docker container
type DockerContainerInfo struct {
	ID         string
	Hostname   string
	Target     string
	RecordType string
	TTL        int
	Overwrite  bool
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

// NewProvider creates a new Docker poll provider
func NewProvider(options map[string]string) (poll.Provider, error) {
	// Setup Docker client options from environment or provided options
	clientOpts := []client.Opt{client.FromEnv}

	// Check for explicit Docker host from options
	if dockerHost, exists := options["docker_host"]; exists && dockerHost != "" {
		log.Debug("[poll/docker] Using explicit Docker host: %s", dockerHost)
		clientOpts = append(clientOpts, client.WithHost(dockerHost))
	}

	// Check for TLS options
	if certPath, exists := options["docker_cert_path"]; exists && certPath != "" {
		log.Debug("[poll/docker] Using Docker TLS certificates from: %s", certPath)
		clientOpts = append(clientOpts, client.WithTLSClientConfig(
			filepath.Join(certPath, "ca.pem"),
			filepath.Join(certPath, "cert.pem"),
			filepath.Join(certPath, "key.pem"),
		))
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
	}

	// Parse configuration
	var config Config

	// Default values
	config.ExposeContainers = false
	config.SwarmMode = false

	// Log all available options for debugging
	log.Debug("[poll/docker] Provider options received: %v", options)

	// Check if we should expose all containers by default from options
	if val, exists := options["expose_containers"]; exists {
		lowerVal := strings.ToLower(val)
		config.ExposeContainers = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
		log.Debug("[poll/docker] Option 'expose_containers' found with value: '%s', parsed as: %v",
			val, config.ExposeContainers)
	} else {
		log.Debug("[poll/docker] No 'expose_containers' option found, using default: %v",
			config.ExposeContainers)
	}

	// Check if we're running in Swarm mode
	if val, exists := options["swarm_mode"]; exists {
		lowerVal := strings.ToLower(val)
		config.SwarmMode = lowerVal == "true" || lowerVal == "1" || lowerVal == "yes"
		log.Debug("[poll/docker] Option 'swarm_mode' found with value: '%s', parsed as: %v",
			val, config.SwarmMode)
	} else {
		log.Debug("[poll/docker] No 'swarm_mode' option found, using default: %v",
			config.SwarmMode)
	}

	// Create filter configuration
	filterConfig, err := filter.NewFilterFromOptions(options)
	if err != nil {
		log.Warn("[poll/docker] Error creating filter configuration: %v, using default", err)
		filterConfig = filter.DefaultFilterConfig()
	}

	// Store the config and filter config in the provider
	provider.config = config
	provider.filterConfig = filterConfig

	// Parse record_remove_on_stop option
	if val, exists := options["record_remove_on_stop"]; exists {
		provider.recordRemoveOnStop = strings.ToLower(val) == "true" || val == "1"
	}

	// Log filter configuration
	if len(filterConfig.Filters) > 0 && filterConfig.Filters[0].Type != filter.FilterTypeNone {
		log.Info("[poll/docker] Provider created with %d filters", len(filterConfig.Filters))
		for i, f := range filterConfig.Filters {
			log.Debug("[poll/docker] Filter %d: type=%s, value=%s, operation=%s, negate=%v",
				i+1, f.Type, f.Value, f.Operation, f.Negate)
		}
	} else {
		log.Info("[poll/docker] Provider created with no filters")
	}

	log.Info("[poll/docker] Provider created with expose_containers=%v, swarm_mode=%v",
		provider.config.ExposeContainers, provider.config.SwarmMode)

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

		log.Debug("[poll/docker] Added service events to event filters (swarm mode)")
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
				log.Error("[poll/docker] Event stream error: %v", err)
				time.Sleep(5 * time.Second)

				// Try to reconnect
				eventChan, errChan = p.client.Events(ctx, types.EventsOptions{
					Filters: f,
				})

			case event := <-eventChan:
				// Handle different event types
				switch event.Type {
				case "container":
					p.handleContainerEvent(ctx, event)
				case "service":
					p.handleServiceEvent(ctx, event)
				}
			}
		}
	}()

	// Check if we should process existing containers/services
	processExisting := false
	if val, exists := p.options["process_existing_containers"]; exists {
		processExisting = strings.ToLower(val) == "true" || val == "1"
	}

	if processExisting {
		log.Info("[poll/docker] Processing existing containers and services")
		// Process existing containers in a goroutine to not block startup
		go p.processRunningContainers(ctx)

		// Process existing services if in swarm mode
		if p.swarmMode {
			go p.processRunningServices(ctx)
		}
	} else {
		log.Info("[poll/docker] Waiting for new containers/services")
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

	log.Debug("[poll/docker] Container event: %s - name: %s - id: %s", event.Action, containerName, containerID[:12])

	// Process based on event action
	switch event.Action {
	case "start":
		// Container started - check for DNS entries but log at DEBUG level initially
		//log.Debug("[poll/docker] Container started: %s", containerName)
		p.processContainer(ctx, containerID)
	case "stop":
		// Container stopped - remove DNS records if enabled
		if p.recordRemoveOnStop {
			container, err := p.client.ContainerInspect(ctx, containerID)
			if err != nil {
				log.Warn("[poll/docker] Failed to inspect container %s for DNS removal: %v", containerID[:12], err)
				return
			}
			entries := p.extractDNSEntriesFromContainer(container)
			for _, entry := range entries {
				if entry.Hostname == "" && entry.Domain == "" {
					continue
				}
				if p.dnsProvider == nil {
					continue
				}
				log.Info("[poll/docker] Removing DNS record for %s.%s (%s)", entry.Hostname, entry.Domain, entry.RecordType)
				err := p.dnsProvider.DeleteRecord(entry.Domain, entry.RecordType, entry.Hostname)
				if err != nil {
					log.Warn("[poll/docker] Failed to remove DNS record for %s.%s: %v", entry.Hostname, entry.Domain, err)
				} else {
					log.Info("[poll/docker] Successfully removed DNS record for %s.%s (%s)", entry.Hostname, entry.Domain, entry.RecordType)
				}
			}
		}
	case "die":
		// Only log die events at debug level
		//log.Debug("[poll/docker] Container died: %s", containerName)
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

	log.Debug("[poll/docker] Service %s: (%s) - %s", event.Action, serviceName, serviceID[:12])

	// Process based on event action
	switch event.Action {
	case "create", "update":
		// Service created or updated - check for DNS entries
		p.processService(ctx, serviceID)
	case "remove":
		// Service removed - we may want to implement DNS record removal here
		log.Debug("[poll/docker] Service removed: %s", serviceName)
	}
}

// processRunningContainers processes all currently running containers
func (p *DockerProvider) processRunningContainers(ctx context.Context) {
	log.Info("[poll/docker] Processing running containers")

	// List containers
	containers, err := p.client.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		log.Error("[poll/docker] Failed to list containers: %v", err)
		return
	}

	log.Info("[poll/docker] Found %d containers", len(containers))

	// Process each container
	for _, container := range containers {
		p.processContainer(ctx, container.ID)
	}
}

// processRunningServices processes all currently running Swarm services
func (p *DockerProvider) processRunningServices(ctx context.Context) {
	if !p.swarmMode {
		log.Debug("[poll/docker] Not in swarm mode, skipping service processing")
		return
	}

	log.Info("[poll/docker] Processing running services (swarm mode)")

	// List services
	services, err := p.client.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		log.Error("[poll/docker] Failed to list services: %v", err)
		return
	}

	log.Info("[poll/docker] Found %d services", len(services))

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
	if !p.filterConfig.ShouldProcessContainer(container) {
		log.Debug("[poll/docker] Skipping container %s because it does not match filter criteria", containerName)
		return false
	}

	// Check if the container has the nfrastack.dns.enable label
	enableDNS, hasLabel := container.Config.Labels["nfrastack.dns.enable"]

	// If the label is explicitly set to "false", always skip the container
	if hasLabel && (strings.ToLower(enableDNS) == "false" || enableDNS == "0") {
		log.Debug("[poll/docker] Skipping container %s because it has an explicit nfrastack.dns.enable=false label", containerName)
		return false
	}

	// If expose_containers is true, process all containers unless explicitly disabled above
	if p.config.ExposeContainers {
		log.Debug("[poll/docker] Processing container %s because expose_containers=true in config", containerName)
		return true
	}

	// If expose_containers is false and no label exists, skip the container due to config
	if !hasLabel {
		log.Debug("[poll/docker] Skipping container %s because expose_containers=false in config and no nfrastack.dns.enable label exists", containerName)
		return false
	}

	// If expose_containers is false but label exists and is true, process the container
	if strings.ToLower(enableDNS) == "true" || enableDNS == "1" {
		log.Debug("[poll/docker] Processing container %s because it has nfrastack.dns.enable=true label (overriding expose_containers=false)", containerName)
		return true
	}

	// If we get here, label exists but is not true or false (some other value)
	log.Debug("[poll/docker] Skipping container %s because it has nfrastack.dns.enable=%s (not 'true') and expose_containers=false", containerName, enableDNS)
	return false
}

// processContainer processes a single container for DNS entries
func (p *DockerProvider) processContainer(ctx context.Context, containerID string) {
	// Get container details
	container, err := p.client.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Warn("[poll/docker] Failed to inspect container %s: %v", containerID[:12], err)
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
		p.processDNSEntries(containerID, containerName, entries)
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
		log.Warn("[poll/docker] Failed to inspect service %s: %v", serviceID[:12], err)
		return
	}

	serviceName := service.Spec.Name

	// Extract DNS entries for this service
	entries := p.extractDNSEntriesFromService(service)

	// If we found DNS entries, process them
	if len(entries) > 0 {
		log.Info("[poll/docker] Found %d DNS entries for service %s", len(entries), serviceName)
		p.processDNSEntries(serviceID, serviceName, entries)
	} else {
		log.Debug("[poll/docker] No DNS entries found for service %s", serviceName)
	}
}

// processDNSEntries sends DNS entries to the DNS provider
func (p *DockerProvider) processDNSEntries(containerID string, containerName string, entries []poll.DNSEntry) {
	// Skip processing if no DNS provider is configured
	if p.dnsProvider == nil {
		log.Debug("[poll/docker] No DNS provider configured, skipping DNS record creation")
		return
	}

	// Process each DNS entry
	for _, entry := range entries {
		// Skip entries with empty hostnames
		if entry.Hostname == "" && entry.Domain == "" {
			log.Warn("[poll/docker] Empty hostname and domain in DNS entry from container %s, skipping", containerName)
			continue
		}

		// The hostname and domain are already parsed correctly in extractDNSEntriesFromContainer
		hostname := entry.Hostname
		domain := entry.Domain

		// Set defaults from the entry initially
		recordType := entry.RecordType
		ttl := entry.TTL
		target := entry.Target
		updateExisting := entry.Overwrite

		// If no record type specified yet, use global default
		if recordType == "" {
			recordType = "A" // Global default
			log.Debug("[poll/docker] Using global default record type: %s", recordType)
		}

		// Validate that target is appropriate for record type
		if recordType == "A" && target != "" {
			// Validate target is an IP address for A records
			if net.ParseIP(target) == nil {
				log.Error("[poll/docker] Invalid target for A record: %s is not an IP address. Skipping DNS entry %s.%s",
					target, hostname, domain)
				continue
			}
		}

		if recordType == "AAAA" && target != "" {
			// Validate target is an IPv6 address for AAAA records
			if ip := net.ParseIP(target); ip == nil || ip.To16() == nil || ip.To4() != nil {
				log.Error("[poll/docker] Invalid target for AAAA record: %s is not an IPv6 address. Skipping DNS entry %s.%s",
					target, hostname, domain)
				continue
			}
		}

		// If target is still missing, this is a fatal error - we require an explicit target
		if target == "" {
			log.Fatal("[poll/docker] No target specified for DNS entry %s.%s and no valid target found in container, domain, or global configuration",
				hostname, domain)
			return // This will never execute due to Fatal, but kept for clarity
		}

		// Set TTL from global default if still not set
		if ttl <= 0 {
			ttl = 60 // Global default
			log.Debug("[poll/docker] Using global default TTL: %d", ttl)
		}

		log.Debug("[poll/docker] Sending DNS entry to Provider: %s.%s (%s) -> %s (TTL: %d, Update: %v)",
			hostname, domain, recordType, target, ttl, updateExisting)

		// Check for multiple A/AAAA record support in domain config
		domainCfg, hasDomainCfg := p.domainConfigs[domain]
		allowMultipleA := hasDomainCfg && domainCfg.RecordTypeAMultiple && recordType == "A"
		allowMultipleAAAA := hasDomainCfg && domainCfg.RecordTypeAAAAMultiple && recordType == "AAAA"
		if (allowMultipleA || allowMultipleAAAA) && !updateExisting {
			log.Error("[poll/docker] Multiple %s records requested for %s.%s but update_existing_record is not enabled. Skipping.", recordType, hostname, domain)
			continue
		}
		if allowMultipleA || allowMultipleAAAA {
			existingRecords, err := p.dnsProvider.GetRecords(domain, recordType, hostname)
			if err != nil {
				log.Warn("[poll/docker] Could not fetch existing %s records for %s.%s: %v", recordType, hostname, domain, err)
			}
			alreadyExists := false
			for _, rec := range existingRecords {
				if rec.Value == target {
					alreadyExists = true
					break
				}
			}
			if alreadyExists {
				log.Info("[poll/docker] %s record for %s.%s with value %s already exists, skipping.", recordType, hostname, domain, target)
				continue
			}
		}

		// Check if record exists - but don't log this, let the provider do it
		recordExists := false
		recordID, err := p.dnsProvider.GetRecordID(domain, recordType, hostname)
		if err != nil {
			log.Debug("[poll/docker] Error checking if record exists: %v", err)
		} else if recordID != "" {
			recordExists = true
		}

		// If record exists, fetch its current value and compare
		if recordExists {
			currentRecord, err := p.dnsProvider.GetRecordValue(domain, recordType, hostname)
			if err != nil {
				log.Warn("[poll/docker] Could not fetch current value for existing DNS record %s.%s: %v", hostname, domain, err)
			} else {
				// Compare current record with intended values
				if currentRecord != nil && currentRecord.Value == target && currentRecord.TTL == ttl {
					log.Info("[poll/docker] DNS record %s.%s already set to intended value (target: %s, TTL: %d), skipping update", hostname, domain, target, ttl)
					continue
				}
			}
		}

		// Create or update the DNS record
		err = p.dnsProvider.CreateOrUpdateRecord(domain, recordType, hostname, target, ttl, updateExisting)
		if err != nil {
			if recordExists && strings.Contains(err.Error(), "already exists") {
				if updateExisting {
					log.Error("[poll/docker] Failed to update existing DNS record for container %s: %v", containerName, err)
				} else {
					log.Debug("[poll/docker] Skipping update for existing DNS record %s.%s", hostname, domain)
				}
			} else {
				log.Error("[poll/docker] Failed to create DNS record for container %s: %v", containerName, err)
			}
		} else {
			if recordExists {
				log.Info("[poll/docker] Successfully updated DNS record %s.%s (%s) -> %s (TTL: %d)",
					hostname, domain, recordType, target, ttl)
			} else {
				log.Info("[poll/docker] Successfully created DNS record %s.%s (%s) -> %s (TTL: %d)",
					hostname, domain, recordType, target, ttl)
			}
		}
	}
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
			log.Warn("[poll/docker] Failed to inspect container %s: %v", c.ID[:12], err)
			continue
		}

		// Extract DNS entries from this container
		entries := p.extractDNSEntriesFromContainer(container)
		result = append(result, entries...)
	}

	log.Info("[poll/docker] Found %d DNS entries from all containers", len(result))

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
			log.Warn("[poll/docker] Failed to inspect container %s: %v", c.ID[:12], err)
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

	log.Info("[poll/docker] Found %d containers with DNS entries for domain %s",
		len(result), domain)

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
	hostname := container.ID[:12] // Default to container ID if no specific hostname

	// Check through nfrastack.dns.host label for the domain
	if hostLabel, exists := labels["nfrastack.dns.host"]; exists && hostLabel != "" {
		// Format: nfrastack.dns.host=subdomain.example.com
		parts := strings.Split(hostLabel, ".")
		if len(parts) >= 2 {
			hostDomain := strings.Join(parts[len(parts)-2:], ".")
			if hostDomain == domain {
				shouldRegister = true
				// Extract hostname from host label (everything before domain)
				if len(parts) > 2 {
					hostname = strings.Join(parts[:len(parts)-2], ".")
				}
			}
		}
	}

	// Also check Traefik rules for Host entries
	if !shouldRegister {
		for k, v := range labels {
			if strings.HasPrefix(k, "traefik.http.routers.") && strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
				// Extract the host from the value (format: Host(`subdomain.example.com`))
				hostStart := strings.Index(v, "Host(`")
				if hostStart == -1 {
					continue
				}
				hostStart += 6 // Move past "Host(`"

				hostEnd := strings.Index(v[hostStart:], "`)")
				if hostEnd == -1 {
					continue
				}

				host := v[hostStart : hostStart+hostEnd]

				// Split the host into parts to extract domain
				parts := strings.Split(host, ".")
				if len(parts) >= 2 {
					hostDomain := strings.Join(parts[len(parts)-2:], ".")
					if hostDomain == domain {
						shouldRegister = true
						// Extract hostname from host (everything before domain)
						if len(parts) > 2 {
							hostname = strings.Join(parts[:len(parts)-2], ".")
						} else {
							hostname = "@" // Use @ for apex domain
						}
						break
					}
				}
			}
		}
	}

	if !shouldRegister {
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
		log.Warn("[poll/docker] Container %s has no target for domain %s (no label set)",
			container.ID[:12], domain)
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

	// Create the container info
	containerInfo := &DockerContainerInfo{
		ID:         container.ID,
		Hostname:   hostname,
		Target:     target,
		RecordType: recordType,
		TTL:        ttl,
		Overwrite:  overwrite,
	}

	entries = append(entries, containerInfo)

	log.Info("[poll/docker] Using domain %s: %s.%s (%s) -> %s (TTL: %d, Overwrite: %v)",
		domain, hostname, domain, recordType, target, ttl, overwrite)

	return entries
}

// getContainerName returns the container name without the leading slash
func getContainerName(container types.ContainerJSON) string {
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}
	return containerName
}

// extractDNSEntriesFromContainer extracts DNS entries from a Docker container
func (p *DockerProvider) extractDNSEntriesFromContainer(container types.ContainerJSON) []poll.DNSEntry {
	log.Debug("[poll/docker] domainConfigs map at entry: %v", p.domainConfigs)

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
			log.Debug("[poll/docker] Skipping container %s due to nfrastack.dns.enable/nfrastack.dns label set to false", containerName)
			return entries
		}
		if val == "true" || val == "1" {
			log.Debug("[poll/docker] DNS enabled for container %s due to label override", containerName)
			// continue processing
		} else {
			log.Debug("[poll/docker] Skipping container %s due to nfrastack.dns.enable/nfrastack.dns label set to unknown value '%s'", containerName, dnsLabel)
			return entries
		}
	} else if !p.config.ExposeContainers {
		log.Debug("[poll/docker] Skipping container %s because expose_containers is false and no enable label is set", containerName)
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
				hostStart := strings.Index(v, "Host(`")
				if hostStart == -1 {
					continue
				}
				hostStart += 6
				hostEnd := strings.Index(v[hostStart:], "`)")
				if hostEnd == -1 {
					continue
				}
				hostValue = v[hostStart : hostStart+hostEnd]
				hostSource = k
				break
			}
		}
	}
	if hostValue == "" {
		log.Debug("[poll/docker] No hostname/domain found for container %s, skipping", containerName)
		return entries
	}
	log.Debug("[poll/docker] Using label %s=%s for hostname/domain extraction on container %s", hostSource, hostValue, containerName)
	parts := strings.Split(hostValue, ".")
	if len(parts) < 2 {
		log.Debug("[poll/docker] Host value '%s' is not a valid FQDN for container %s, skipping", hostValue, containerName)
		return entries
	}
	domain := strings.Join(parts[len(parts)-2:], ".")
	hostname := strings.Join(parts[:len(parts)-2], ".")
	if hostname == "" {
		hostname = "@"
	}

	// 3. Other nfrastack.dns.* labels and config precedence
	recordType := ""
	if rt, exists := labels["nfrastack.dns.record.type"]; exists && rt != "" {
		recordType = rt
		log.Debug("[poll/docker] Found label nfrastack.dns.record.type=%s on container %s", rt, containerName)
	}
	target := ""
	if t, exists := labels["nfrastack.dns.target"]; exists && t != "" {
		target = t
		log.Debug("[poll/docker] Found label nfrastack.dns.target=%s on container %s", t, containerName)
	}
	ttl := 0
	if ttlStr, exists := labels["nfrastack.dns.record.ttl"]; exists && ttlStr != "" {
		if parsed, err := strconv.Atoi(ttlStr); err == nil {
			log.Debug("[poll/docker] Found label nfrastack.dns.record.ttl=%s on container %s", ttlStr, containerName)
			ttl = parsed
		}
	}
	overwrite := false
	if overwriteStr, exists := labels["nfrastack.dns.record.overwrite"]; exists {
		if strings.ToLower(overwriteStr) == "true" || overwriteStr == "1" {
			log.Debug("[poll/docker] Found label nfrastack.dns.record.overwrite=%s on container %s", overwriteStr, containerName)
			overwrite = true
		}
	}

	// Per-container overrides for multiple A/AAAA record support
	recordTypeAMultiple := false
	if val, exists := labels["nfrastack.dns.record.type.a.multiple"]; exists && val != "" {
		recordTypeAMultiple = strings.ToLower(val) == "true" || val == "1"
		log.Debug("[poll/docker] Found label nfrastack.dns.record.type.a.multiple=%s on container %s", val, containerName)
	}
	recordTypeAAAAMultiple := false
	if val, exists := labels["nfrastack.dns.record.type.aaaa.multiple"]; exists && val != "" {
		recordTypeAAAAMultiple = strings.ToLower(val) == "true" || val == "1"
		log.Debug("[poll/docker] Found label nfrastack.dns.record.type.aaaa.multiple=%s on container %s", val, containerName)
	}

	// Domain config fallback
	if p.domainConfigs != nil {
		for _, domainCfg := range p.domainConfigs {
			if domainCfg.Name == domain {
				if target == "" && domainCfg.Target != "" {
					log.Debug("[poll/docker] Using domain config for %s: value: target %s", domain, domainCfg.Target)
					target = domainCfg.Target
				}
				if recordType == "" && domainCfg.RecordType != "" {
					log.Debug("[poll/docker] Using domain config for %s: value: recordType %s", domain, domainCfg.RecordType)
					recordType = domainCfg.RecordType
				}
				if ttl == 0 && domainCfg.TTL > 0 {
					log.Debug("[poll/docker] Using domain config for %s: value: TTL %d", domain, domainCfg.TTL)
					ttl = domainCfg.TTL
				}
				if !overwrite && domainCfg.UpdateExistingRecord {
					log.Debug("[poll/docker] Using domain config for %s: value: UpdateExistingRecord true", domain)
					overwrite = true
				}
				break
			}
		}
	}

	// Global config fallback (if still unset)
	if target == "" && p.options != nil {
		if globalTarget, ok := p.options["dns_record_target"]; ok && globalTarget != "" {
			log.Debug("[poll/docker] Using global config for %s: value: target %s", domain, globalTarget)
			target = globalTarget
		}
	}
	if recordType == "" && p.options != nil {
		if globalType, ok := p.options["dns_record_type"]; ok && globalType != "" {
			log.Debug("[poll/docker] Using global config for %s: value: type %s", domain, globalType)
			recordType = globalType
		}
	}
	if ttl == 0 && p.options != nil {
		if globalTTL, ok := p.options["dns_record_ttl"]; ok && globalTTL != "" {
			if parsed, err := strconv.Atoi(globalTTL); err == nil {
				log.Debug("[poll/docker] Using global config for %s: value: TTL %d", domain, parsed)
				ttl = parsed
			}
		}
	}
	if !overwrite && p.options != nil {
		if globalOverwrite, ok := p.options["update_existing_record"]; ok && (globalOverwrite == "true" || globalOverwrite == "1") {
			log.Debug("[poll/docker] Using global config for %s: value: update_existing_record true", domain)
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
			log.Error("[poll/docker] Invalid target for A record: %s is not an IPv4 address. Skipping DNS entry %s.%s", target, hostname, domain)
			return entries
		}
	}
	if recordType == "AAAA" && target != "" {
		if ip := net.ParseIP(target); ip == nil || ip.To16() == nil || ip.To4() != nil {
			log.Error("[poll/docker] Invalid target for AAAA record: %s is not an IPv6 address. Skipping DNS entry %s.%s", target, hostname, domain)
			return entries
		}
	}

	if target == "" {
		log.Warn("[poll/docker] Container %s has no target for domain %s (no label, domain, or global config set)", containerName, domain)
		return entries
	}

	log.Debug("[poll/docker] Final values for container %s: hostname=%s, domain=%s, recordType=%s, target=%s, ttl=%d, overwrite=%v", containerName, hostname, domain, recordType, target, ttl, overwrite)
	entries = append(entries, poll.DNSEntry{
		Hostname:               hostname,
		Domain:                 domain,
		RecordType:             recordType,
		Target:                 target,
		TTL:                    ttl,
		Overwrite:              overwrite,
		RecordTypeAMultiple:    recordTypeAMultiple,
		RecordTypeAAAAMultiple: recordTypeAAAAMultiple,
	})
	return entries
}

// extractDNSEntriesFromService extracts all DNS entries from a Swarm service
func (p *DockerProvider) extractDNSEntriesFromService(service swarm.Service) []poll.DNSEntry {
	var entries []poll.DNSEntry

	// Get service labels
	labels := service.Spec.Labels
	if len(labels) == 0 {
		return entries
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
			log.Debug("[poll/docker] Service %s has nfrastack.dns.enable=false label, skipping", serviceName)
			return entries // Return empty entries list
		}
	}

	// If not enabled, skip processing
	if !dnsEnabled {
		return entries
	}

	// The rest of the function remains unchanged
	return entries
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
