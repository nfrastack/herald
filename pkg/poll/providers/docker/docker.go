package docker

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"container-dns-companion/pkg/config"
	"container-dns-companion/pkg/dns"
	"container-dns-companion/pkg/log"
	"container-dns-companion/pkg/poll"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// DockerProvider implements the Provider interface for Docker
type DockerProvider struct {
	client           *client.Client
	config           Config
	lastContainerIDs map[string]bool
	options          map[string]string
	dnsProvider      dns.Provider
	running          bool
	exposeContainers bool
}

// Config defines configuration for the Docker provider
type Config struct {
	ExposeContainers bool `mapstructure:"expose_containers"`
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
	client, err := client.NewClientWithOpts(client.FromEnv)
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

	// Default value set to false
	config.ExposeContainers = false

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

	// Store the config in the provider
	provider.config = config

	log.Info("[poll/docker] Provider created with expose_containers=%v", provider.config.ExposeContainers)

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

// StartPolling starts watching Docker events for container changes
func (p *DockerProvider) StartPolling() error {
	ctx := context.Background()

	// Set up filters for container events
	f := filters.NewArgs()
	f.Add("type", "container")
	f.Add("event", "start")
	f.Add("event", "stop")
	f.Add("event", "die")

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
				p.handleContainerEvent(ctx, event)
			}
		}
	}()

	// Check if we should process existing containers
	processExisting := false
	if val, exists := p.options["process_existing_containers"]; exists {
		processExisting = strings.ToLower(val) == "true" || val == "1"
	}

	if processExisting {
		log.Info("[poll/docker] Processing existing containers")
		// Process existing containers in a goroutine to not block startup
		go p.processRunningContainers(ctx)
	} else {
		log.Info("[poll/docker] Waiting for new containers")
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

	log.Debug("[poll/docker] Container %s: (%s) - %s", event.Action, containerName, containerID[:12])

	// Process based on event action
	switch event.Action {
	case "start":
		// Container started - check for DNS entries but log at DEBUG level initially
		//log.Debug("[poll/docker] Container started: %s", containerName)
		p.processContainer(ctx, containerID)
	case "stop":
		// Container stopped - log at DEBUG level only
		//log.Debug("[poll/docker] Container stopped: %s", containerName)
	case "die":
		// Only log die events at debug level
		//log.Debug("[poll/docker] Container died: %s", containerName)
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

// shouldProcessContainer determines if the container should be processed based on labels and configuration
func (p *DockerProvider) shouldProcessContainer(container types.ContainerJSON) bool {
	// Ensure container name doesn't have slash prefix
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
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

		// Get domain-specific configuration
		domainKey := strings.ReplaceAll(domain, ".", "_")
		domainConfig := config.GetDomainConfig(domainKey)

		// Set defaults from the entry initially
		recordType := entry.RecordType
		ttl := entry.TTL
		target := entry.Target
		updateExisting := entry.Overwrite

		// Apply domain-specific configuration if available
		if domainConfig != nil {
			log.Debug("[poll/docker] Found domain config for %s: %v", domain, domainConfig)

			// Always use domain record_type if it exists (higher priority than container labels)
			if domainConfig["record_type"] != "" {
				recordType = domainConfig["record_type"]
				log.Debug("[poll/docker] Using domain-specific record type: %s", recordType)
			}

			// Use domain TTL if it exists and entry TTL is not specified
			if ttl <= 0 && domainConfig["ttl"] != "" {
				if parsedTTL, err := strconv.Atoi(domainConfig["ttl"]); err == nil && parsedTTL > 0 {
					ttl = parsedTTL
					log.Debug("[poll/docker] Using domain-specific TTL: %d", ttl)
				}
			}

			// Use domain target if it exists and entry target is not specified
			if target == "" && domainConfig["target"] != "" {
				target = domainConfig["target"]
				log.Debug("[poll/docker] Using domain-specific target: %s", target)
			}

			// Use domain update_existing_record setting
			if updateExistingStr, exists := domainConfig["update_existing_record"]; exists && updateExistingStr != "" {
				if parsedUpdate, err := strconv.ParseBool(updateExistingStr); err == nil {
					// Use domain configuration unless explicitly overridden in container
					if !entry.Overwrite {
						updateExisting = parsedUpdate
						log.Debug("[poll/docker] Using domain-specific update_existing_record: %v", updateExisting)
					}
				}
			}
		} else {
			log.Debug("[poll/docker] No domain config found for %s", domain)
		}

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

		// Check if record exists - but don't log this, let the provider do it
		recordExists := false
		recordID, err := p.dnsProvider.GetRecordID(domain, recordType, hostname)
		if err != nil {
			log.Debug("[poll/docker] Error checking if record exists: %v", err)
		} else if recordID != "" {
			recordExists = true
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

// getDomainConfig retrieves domain-specific configuration from environment
func (p *DockerProvider) getDomainConfig(domainKey string) map[string]string {
	// Look for domain configuration in environment variables
	prefix := "DOMAIN_" + strings.ToUpper(domainKey) + "_"

	// List of expected domain configuration keys
	configKeys := []string{
		"NAME", "PROVIDER", "ZONE_ID", "TTL", "RECORD_TYPE",
		"TARGET", "UPDATE_EXISTING_RECORD",
	}

	domainConfig := make(map[string]string)
	hasConfig := false

	// Check for each expected key
	for _, key := range configKeys {
		envKey := prefix + key
		if value, exists := os.LookupEnv(envKey); exists && value != "" {
			domainConfig[strings.ToLower(key)] = value
			hasConfig = true
		}
	}

	// Only return the config if we found at least one valid entry
	if hasConfig {
		log.Debug("[poll/docker] Found domain configuration for %s with %d settings",
			domainKey, len(domainConfig))
		return domainConfig
	}

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
		log.Warn("[poll/docker] Container %s has no target IP for domain %s",
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

// extractDNSEntriesFromContainer extracts all DNS entries from a container
func (p *DockerProvider) extractDNSEntriesFromContainer(container types.ContainerJSON) []poll.DNSEntry {
	var entries []poll.DNSEntry

	// Get container labels
	labels := container.Config.Labels
	if len(labels) == 0 {
		return entries
	}

	// Clean container name for logging (remove leading slash if present)
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// Check if DNS is explicitly enabled or disabled
	dnsEnabled := p.config.ExposeContainers // Default based on config setting

	// Check for explicit setting from container labels
	if value, exists := labels["nfrastack.dns.enable"]; exists {
		explicitValue := strings.ToLower(value)
		if explicitValue == "true" || explicitValue == "1" {
			dnsEnabled = true
		} else if explicitValue == "false" || explicitValue == "0" {
			dnsEnabled = false
			log.Debug("[poll/docker] Container %s has nfrastack.dns.enable=false label, skipping", containerName)
			return entries // Return empty entries list
		}
	}

	// Log debug message if DNS is enabled but no entries found
	defer func() {
		if dnsEnabled && len(entries) == 0 {
			log.Debug("[poll/docker] DNS is enabled for container %s but no valid DNS entries were found", containerName)
		}
	}()

	// Track processed domains to avoid duplicates
	processedDomains := make(map[string]bool)

	// Look for nfrastack.dns.host labels - this is now the primary label to use
	for k, v := range labels {
		if k == "nfrastack.dns.host" && v != "" {
			parts := strings.Split(v, ".")
			if len(parts) < 2 {
				log.Debug("[poll/docker] Invalid nfrastack.dns.host value: %s (needs at least a domain part)", v)
				continue
			}

			// Extract domain (last two parts)
			domain := strings.Join(parts[len(parts)-2:], ".")

			// Skip if already processed
			if processedDomains[domain] {
				continue
			}

			processedDomains[domain] = true

			// Extract hostname (everything before domain)
			hostname := ""
			if len(parts) > 2 {
				hostname = strings.Join(parts[:len(parts)-2], ".")
			} else {
				// If there are only 2 parts (like example.com), we're dealing with an apex domain
				hostname = "@"
			}

			// Get record-specific configurations
			recordType := ""
			if rt, exists := labels["nfrastack.dns.record.type"]; exists && rt != "" {
				recordType = rt
			}

			// Get target
			target := ""
			if t, exists := labels["nfrastack.dns.target"]; exists && t != "" {
				target = t
			}

			// Create DNS entry with proper hostname and domain
			entry := poll.DNSEntry{
				Hostname:   hostname,
				Domain:     domain,
				RecordType: recordType,
				Target:     target,
				TTL:        0,     // Will be set by domain or global config
				Overwrite:  false, // Will be set by domain or global config
			}

			entries = append(entries, entry)

			log.Debug("[poll/docker] Found DNS host entry: %s.%s (%s) -> %s (TTL: %d, Overwrite: %v)",
				hostname, domain, recordType, target, 0, false)
		}
	}

	// Now process Traefik Host rules
	// Format: traefik.http.routers.*.rule=Host(`subdomain.example.com`)
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
			log.Debug("[poll/docker] Extracted host from Traefik rule: %s", host)

			// Split the host into parts to extract domain and hostname
			parts := strings.Split(host, ".")
			if len(parts) < 2 {
				continue
			}

			// Extract domain (last two parts)
			domain := strings.Join(parts[len(parts)-2:], ".")

			// Skip if already processed
			if processedDomains[domain] {
				continue
			}

			processedDomains[domain] = true

			// Extract hostname (everything before domain)
			hostname := ""
			if len(parts) > 2 {
				hostname = strings.Join(parts[:len(parts)-2], ".")
			} else if len(parts) == 2 {
				// For apex domain records, use @ as hostname
				hostname = "@"
			}

			// Double check our parsing
			log.Debug("[poll/docker] Parsed Traefik host: hostname=%s, domain=%s", hostname, domain)

			// Get record-specific configurations from labels - no defaults!
			recordType := ""
			if rt, exists := labels["nfrastack.dns.record.type"]; exists && rt != "" {
				recordType = rt
			}

			// No default target for Traefik entries - this will be resolved from domain config
			target := ""
			if t, exists := labels["nfrastack.dns.target"]; exists && t != "" {
				target = t
			}

			// Get TTL
			ttl := 0 // No default TTL
			if ttlStr, exists := labels["nfrastack.dns.record.ttl"]; exists && ttlStr != "" {
				parsed, err := strconv.Atoi(ttlStr)
				if err == nil {
					ttl = parsed
				}
			}

			// No default for overwrite
			overwrite := false
			if overwriteStr, exists := labels["nfrastack.dns.record.overwrite"]; exists {
				if strings.ToLower(overwriteStr) == "true" || overwriteStr == "1" {
					overwrite = true
				}
			}

			// Create DNS entry using hostname and domain separately
			entry := poll.DNSEntry{
				Hostname:   hostname,
				Domain:     domain,
				RecordType: recordType, // Will be set by domain or global config if empty
				Target:     target,     // Will be set by domain or global config
				TTL:        ttl,        // Will be set by domain or global config if 0
				Overwrite:  overwrite,  // Will be set by domain or global config
			}

			entries = append(entries, entry)

			log.Debug("[poll/docker] Found Traefik Host entry: %s.%s (%s) -> %s (TTL: %d, Overwrite: %v)",
				hostname, domain, recordType, target, ttl, overwrite)
		}
	}

	return entries
}
