// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package poll

import (
	"context"
	"dns-companion/pkg/config"
	"dns-companion/pkg/log"
	"fmt"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
)

// DockerProvider implements the Provider interface for Docker containers
type DockerProvider struct {
	client        *client.Client
	domainConfigs map[string]config.DomainConfig
	swarmMode     bool
	isRunning     bool
	mutex         sync.RWMutex
	engineInfo    *EngineInfo
}

// NewDockerProvider creates a new Docker provider
func NewDockerProvider(options map[string]string) (Provider, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	provider := &DockerProvider{
		client:        cli,
		domainConfigs: make(map[string]config.DomainConfig),
		swarmMode:     false,
	}

	// Detect engine type (Docker vs Podman)
	engineInfo, err := provider.DetectEngine()
	if err != nil {
		log.Warn("[docker] Could not detect container engine type: %v", err)
		provider.engineInfo = &EngineInfo{Type: EngineUnknown}
	} else {
		provider.engineInfo = engineInfo
		if engineInfo.Type == EnginePodman {
			log.Info("[docker] Detected Podman container engine (version: %s)", engineInfo.Version)
		} else if engineInfo.Type == EngineDocker {
			log.Info("[docker] Detected Docker container engine (version: %s)", engineInfo.Version)
		}
	}

	// Check swarm mode setting
	if swarmModeStr, exists := options["swarm_mode"]; exists && swarmModeStr == "true" {
		if err := provider.ValidateSwarmSupport(); err != nil {
			return nil, err
		}
		provider.swarmMode = true
		log.Info("[docker] Swarm mode enabled")
	}

	return provider, nil
}

// DetectEngine detects whether we're running Docker or Podman
func (d *DockerProvider) DetectEngine() (*EngineInfo, error) {
	ctx := context.Background()
	
	info, err := d.client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Docker info: %w", err)
	}

	engineInfo := &EngineInfo{
		Type:    EngineUnknown,
		Version: info.ServerVersion,
	}

	// Check if it's Podman by looking for Podman-specific fields
	if strings.Contains(strings.ToLower(info.Name), "podman") ||
		strings.Contains(strings.ToLower(info.ServerVersion), "podman") {
		engineInfo.Type = EnginePodman
		return engineInfo, nil
	}

	// Check for Docker-specific indicators
	if info.DockerRootDir != "" || strings.Contains(strings.ToLower(info.Name), "docker") {
		engineInfo.Type = EngineDocker
		return engineInfo, nil
	}

	// Additional check: try to get swarm info (Podman will fail this)
	_, err = d.client.SwarmInspect(ctx)
	if err != nil {
		// If swarm inspect fails with "not implemented" or similar, it's likely Podman
		if strings.Contains(strings.ToLower(err.Error()), "not implemented") ||
			strings.Contains(strings.ToLower(err.Error()), "not supported") {
			engineInfo.Type = EnginePodman
			return engineInfo, nil
		}
	} else {
		// If swarm inspect succeeds, it's likely Docker
		engineInfo.Type = EngineDocker
		return engineInfo, nil
	}

	return engineInfo, nil
}

// ValidateSwarmSupport validates that swarm mode is supported by the current engine
func (d *DockerProvider) ValidateSwarmSupport() error {
	if d.engineInfo != nil && d.engineInfo.Type == EnginePodman {
		return fmt.Errorf("swarm mode is not supported with Podman - please disable swarm mode or use Docker")
	}

	// For Docker or unknown engines, allow swarm mode
	return nil
}

// SetDomainConfigs sets the domain configurations
func (d *DockerProvider) SetDomainConfigs(configs map[string]config.DomainConfig) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.domainConfigs = configs
}

// StartPolling starts polling for container changes
func (d *DockerProvider) StartPolling() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.isRunning = true
	return nil
}

// StopPolling stops polling for container changes
func (d *DockerProvider) StopPolling() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.isRunning = false
	return nil
}

// IsRunning returns whether the provider is currently running
func (d *DockerProvider) IsRunning() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.isRunning
}

// GetDNSEntries returns DNS entries from Docker containers
func (d *DockerProvider) GetDNSEntries() ([]DNSEntry, error) {
	ctx := context.Background()
	
	var containers []types.Container
	var err error

	if d.swarmMode {
		// Get swarm services instead of containers
		services, err := d.client.ServiceList(ctx, types.ServiceListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list swarm services: %w", err)
		}
		return d.getEntriesFromServices(ctx, services)
	} else {
		// Get regular containers
		containers, err = d.client.ContainerList(ctx, types.ContainerListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}
		return d.getEntriesFromContainers(ctx, containers)
	}
}

// getEntriesFromContainers processes regular Docker containers
func (d *DockerProvider) getEntriesFromContainers(ctx context.Context, containers []types.Container) ([]DNSEntry, error) {
	var entries []DNSEntry

	for _, cont := range containers {
		// Get container details
		inspect, err := d.client.ContainerInspect(ctx, cont.ID)
		if err != nil {
			log.Warn("[docker] Failed to inspect container %s: %v", cont.ID[:12], err)
			continue
		}

		// Skip if container is not running
		if !inspect.State.Running {
			continue
		}

		// Process container labels for DNS entries
		containerEntries := d.processContainerLabels(inspect, cont.Names[0])
		entries = append(entries, containerEntries...)
	}

	return entries, nil
}

// getEntriesFromServices processes Docker Swarm services
func (d *DockerProvider) getEntriesFromServices(ctx context.Context, services []swarm.Service) ([]DNSEntry, error) {
	var entries []DNSEntry

	for _, service := range services {
		// Process service labels for DNS entries
		serviceEntries := d.processServiceLabels(service)
		entries = append(entries, serviceEntries...)
	}

	return entries, nil
}

// processContainerLabels processes container labels to extract DNS entries
func (d *DockerProvider) processContainerLabels(inspect types.ContainerJSON, containerName string) []DNSEntry {
	var entries []DNSEntry
	
	labels := inspect.Config.Labels
	if labels == nil {
		return entries
	}

	// Look for DNS-related labels
	for key, value := range labels {
		if strings.HasPrefix(key, "dns.") {
			entry := d.parseLabel(key, value, inspect, containerName)
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
	}

	return entries
}

// processServiceLabels processes service labels to extract DNS entries
func (d *DockerProvider) processServiceLabels(service swarm.Service) []DNSEntry {
	var entries []DNSEntry
	
	labels := service.Spec.Labels
	if labels == nil {
		return entries
	}

	// Look for DNS-related labels
	for key, value := range labels {
		if strings.HasPrefix(key, "dns.") {
			entry := d.parseServiceLabel(key, value, service)
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
	}

	return entries
}

// parseLabel parses a DNS label and returns a DNSEntry
func (d *DockerProvider) parseLabel(key, value string, inspect types.ContainerJSON, containerName string) *DNSEntry {
	// Implementation would parse labels like:
	// dns.hostname=myapp
	// dns.domain=example.com
	// dns.type=A
	// dns.target=auto (or specific IP)
	
	// This is a simplified implementation - you'd want to expand this
	// based on your specific label format requirements
	
	return nil // Placeholder
}

// parseServiceLabel parses a DNS label from a swarm service
func (d *DockerProvider) parseServiceLabel(key, value string, service swarm.Service) *DNSEntry {
	// Similar to parseLabel but for swarm services
	return nil // Placeholder
}

// getContainerIP gets the IP address of a container
func (d *DockerProvider) getContainerIP(inspect types.ContainerJSON) string {
	// Try to get IP from default network first
	if inspect.NetworkSettings.IPAddress != "" {
		return inspect.NetworkSettings.IPAddress
	}

	// Try to get IP from any available network
	for _, network := range inspect.NetworkSettings.Networks {
		if network.IPAddress != "" {
			return network.IPAddress
		}
	}

	return ""
}

func init() {
	RegisterProvider("docker", NewDockerProvider)
}