// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package input

import (
	"github.com/nfrastack/herald/internal/domain" // Import domain to access OutputWriter and OutputSyncer interfaces
	"github.com/nfrastack/herald/internal/input/types/caddy"
	"github.com/nfrastack/herald/internal/input/types/docker"
	"github.com/nfrastack/herald/internal/input/types/file"
	"github.com/nfrastack/herald/internal/input/types/remote"
	"github.com/nfrastack/herald/internal/input/types/tailscale"
	"github.com/nfrastack/herald/internal/input/types/traefik"
	"github.com/nfrastack/herald/internal/input/types/zerotier"

	"encoding/json"
	"fmt"
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/log"
	"strings"
)

// Provider interface defines the methods that all input providers must implement
type Provider interface {
	StartPolling() error
	StopPolling() error
	GetName() string
}

// ProviderWithContainer interface for providers that support container operations
type ProviderWithContainer interface {
	Provider
	GetContainerState(containerID string) (map[string]interface{}, error)
}

// DNSEntry represents a DNS entry from input providers
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

// ContainerInfo represents container information
type ContainerInfo struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	State  string            `json:"state"`
}

// GetFQDN returns the fully qualified domain name
func (d DNSEntry) GetFQDN() string {
	return d.Name
}

func (d DNSEntry) GetRecordType() string {
	return d.RecordType
}

// NewInputProvider creates a new input provider instance using factory pattern
func NewInputProvider(inputProviderType string, providerOptions map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	log.NewScopedLogger("", "").With("type", inputProviderType).Debug("Creating input provider")

	profileName := providerOptions["name"]
	if profileName == "" {
		profileName = inputProviderType + "_default"
	}

	// Factory pattern - direct creation based on type
	switch inputProviderType {
	case "caddy":
		// Convert to interface{} map for providers that need it
		config := make(map[string]interface{})
		for k, v := range providerOptions {
			config[k] = v
		}
		return caddy.NewProvider(profileName, config, outputWriter, outputSyncer)
	case "docker":
		// Convert to interface{} map for providers that need it
		config := make(map[string]interface{})
		for k, v := range providerOptions {
			config[k] = v
		}
		return docker.NewProvider(profileName, config, outputWriter, outputSyncer)
	case "file":
		return file.NewProvider(providerOptions, outputWriter, outputSyncer)
	case "remote":
		return remote.NewProvider(providerOptions, outputWriter, outputSyncer)
	case "tailscale":
		return tailscale.NewProvider(providerOptions, outputWriter, outputSyncer)
	case "traefik":
		return traefik.NewProvider(providerOptions, outputWriter, outputSyncer)
	case "zerotier":
		return zerotier.NewProvider(providerOptions, outputWriter, outputSyncer)
	default:
		availableTypes := []string{"caddy", "docker", "file", "remote", "tailscale", "traefik", "zerotier"}
		return nil, fmt.Errorf("unknown input provider type '%s'. Available types: %v", inputProviderType, availableTypes)
	}
}

// GetAvailableTypes returns a list of all available input provider type names
func GetAvailableTypes() []string {
	return []string{"caddy", "docker", "file", "remote", "tailscale", "traefik", "zerotier"}
}

// CreateAndStartProvider creates and starts an input provider with minimal main.go coupling
func CreateAndStartProvider(name string, inputConfig config.InputProviderConfig, domains map[string]config.DomainConfig, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {

	log.NewScopedLogger("", "").With("provider", name, "type", inputConfig.Type).Verbose("Initializing input provider")

	// Create options map for the provider
	providerOptions := inputConfig.GetOptions(name)

	// For backward compatibility, add expose_containers directly
	if inputConfig.ExposeContainers {
		providerOptions["expose_containers"] = "true"
		log.NewScopedLogger("", "").With("provider", name).Debug("Adding expose_containers=true to provider options")
	}

	// Handle filter configuration properly for inputcommon
	if filterConfig, exists := inputConfig.Options["filter"]; exists {
		log.NewScopedLogger("", "").With("provider", name).Debug("Found filter configuration: %+v", filterConfig)
	}

	// Add or override with any additional options from the options map
	for k, v := range inputConfig.Options {
		if strVal, ok := v.(string); ok {
			providerOptions[k] = strVal
		} else {
			// For complex types like filters, convert to string representation
			if k == "filter" {
				log.NewScopedLogger("", "").With("provider", name).Debug("Converting filter to string: %+v", v)
			}
			providerOptions[k] = fmt.Sprintf("%v", v)
		}
	}

	// Handle filter JSON conversion if needed
	if filterOpt, exists := providerOptions["filter"]; exists {
		log.NewScopedLogger("", "").With("provider", name).Debug("Filter found in final options: %s (type: %T)", filterOpt, filterOpt)

		// Force JSON conversion for all filters
		if filterRaw, exists := inputConfig.Options["filter"]; exists {
			if filterJSON, err := json.Marshal(filterRaw); err == nil {
				providerOptions["filter"] = string(filterJSON)
				log.NewScopedLogger("", "").With("provider", name).Debug("Successfully converted filter to JSON: %s", string(filterJSON))
			} else {
				log.NewScopedLogger("", "").With("provider", name).Error("Failed to convert filter to JSON: %v", err)
			}
		}
	}

	// Log configuration for debugging
	log.NewScopedLogger("", "").With("provider", name).Debug("Provider raw config: %+v", inputConfig)
	log.NewScopedLogger("", "").With("provider", name).Trace("Provider options: %v", maskSensitiveOptions(providerOptions))

	// Create the input provider
	inputProvider, err := NewInputProvider(inputConfig.Type, providerOptions, outputWriter, outputSyncer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize input provider '%s': %v", name, err)
	}

	// Set domain configs on the provider if it supports it
	if providerWithDomains, ok := inputProvider.(interface {
		SetDomainConfigs(map[string]config.DomainConfig)
	}); ok {
		log.NewScopedLogger("", "").With("provider", name).Debug("Setting domain configs on provider")
		providerWithDomains.SetDomainConfigs(domains)
	} else {
		log.NewScopedLogger("", "").With("provider", name).Debug("Provider does not support domain configs")
	}

	// Start polling
	if err := inputProvider.StartPolling(); err != nil {
		return nil, fmt.Errorf("failed to start polling with provider '%s': %v", name, err)
	}

	return inputProvider, nil
}

// maskSensitiveOptions masks sensitive configuration options for logging
func maskSensitiveOptions(options map[string]string) map[string]string {
	sensitiveKeys := []string{"password", "token", "secret", "key", "auth", "api_token", "api_auth_pass"}
	masked := make(map[string]string)
	for k, v := range options {
		shouldMask := false
		for _, sensitiveKey := range sensitiveKeys {
			if strings.Contains(strings.ToLower(k), sensitiveKey) {
				shouldMask = true
				break
			}
		}
		if shouldMask && len(v) > 0 {
			masked[k] = "***"
		} else {
			masked[k] = v
		}
	}
	return masked
}
