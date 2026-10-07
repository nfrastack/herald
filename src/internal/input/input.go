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

type Provider interface {
	StartPolling() error
	StopPolling() error
	GetName() string
}

type ProviderWithContainer interface {
	Provider
	GetContainerState(containerID string) (map[string]interface{}, error)
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

type ContainerInfo struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	State  string            `json:"state"`
}

func (d DNSEntry) GetFQDN() string {
	return d.Name
}

func (d DNSEntry) GetRecordType() string {
	return d.RecordType
}

func NewInputProvider(inputProviderType string, providerOptions map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	log.NewScopedLogger("", "").With("action", "provider.init", "type", inputProviderType).Debug("input provider")

	profileName := providerOptions["name"]
	if profileName == "" {
		profileName = inputProviderType + "_default"
	}

	switch inputProviderType {
	case "caddy":
		config := make(map[string]interface{})
		for k, v := range providerOptions {
			config[k] = v
		}
		return caddy.NewProvider(profileName, config, outputWriter, outputSyncer)
	case "docker":
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

func GetAvailableTypes() []string {
	return []string{"caddy", "docker", "file", "remote", "tailscale", "traefik", "zerotier"}
}

func CreateAndStartProvider(name string, inputConfig config.InputProviderConfig, domains map[string]config.DomainConfig, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {

	log.NewScopedLogger("", "").With("action", "provider.init", "provider", name, "type", inputConfig.Type).Verbose("input provider")

	providerOptions := inputConfig.GetOptions(name)

	if inputConfig.ExposeContainers {
		providerOptions["expose_containers"] = "true"
		log.NewScopedLogger("", "").With("action", "config.load", "provider", name).Debug("expose_containers=true to provider options")
	}

	if filterConfig, exists := inputConfig.Options["filter"]; exists {
		log.NewScopedLogger("", "").With("action", "input.filter", "provider", name).Debug("filter configuration: %+v", filterConfig)
	}

	for k, v := range inputConfig.Options {
		if strVal, ok := v.(string); ok {
			providerOptions[k] = strVal
		} else {
			if k == "filter" {
				log.NewScopedLogger("", "").With("action", "input.filter", "provider", name).Debug("filter to string: %+v", v)
			}
			providerOptions[k] = fmt.Sprintf("%v", v)
		}
	}

	if filterOpt, exists := providerOptions["filter"]; exists {
		log.NewScopedLogger("", "").With("action", "input.filter", "provider", name).Debug("in final options: %s (type: %T)", filterOpt, filterOpt)

		if filterRaw, exists := inputConfig.Options["filter"]; exists {
			if filterJSON, err := json.Marshal(filterRaw); err == nil {
				providerOptions["filter"] = string(filterJSON)
				log.NewScopedLogger("", "").With("action", "input.filter", "provider", name).Debug("filter to JSON: %s", string(filterJSON))
			} else {
				log.NewScopedLogger("", "").With("action", "input.filter", "provider", name).Error("filter to JSON: %v", err)
			}
		}
	}

	log.NewScopedLogger("", "").With("action", "config.load", "provider", name).Debug("raw config: %+v", inputConfig)
	log.NewScopedLogger("", "").With("action", "config.load", "provider", name).Trace("options: %v", maskSensitiveOptions(providerOptions))

	inputProvider, err := NewInputProvider(inputConfig.Type, providerOptions, outputWriter, outputSyncer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize input provider '%s': %v", name, err)
	}

	if providerWithDomains, ok := inputProvider.(interface {
		SetDomainConfigs(map[string]config.DomainConfig)
	}); ok {
		log.NewScopedLogger("", "").With("action", "domain.match", "provider", name).Debug("domain configs on provider")
		providerWithDomains.SetDomainConfigs(domains)
	} else {
		log.NewScopedLogger("", "").With("action", "domain.skip", "provider", name).Debug("domain configs not supported")
	}

	if err := inputProvider.StartPolling(); err != nil {
		return nil, fmt.Errorf("failed to start polling with provider '%s': %v", name, err)
	}

	return inputProvider, nil
}

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
