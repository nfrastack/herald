// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package input

import (
	"herald/pkg/domain"
	"herald/pkg/input/types"
	"herald/pkg/input/registry"
	"encoding/json"
	"fmt"
	"herald/pkg/config"
	"herald/pkg/log"
	"strings"
)

// ProviderFactory is a function that creates a Provider
// (profileName, config, outputWriter, outputSyncer) -> Provider, error
// For legacy providers, config is map[string]string; for others, map[string]interface{}
type ProviderFactory = registry.ProviderFactory

// NewInputProvider creates a new input provider instance using factory pattern
func NewInputProvider(inputProviderType string, providerOptions map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (types.Provider, error) {
	log.Debug("[input] Creating input provider type: '%s'", inputProviderType)

	profileName := providerOptions["name"]
	if profileName == "" {
		profileName = inputProviderType + "_default"
	}

	factory, ok := registry.GetProviderFactory(inputProviderType)
	if !ok {
		availableTypes := registry.GetAvailableTypes()
		return nil, fmt.Errorf("unknown input provider type '%s'. Available types: %v", inputProviderType, availableTypes)
	}

	// Convert providerOptions to map[string]interface{} for compatibility
	config := make(map[string]interface{})
	for k, v := range providerOptions {
		config[k] = v
	}
	providerIface, err := factory(profileName, config, outputWriter, outputSyncer)
	if err != nil {
		return nil, err
	}
	provider, ok := providerIface.(types.Provider)
	if !ok {
		return nil, fmt.Errorf("factory for '%s' did not return types.Provider", inputProviderType)
	}
	return provider, nil
}

// CreateAndStartProvider creates and starts an input provider with minimal main.go coupling
func CreateAndStartProvider(name string, inputConfig config.InputProviderConfig, domains map[string]config.DomainConfig, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (types.Provider, error) {
	logPrefix := fmt.Sprintf("[input/%s/%s]", inputConfig.Type, name)
	filterLogPrefix := logPrefix + "/filter"

	log.Verbose("%s Initializing input provider: '%s' (type: %s)", logPrefix, name, inputConfig.Type)

	// Create options map for the provider
	providerOptions := inputConfig.GetOptions(name)

	// For backward compatibility, add expose_containers directly
	if inputConfig.ExposeContainers {
		providerOptions["expose_containers"] = "true"
		log.Debug("%s Adding expose_containers=true to provider options", logPrefix)
	}

	// Handle filter configuration properly for inputcommon
	if filterConfig, exists := inputConfig.Options["filter"]; exists {
		log.Debug("%s Found filter configuration: %+v", filterLogPrefix, filterConfig)
	}

	// Add or override with any additional options from the options map
	for k, v := range inputConfig.Options {
		if strVal, ok := v.(string); ok {
			providerOptions[k] = strVal
		} else {
			// For complex types like filters, convert to string representation
			if k == "filter" {
				log.Debug("%s Converting filter to string: %+v", filterLogPrefix, v)
			}
			providerOptions[k] = fmt.Sprintf("%v", v)
		}
	}

	// Handle filter JSON conversion if needed
	if filterOpt, exists := providerOptions["filter"]; exists {
		log.Debug("%s Filter found in final options: %s (type: %T)", filterLogPrefix, filterOpt, filterOpt)

		// Force JSON conversion for all filters
		if filterRaw, exists := inputConfig.Options["filter"]; exists {
			if filterJSON, err := json.Marshal(filterRaw); err == nil {
				providerOptions["filter"] = string(filterJSON)
				log.Debug("%s Successfully converted filter to JSON: %s", filterLogPrefix, string(filterJSON))
			} else {
				log.Error("%s Failed to convert filter to JSON: %v", filterLogPrefix, err)
			}
		}
	}

	// Log configuration for debugging
	log.Debug("%s Provider raw config: %+v", logPrefix, inputConfig)
	log.Trace("%s Provider options: %v", logPrefix, maskSensitiveOptions(providerOptions))

	// Create the input provider
	inputProvider, err := NewInputProvider(inputConfig.Type, providerOptions, outputWriter, outputSyncer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize input provider '%s': %v", name, err)
	}

	// Set domain configs on the provider if it supports it
	if providerWithDomains, ok := inputProvider.(interface {
		SetDomainConfigs(map[string]config.DomainConfig)
	}); ok {
		log.Debug("%s Setting domain configs on provider", logPrefix)
		providerWithDomains.SetDomainConfigs(domains)
	} else {
		log.Debug("%s Provider does not support domain configs", logPrefix)
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

// Global registry for all input providers
var allInputProviders []types.Provider

// RegisterInputProvider adds a provider to the global registry
func RegisterInputProvider(p types.Provider) {
	allInputProviders = append(allInputProviders, p)
}

// GetAllProviders returns all registered input providers
func GetAllProviders() []types.Provider {
	return allInputProviders
}
