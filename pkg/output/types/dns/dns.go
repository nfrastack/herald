// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Provider defines the interface that all DNS providers must implement
type Provider interface {
	// CreateOrUpdateRecord creates or updates a DNS record
	CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool) error

	// CreateOrUpdateRecordWithSource creates or updates a DNS record with source information
	CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string) error

	// DeleteRecord deletes a DNS record
	DeleteRecord(domain, recordType, hostname string) error

	// GetName returns the provider name
	GetName() string

	// Validate validates the provider configuration
	Validate() error
}

// ProviderConstructor is a function that creates a new DNS provider instance
type ProviderConstructor func(config map[string]string) (Provider, error)

// providerRegistry holds all registered DNS providers
var providerRegistry = make(map[string]ProviderConstructor)
var registryMutex sync.RWMutex

// RegisterProvider registers a new DNS provider
func RegisterProvider(name string, constructor ProviderConstructor) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	providerRegistry[name] = constructor
}

// GetProvider creates a new instance of the specified DNS provider
func GetProvider(name string, config map[string]string) (Provider, error) {
	registryMutex.RLock()
	constructor, exists := providerRegistry[name]
	registryMutex.RUnlock()

	if !exists {
		availableProviders := GetAvailableProviders()
		return nil, fmt.Errorf("unknown DNS provider '%s'. Available providers: %v", name, availableProviders)
	}

	// Process configuration values to support file:// and env:// references
	processedConfig := ProcessConfigValues(config)

	return constructor(processedConfig)
}

// GetAvailableProviders returns a list of all registered DNS provider names
func GetAvailableProviders() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	providers := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		providers = append(providers, name)
	}
	return providers
}

// ValidateProviderExists checks if a DNS provider is registered
func ValidateProviderExists(providerName string) error {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	if _, exists := providerRegistry[providerName]; !exists {
		availableProviders := GetAvailableProviders()
		return fmt.Errorf("unknown DNS provider '%s'. Available providers: %v", providerName, availableProviders)
	}
	return nil
}

// ProcessConfigValues processes DNS provider configuration values to support file:// and env:// references
func ProcessConfigValues(config map[string]string) map[string]string {
	processed := make(map[string]string)
	for key, value := range config {
		processed[key] = processConfigValue(value)
	}
	return processed
}

// processConfigValue processes a single configuration value for file:// and env:// support
func processConfigValue(value string) string {
	// Check if the value is a file reference and resolve it
	if strings.HasPrefix(value, "file://") {
		filePath := value[7:] // Remove "file://" prefix

		// Read the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			// Log error but return original value
			return value
		}

		// Trim whitespace and return content
		return strings.TrimSpace(string(content))
	}

	// Check if the value is an environment variable reference and resolve it
	if strings.HasPrefix(value, "env://") {
		envName := value[6:] // Remove "env://" prefix

		// Read the environment variable
		envValue := os.Getenv(envName)
		if envValue == "" {
			// Return original value if env var not set
			return value
		}

		// Return environment variable value
		return envValue
	}

	return value
}
