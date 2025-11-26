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
	CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error

	// CreateOrUpdateRecordWithSource creates or updates a DNS record with source information
	CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error

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
func RegisterProvider(name string, constructor func(map[string]string) (interface{}, error)) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	providerRegistry[name] = func(config map[string]string) (Provider, error) {
		prov, err := constructor(config)
		if err != nil {
			return nil, err
		}
		provider, ok := prov.(Provider)
		if !ok {
			return nil, fmt.Errorf("provider '%s' does not implement Provider interface", name)
		}
		return provider, nil
	}
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

// DNSOutputFormat wraps a DNS Provider as an OutputFormat for the output manager
// This allows the output manager to treat DNS providers as output profiles

type DNSOutputFormat struct {
	ProfileName string
	Provider    Provider
	Config      map[string]interface{}
}

func (d *DNSOutputFormat) GetName() string {
	return fmt.Sprintf("dns/%s", d.Provider.GetName())
}

func (d *DNSOutputFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	proxied := false
	if d.Config != nil {
		if p, ok := d.Config["proxied"].(bool); ok {
			proxied = p
		} else if ps, ok := d.Config["proxied"].(string); ok {
			if strings.ToLower(ps) == "true" {
				proxied = true
			}
		}
	}
	return d.Provider.CreateOrUpdateRecord(domain, recordType, hostname, target, ttl, proxied, false)
}

func (d *DNSOutputFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	proxied := false
	if d.Config != nil {
		if p, ok := d.Config["proxied"].(bool); ok {
			proxied = p
		} else if ps, ok := d.Config["proxied"].(string); ok {
			if strings.ToLower(ps) == "true" {
				proxied = true
			}
		}
	}
	return d.Provider.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", source, false)
}

func (d *DNSOutputFormat) RemoveRecord(domain, hostname, recordType string) error {
	return d.Provider.DeleteRecord(domain, recordType, hostname)
}

func (d *DNSOutputFormat) Sync() error {
	return nil
}

// DNS provider registration happens in individual provider files
