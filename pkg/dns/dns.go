// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// Package dns provides DNS provider interfaces and implementations
package dns

import (
	"dns-companion/pkg/log"

	"fmt"
	"sync"
)

// Provider defines the interface for all DNS providers
type Provider interface {
	// CreateOrUpdateRecord creates or updates a DNS record
	CreateOrUpdateRecord(domain string, recordType string, hostname string, target string, ttl int, overwrite bool) error

	// GetRecordID gets a DNS record ID for a specific record
	GetRecordID(domain string, recordType string, hostname string) (string, error)

	// DeleteRecord deletes a DNS record
	DeleteRecord(domain string, recordType string, hostname string) error

	// GetRecordValue gets the current value of a DNS record (target, TTL, etc.)
	GetRecordValue(domain string, recordType string, hostname string) (*Record, error)

	// GetRecords gets all DNS records of a type for a specific hostname
	GetRecords(domain string, recordType string, hostname string) ([]*Record, error)
}

// ProviderFactory is a function that creates a new DNS provider
type ProviderFactory func(config map[string]string) (Provider, error)

// ProviderConfig contains configuration for DNS providers
type ProviderConfig struct {
	Type    string
	Options map[string]string
}

// DomainConfig contains configuration for a domain
type DomainConfig struct {
	Name   string
	ZoneID string
}

// Record represents a DNS record
type Record struct {
	Name    string
	Type    string
	Value   string
	TTL     int
	ZoneID  string
	Proxied bool
}

var (
	providersMu sync.RWMutex
	providers   = make(map[string]ProviderFactory)
)

// RegisterProvider registers a new DNS provider
func RegisterProvider(name string, factory ProviderFactory) {
	providersMu.Lock()
	defer providersMu.Unlock()
	if factory == nil {
		log.Fatal("[dns] RegisterProvider factory is nil")
	}
	if _, dup := providers[name]; dup {
		log.Fatal("[dns] RegisterProvider called twice for provider %s", name)
	}

	providers[name] = factory
}

// GetProvider returns a provider by name
func GetProvider(name string, options map[string]string) (Provider, error) {
	providersMu.RLock()
	factory, ok := providers[name]
	providersMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("[dns] DNS provider not found: %s", name)
	}
	return factory(options)
}

// LoadProviderFromConfig loads a DNS provider from configuration
func LoadProviderFromConfig(name string, config map[string]string) (Provider, error) {
	profileName := name // Use the profile name passed in
	if v, ok := config["profile_name"]; ok && v != "" {
		profileName = v
	}

	// Get the actual provider type from config - use provider_type not type
	providerType := ""
	if v, ok := config["provider_type"]; ok && v != "" {
		providerType = v
	} else {
		// Last fallback: try to determine provider type from known providers
		if name == "cloudflare" || name == "hosts" {
			providerType = name
		} else {
			// This might be a profile name, so we need to infer the type
			providerType = name
		}
	}

	log.Trace("[dns] Loading DNS Provider: %s (%s)", profileName, providerType)
	log.Trace("[dns] Provider config: %+v", config)
	return GetProvider(providerType, config)
}

// MergeProviderOptions merges provider-specific config into the options map
func MergeProviderOptions(global map[string]string, provider map[string]interface{}) map[string]string {
	merged := make(map[string]string)
	for k, v := range global {
		merged[k] = v
	}
	for k, v := range provider {
		if str, ok := v.(string); ok {
			merged[k] = str
		}
	}
	return merged
}

// JoinHostWithDomain joins a hostname with a domain
func JoinHostWithDomain(hostname, domain string) string {
	if hostname == "" || hostname == "@" {
		return domain
	}
	return hostname + "." + domain
}
