// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"container-dns-companion/pkg/log"
	"os"
	"strings"
	"sync"
)

type ConfigFile struct {
	General   GeneralConfig             `yaml:"general"`
	Defaults  DefaultsConfig            `yaml:"defaults"`
	Providers map[string]ProviderConfig `yaml:"providers"`
	Polls     map[string]ProviderConfig `yaml:"polls"`
	Domains   map[string]DomainConfig   `yaml:"domains"`
}

type GeneralConfig struct {
	LogLevel      string   `yaml:"log_level"`
	LogTimestamps bool     `yaml:"log_timestamps"`
	LogType       string   `yaml:"log_type"`
	PollProfiles  []string `yaml:"poll_profiles"`
	DryRun        bool     `yaml:"dry_run"`
}

type DefaultsConfig struct {
	Record RecordConfig `yaml:"record"`
}

type RecordConfig struct {
	Type           string `yaml:"type"`
	TTL            int    `yaml:"ttl"`
	Target         string `yaml:"target"`
	UpdateExisting bool   `yaml:"update_existing"`
	AllowMultiple  bool   `yaml:"allow_multiple"`
}

type ProviderConfig struct {
	Type             string            `yaml:"type"`
	APIToken         string            `yaml:"api_token"`
	APIKey           string            `yaml:"api_key"`
	APIEmail         string            `yaml:"api_email"`
	DefaultTTL       int               `yaml:"default_ttl"`
	ExposeContainers bool              `yaml:"expose_containers"`
	Options          map[string]string `yaml:"options"`
}

type DomainConfig struct {
	Name              string            `yaml:"name"`
	Provider          string            `yaml:"provider"`
	ZoneID            string            `yaml:"zone_id"`
	Record            RecordConfig      `yaml:"record"`
	Options           map[string]string `yaml:"options"`
	ExcludeSubdomains []string          `yaml:"exclude_subdomains"`
	IncludeSubdomains []string          `yaml:"include_subdomains"`
}

// Global domain configuration storage
var (
	domainConfigsMu sync.RWMutex
	domainConfigs   = make(map[string]map[string]string)
)

// SetDomainConfigs sets the global domain configurations
func SetDomainConfigs(configs map[string]map[string]string) {
	domainConfigsMu.Lock()
	defer domainConfigsMu.Unlock()
	domainConfigs = configs
}

// GetDomainConfig retrieves configuration for a specific domain
func GetDomainConfig(domain string) map[string]string {
	domainConfigsMu.RLock()
	defer domainConfigsMu.RUnlock()

	// Try with domain as is
	if config, exists := domainConfigs[domain]; exists {
		return config
	}

	// Try with normalized domain (replace dots with underscores)
	normalizedDomain := strings.ReplaceAll(domain, ".", "_")
	if config, exists := domainConfigs[normalizedDomain]; exists {
		return config
	}

	// Check if we have a domain that matches this configuration
	for _, config := range domainConfigs {
		if actualDomain, exists := config["name"]; exists && actualDomain == domain {
			return config
		}
	}

	return nil
}

// GetConfig retrieves a configuration key, handling file references
func GetConfig(config map[string]string, key string) string {
	value, ok := config[key]
	if !ok || value == "" {
		return ""
	}

	// Check if the value is a file reference
	if len(value) > 5 && value[:5] == "file:" {
		// Extract file path
		filePath := value[5:]
		log.Debug("[config] Loading %s from file: %s", key, filePath)

		// Read the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Error("[config] Failed to read %s from file %s: %v", key, filePath, err)
			return ""
		}

		// Trim whitespace and return
		return strings.TrimSpace(string(content))
	}

	return value
}

// GetGlobalProviders returns the list of global providers from environment
func GetGlobalProviders() []string {
	providersStr := GetEnvVar("GLOBAL_PROVIDER", "")
	if providersStr == "" {
		return nil
	}

	providers := strings.Split(providersStr, ",")
	// Trim whitespace from each provider
	for i := range providers {
		providers[i] = strings.TrimSpace(providers[i])
	}

	return providers
}

// GetGlobalPollers returns the list of global pollers from environment
func GetGlobalPollers() []string {
	pollersStr := GetEnvVar("GLOBAL_POLLER", "")
	if pollersStr == "" {
		return nil
	}

	pollers := strings.Split(pollersStr, ",")
	// Trim whitespace from each poller
	for i := range pollers {
		pollers[i] = strings.TrimSpace(pollers[i])
	}

	return pollers
}

// Add ProviderConfig methods here since struct is defined in this file
func (pc *ProviderConfig) GetOptions() map[string]string {
	return pc.setProviderOptions()
}

func (pc *ProviderConfig) setProviderOptions() map[string]string {
	options := make(map[string]string)
	if pc.ExposeContainers {
		options["expose_containers"] = "true"
		log.Debug("[config/file] Setting provider option expose_containers = true")
	} else {
		options["expose_containers"] = "false"
		log.Debug("[config/file] Setting provider option expose_containers = false")
	}
	for k, v := range pc.Options {
		log.Debug("[config/file] Setting provider option %s = %s", k, v)
		options[k] = v
	}
	log.Debug("[config/file] Provider options: %v", options)
	return options
}
