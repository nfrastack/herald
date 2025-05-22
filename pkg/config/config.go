// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"container-dns-companion/pkg/log"
	"fmt"
	"os"
	"strings"
	"sync"
	"reflect"
)

type ConfigFile struct {
	General   GeneralConfig                 `yaml:"general"`
	Defaults  DefaultsConfig                `yaml:"defaults"`
	Providers map[string]DNSProviderConfig  `yaml:"providers"`
	Polls     map[string]PollProviderConfig `yaml:"polls"`
	Domains   map[string]DomainConfig       `yaml:"domains"`
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

type DNSProviderConfig struct {
	Type     string                 `yaml:"type"`
	APIToken string                 `yaml:"api_token"`
	APIKey   string                 `yaml:"api_key"`
	APIEmail string                 `yaml:"api_email"`
	ZoneID   string                 `yaml:"zone_id"`
	Options  map[string]interface{} `yaml:",inline"`
}

type PollProviderConfig struct {
	Type             string                 `yaml:"type"`
	ExposeContainers bool                   `yaml:"expose_containers"`
	DefaultTTL       int                    `yaml:"default_ttl"`
	Options          map[string]interface{} `yaml:",inline"`
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

// Add DNSProviderConfig methods here since struct is defined in this file
func (dpc *DNSProviderConfig) GetOptions() map[string]string {
	options := make(map[string]string)
	for k, v := range dpc.Options {
		if strVal, ok := v.(string); ok {
			options[k] = strVal
		}
	}
	if dpc.APIToken != "" {
		options["api_token"] = dpc.APIToken
	}
	if dpc.APIKey != "" {
		options["api_key"] = dpc.APIKey
	}
	if dpc.APIEmail != "" {
		options["api_email"] = dpc.APIEmail
	}
	if dpc.ZoneID != "" {
		options["zone_id"] = dpc.ZoneID
	}
	if dpc.Type != "" {
		options["type"] = dpc.Type
	}

	// Create masked options map for logging
	maskedOptions := utils.MaskSensitiveOptions(options)
	log.Debug("[config/file] DNS provider options: %v", maskedOptions)

	return options
}

// Add PollProviderConfig methods here since struct is defined in this file
func (ppc *PollProviderConfig) GetOptions() map[string]string {
	options := make(map[string]string)
	// Add all struct fields from the PollProviderConfig struct itself
	val := reflect.ValueOf(*ppc)
	typ := reflect.TypeOf(*ppc)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		key := field.Tag.Get("yaml")
		if key == "" {
			key = strings.ToLower(field.Name)
		}
		 // Skip the "options" field since we handle it separately
		if key == ",inline" {
			continue
		}

		// Only add string fields
		if field.Type.Kind() == reflect.String {
			valStr := val.Field(i).String()
			if valStr != "" {
				options[key] = valStr
			}
		}
		// Add bool and int fields as string
		if field.Type.Kind() == reflect.Bool {
			options[key] = fmt.Sprintf("%v", val.Field(i).Bool())
		}
		if field.Type.Kind() == reflect.Int {
			intVal := val.Field(i).Int()
			if intVal != 0 { // Only add non-zero values
				options[key] = fmt.Sprintf("%d", intVal)
			}
		}
	}
	// Add all keys from Options map (do not filter or restrict)
	for k, v := range ppc.Options {
		// Convert any type to string
		options[k] = fmt.Sprintf("%v", v)
	}

	// Create masked options map for logging
	maskedOptions := utils.MaskSensitiveOptions(options)
	log.Debug("[config/file] Poll provider options (all keys): %v", maskedOptions)

	return options
}
