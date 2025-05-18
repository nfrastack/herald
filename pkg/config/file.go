// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"container-dns-companion/pkg/log"

	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecretRegex matches environment variable references like ${ENV_VAR}
var SecretRegex = regexp.MustCompile(`\${([^}]+)}`)

// ConfigFile represents the structure of the configuration file
type ConfigFile struct {
	General  GeneralConfig             `yaml:"general"`
	Defaults DefaultsConfig            `yaml:"defaults"`
	Provider map[string]ProviderConfig `yaml:"provider"`
	Poll     map[string]ProviderConfig `yaml:"poll"`
	Domain   map[string]DomainConfig   `yaml:"domain"`
	Profile  map[string]ProfileConfig  `yaml:"profile"`
}

// DefaultsConfig holds default DNS record settings
type DefaultsConfig struct {
	Record DefaultsRecordConfig `yaml:"record"`
}

type DefaultsRecordConfig struct {
	Type           string `yaml:"type"`
	TTL            int    `yaml:"ttl"`
	Target         string `yaml:"target"`
	UpdateExisting bool   `yaml:"update_existing"`
	AllowMultiple  bool   `yaml:"allow_multiple"`
}

// GeneralConfig represents general configuration settings
type GeneralConfig struct {
	LogLevel      string   `yaml:"log_level"`
	LogTimestamps bool     `yaml:"log_timestamps"`
	LogType       string   `yaml:"log_type"`
	LogPath       string   `yaml:"log_path"`
	DNSProvider   string   `yaml:"dns_provider"`
	PollProfiles  []string `yaml:"poll_profiles"`
	// Additional options as a map
	Options map[string]interface{} `yaml:"options"`
}

// ProviderConfig represents configuration for a provider
type ProviderConfig struct {
	Type             string            `yaml:"type"`
	APIToken         string            `yaml:"api_token"`
	APIKey           string            `yaml:"api_key"`
	APIEmail         string            `yaml:"api_email"`
	DefaultTTL       int               `yaml:"default_ttl"`
	ExposeContainers bool              `yaml:"expose_containers"`
	Options          map[string]string `yaml:"options"`
}

// DomainConfig represents the configuration for a domain
// For YAML: use a list (dash format)
type DomainConfig struct {
	Name              string             `yaml:"name"`
	Provider          string             `yaml:"provider"`
	ZoneID            string             `yaml:"zone_id"`
	Record            DomainRecordConfig `yaml:"record"`
	Options           map[string]string  `yaml:"options"`
	ExcludeSubdomains []string           `yaml:"exclude_subdomains"`
	IncludeSubdomains []string           `yaml:"include_subdomains"`
}

type DomainRecordConfig struct {
	Type           string `yaml:"type"`
	TTL            int    `yaml:"ttl"`
	Target         string `yaml:"target"`
	UpdateExisting bool   `yaml:"update_existing"`
	AllowMultiple  bool   `yaml:"allow_multiple"`
}

// ProfileConfig represents a configuration profile
type ProfileConfig struct {
	LogLevel      string   `yaml:"log_level"`
	LogTimestamps bool     `yaml:"log_timestamps"`
	LogType       string   `yaml:"log_type"`
	LogPath       string   `yaml:"log_path"`
	DryRun        bool     `yaml:"dry_run"`
	PollProfiles  []string `yaml:"poll_profiles"`
	Domains       []string `yaml:"domains"`
}

// GetOptions returns the options map as strings for the provider
func (pc *ProviderConfig) GetOptions() map[string]string {
	return pc.setProviderOptions()
}

// setProviderOptions sets the options map for the provider based on the config
func (pc *ProviderConfig) setProviderOptions() map[string]string {
	// Create a map of options from all fields in the config
	options := make(map[string]string)

	// Add expose_containers setting from the direct field
	if pc.ExposeContainers {
		options["expose_containers"] = "true"
		log.Debug("[config/file] Setting provider option expose_containers = true")
	} else {
		options["expose_containers"] = "false"
		log.Debug("[config/file] Setting provider option expose_containers = false")
	}

	// Add all fields from the provider config options map
	for k, v := range pc.Options {
		log.Debug("[config/file] Setting provider option %s = %s", k, v)
		options[k] = v
	}

	// Debug logging to see what options are being passed
	log.Debug("[config/file] Provider options: %v", options)

	return options
}

// LoadConfigFile loads the configuration from a YAML file (any extension)
func LoadConfigFile(path string) (*ConfigFile, error) {
	log.Debug("[config/file] Loading configuration from %s", path)

	var cfg ConfigFile

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to read config file: %w", err)
	}
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to decode YAML: %w", err)
	}

	// 2. Load environment variable configuration (overrides config file)
	LoadFromEnvironment(&cfg)

	// 3. Set application-level defaults ONLY if still unset after config and env
	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "info"
	}
	// Only set to true if still unset (default bool is false, so check for explicit false)
	if os.Getenv("LOG_TIMESTAMPS") == "" && !fieldSetInConfigFile(path, "log_timestamps") {
		cfg.General.LogTimestamps = true
	}
	if cfg.General.LogType == "" {
		cfg.General.LogType = "console"
	}

	if cfg.Defaults.Record.TTL == 0 {
		cfg.Defaults.Record.TTL = 3600
	}
	// Only set to false if still unset (default bool is false, so check for explicit false)
	if os.Getenv("UPDATE_EXISTING_RECORD") == "" && !fieldSetInConfigFile(path, "update_existing_record") {
		cfg.Defaults.Record.UpdateExisting = false
	}

	// Provider logic: if only one provider, assign it to domains without provider
	if len(cfg.Provider) == 1 {
		var onlyProvider string
		for k := range cfg.Provider {
			onlyProvider = k
			break
		}
		for domainName, domainCfg := range cfg.Domain {
			if domainCfg.Provider == "" {
				domainCfg.Provider = onlyProvider
				cfg.Domain[domainName] = domainCfg
			}
		}
	}

	// Smart logic for domain record_type based on target (domain-level only)
	for name, domainCfg := range cfg.Domain {
		if domainCfg.Record.Type == "" && domainCfg.Record.Target != "" {
			if isIPAddress(domainCfg.Record.Target) {
				domainCfg.Record.Type = "A"
			} else {
				domainCfg.Record.Type = "CNAME"
			}
			cfg.Domain[name] = domainCfg
		}
	}

	// If poll_profiles is not set, use all defined poll profiles
	if len(cfg.General.PollProfiles) == 0 && len(cfg.Poll) > 0 {
		profiles := make([]string, 0, len(cfg.Poll))
		for k := range cfg.Poll {
			profiles = append(profiles, k)
		}
		cfg.General.PollProfiles = profiles
	}

	// Parse exclude_subdomains and include_subdomains as comma-separated lists
	for name, domainCfg := range cfg.Domain {
		excludeStr := domainCfg.Options["exclude_subdomains"]
		if excludeStr != "" {
			domainCfg.ExcludeSubdomains = parseCommaList(excludeStr)
		}
		includeStr := domainCfg.Options["include_subdomains"]
		if includeStr != "" {
			domainCfg.IncludeSubdomains = parseCommaList(includeStr)
		}
		cfg.Domain[name] = domainCfg
	}

	return &cfg, nil
}

// Helper to check if a field is set in the config file (for booleans)
func fieldSetInConfigFile(path, field string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if strings.Contains(string(buf[:n]), field+" = ") {
				return true
			}
		}
		if err != nil {
			break
		}
	}
	return false
}

// Helper to check if a string is an IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// processConfigFileSecrets replaces environment variable references in the config file
func processConfigFileSecrets(content string) string {
	// Replace ${ENV_VAR} with the environment variable value
	processedContent := SecretRegex.ReplaceAllStringFunc(content, func(match string) string {
		// Extract variable name (remove ${ and })
		varName := match[2 : len(match)-1]

		// Check if it's prefixed with "file:"
		if strings.HasPrefix(varName, "file:") {
			// Extract file path
			filePath := strings.TrimPrefix(varName, "file:")

			// Read file content
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				log.Error("[config/file] Failed to read secret file %s: %v", filePath, err)
				return match // Keep original if error
			}

			// Trim whitespace and return content
			return strings.TrimSpace(string(fileData))
		}

		// Look up environment variable
		if value, exists := os.LookupEnv(varName); exists {
			return value
		}

		// If environment variable doesn't exist, keep original
		return match
	})

	return processedContent
}

// Helper to parse a comma-separated list into a slice of strings
func parseCommaList(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
