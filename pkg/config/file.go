// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"container-dns-companion/pkg/log"

	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// SecretRegex matches environment variable references like ${ENV_VAR}
var SecretRegex = regexp.MustCompile(`\${([^}]+)}`)

// ConfigFile represents the structure of the configuration file
type ConfigFile struct {
	Global   GlobalConfig              `toml:"global"`
	Provider map[string]ProviderConfig `toml:"provider"`
	Poll     map[string]ProviderConfig `toml:"poll"`
	Domain   map[string]DomainConfig   `toml:"domain"`
	Profile  map[string]ProfileConfig  `toml:"profile"`
}

// GlobalConfig represents global configuration settings
type GlobalConfig struct {
	LogLevel             string   `toml:"log_level"`
	LogTimestamps        bool     `toml:"log_timestamps"`
	LogType              string   `toml:"log_type"`
	LogPath              string   `toml:"log_path"`
	PollProfiles         []string `toml:"poll_profiles"`
	DNSRecordType        string   `toml:"dns_record_type"`
	DNSRecordTTL         int      `toml:"dns_record_ttl"`
	DNSRecordTarget      string   `toml:"dns_record_target"`
	UpdateExistingRecord bool     `toml:"update_existing_record"`
	// Additional options as a map
	Options map[string]interface{} `toml:"options"`
}

// ProviderConfig represents configuration for a provider
type ProviderConfig struct {
	Type             string            `toml:"type"`
	APIToken         string            `toml:"api_token"`
	APIKey           string            `toml:"api_key"`
	APIEmail         string            `toml:"api_email"`
	DefaultTTL       int               `toml:"default_ttl"`
	ExposeContainers bool              `toml:"expose_containers"`
	Options          map[string]string `toml:"options"`
}

// DomainConfig represents the configuration for a domain
type DomainConfig struct {
	Name                 string            `toml:"name"`
	Provider             string            `toml:"provider"`
	ZoneID               string            `toml:"zone_id"`
	TTL                  int               `toml:"ttl"`
	RecordType           string            `toml:"record_type"`
	Target               string            `toml:"target"`
	UpdateExistingRecord bool              `toml:"update_existing_record"`
	Options              map[string]string `toml:"options"`
}

// ProfileConfig represents a configuration profile
type ProfileConfig struct {
	LogLevel      string   `toml:"log_level"`
	LogTimestamps bool     `toml:"log_timestamps"`
	LogType       string   `toml:"log_type"`
	LogPath       string   `toml:"log_path"`
	DryRun        bool     `toml:"dry_run"`
	PollProfiles  []string `toml:"poll_profiles"`
	Domains       []string `toml:"domains"`
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

// LoadConfigFile loads the configuration from a TOML file
// Accepts logLevelOverride and logTimestampsOverride for CLI precedence
func LoadConfigFile(path string, logLevelOverride string, logTimestampsOverride *bool) (*ConfigFile, error) {
	var cfg ConfigFile

	// Open and decode the TOML file
	_, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to decode TOML file: %w", err)
	}

	// Load environment variable configuration (overrides config file)
	LoadFromEnvironment(&cfg)

	// Command-line overrides (highest precedence)
	if logLevelOverride != "" {
		cfg.Global.LogLevel = logLevelOverride
	}
	if logTimestampsOverride != nil {
		cfg.Global.LogTimestamps = *logTimestampsOverride
	}

	// Application-level defaults for global config (lowest precedence)
	if cfg.Global.LogLevel == "" {
		cfg.Global.LogLevel = "info"
	}
	if !cfg.Global.LogTimestamps {
		cfg.Global.LogTimestamps = true
	}
	if cfg.Global.LogType == "" {
		cfg.Global.LogType = "console"
	}
	if cfg.Global.DNSRecordTTL == 0 {
		cfg.Global.DNSRecordTTL = 3600
	}
	if !cfg.Global.UpdateExistingRecord {
		cfg.Global.UpdateExistingRecord = false
	}

	// PollProfiles logic
	if len(cfg.Global.PollProfiles) == 0 {
		if len(cfg.Poll) == 1 {
			for k := range cfg.Poll {
				cfg.Global.PollProfiles = []string{k}
				break
			}
		} else if len(cfg.Poll) > 1 {
			profiles := make([]string, 0, len(cfg.Poll))
			for k := range cfg.Poll {
				profiles = append(profiles, k)
			}
			cfg.Global.PollProfiles = profiles
		}
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

	// Smart logic for domain record_type based on target
	for name, domainCfg := range cfg.Domain {
		if domainCfg.RecordType == "" && domainCfg.Target != "" {
			if isIPAddress(domainCfg.Target) {
				domainCfg.RecordType = "A"
			} else {
				domainCfg.RecordType = "CNAME"
			}
			cfg.Domain[name] = domainCfg
		}
	}

	// Set Docker and Traefik poll provider defaults if not set
	for name, pollCfg := range cfg.Poll {
		if pollCfg.Type == "docker" {
			if pollCfg.Options == nil {
				pollCfg.Options = make(map[string]string)
			}
			if pollCfg.Options["host"] == "" {
				pollCfg.Options["host"] = "unix:///var/run/docker.sock"
			}
			if _, ok := pollCfg.Options["expose_containers"]; !ok {
				pollCfg.Options["expose_containers"] = "false"
			}
			if pollCfg.Options["filter_type"] == "" {
				pollCfg.Options["filter_type"] = "none"
			}
			if _, ok := pollCfg.Options["process_existing_containers"]; !ok {
				pollCfg.Options["process_existing_containers"] = "false"
			}
			cfg.Poll[name] = pollCfg
		}
		if pollCfg.Type == "traefik" {
			if pollCfg.Options == nil {
				pollCfg.Options = make(map[string]string)
			}
			if pollCfg.Options["poll_interval"] == "" {
				pollCfg.Options["poll_interval"] = "60"
			}
			if pollCfg.Options["filter_type"] == "" {
				pollCfg.Options["filter_type"] = "none"
			}
			cfg.Poll[name] = pollCfg
		}
	}

	return &cfg, nil
}

// Helper to check if a string is an IP address
func isIPAddress(s string) bool {
	// Simple check for IPv4/IPv6
	return strings.Count(s, ".") == 3 || strings.Count(s, ":") >= 2
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
