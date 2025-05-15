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
	DNSProvider          string   `toml:"dns_provider"`
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
func LoadConfigFile(path string) (*ConfigFile, error) {
	log.Debug("[config/file] Loading configuration from %s", path)

	var cfg ConfigFile

	// Open and decode the TOML file
	_, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to decode TOML file: %w", err)
	}

	// Validate basic configuration
	if cfg.Global.DNSProvider == "" {
		return nil, fmt.Errorf("[config/file] no DNS provider specified in configuration")
	}

	// Check if the specified DNS provider has a configuration
	_, exists := cfg.Provider[cfg.Global.DNSProvider]
	if !exists {
		return nil, fmt.Errorf("[config/file] configuration for DNS provider '%s' not found", cfg.Global.DNSProvider)
	}

	// Set defaults for global logging if not specified
	if cfg.Global.LogLevel == "" {
		cfg.Global.LogLevel = "info"
	}

	return &cfg, nil
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
