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

// ConfigFile represents a full configuration file
type ConfigFile struct {
	// Global configuration
	Global GlobalConfig `toml:"global"`

	// Provider configurations
	Provider map[string]ProviderConfig `toml:"provider"`

	// Poll configurations
	Poll map[string]PollConfig `toml:"poll"`

	// Domain configurations
	Domain map[string]DomainConfig `toml:"domain"`

	// Profiles
	Profile map[string]ProfileConfig `toml:"profile"`
}

// GlobalConfig contains global application settings
type GlobalConfig struct {
	// Logging
	LogLevel     string `toml:"log_level"`
	LogType      string `toml:"log_type"`
	LogPath      string `toml:"log_path"`
	LogFile      string `toml:"log_file"`
	LogTimestamp bool   `toml:"log_timestamps"`

	// Operation mode
	DryRun bool `toml:"dry_run"`

	// DNS settings
	DNSProvider    string `toml:"dns_provider"`
	DNSRecordType  string `toml:"dns_record_type"`
	DNSRecordTTL   int    `toml:"dns_record_ttl"`
	DNSRecordValue string `toml:"dns_record_value"`

	// Poll settings
	PollProfiles []string `toml:"poll_profiles"`
}

// ProviderConfig contains DNS provider configuration
type ProviderConfig struct {
	// Provider type (cloudflare, route53, etc)
	Type string `toml:"type"`

	// Default TTL for DNS records
	DefaultTTL int `toml:"default_ttl"`

	// API credentials
	APIKey    string `toml:"api_key"`
	APISecret string `toml:"api_secret"`
	APIToken  string `toml:"api_token"`

	// Additional provider-specific options
	Options map[string]string `toml:"options"`
}

// PollConfig contains poll provider configuration
type PollConfig struct {
	// Provider type (docker, traefik, etc)
	Type string `toml:"type"`

	// Provider-specific options
	Options map[string]string `toml:"options"`
}

// DomainConfig contains domain configuration
type DomainConfig struct {
	// Domain name
	Name string `toml:"name"`

	// DNS provider to use
	Provider string `toml:"provider"`

	// Zone ID (if needed)
	ZoneID string `toml:"zone_id"`

	// TTL for DNS records
	TTL int `toml:"ttl"`

	// Record type (A, AAAA, CNAME, etc)
	RecordType string `toml:"record_type"`

	// Target for the DNS record
	Target string `toml:"target"`

	// Whether to update existing records
	UpdateExistingRecord bool `toml:"update_existing_record"`

	// Additional options
	Options map[string]string `toml:"options"`
}

// ProfileConfig contains profile configuration
type ProfileConfig struct {
	// Profile name is the key in the map

	// Logging
	LogLevel     string `toml:"log_level"`
	LogType      string `toml:"log_type"`
	LogPath      string `toml:"log_path"`
	LogFile      string `toml:"log_file"`
	LogTimestamp bool   `toml:"log_timestamps"`

	// Operation mode
	DryRun bool `toml:"dry_run"`

	// Poll settings
	PollProfiles []string `toml:"poll_profiles"`

	// Domains to manage
	Domains []string `toml:"domains"`
}

// LoadConfigFile loads configuration from a file
func LoadConfigFile(configFile string) (*ConfigFile, error) {
	// Read the file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	log.Debug("Loading configuration from %s", configFile)

	// Process environment variables and secrets
	processedData := processConfigFileSecrets(string(data))

	// Parse TOML
	var config ConfigFile
	if _, err := toml.Decode(processedData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	setConfigDefaults(&config)

	return &config, nil
}

// setConfigDefaults sets default values for the configuration
func setConfigDefaults(config *ConfigFile) {
	// Set global defaults
	if config.Global.LogLevel == "" {
		config.Global.LogLevel = "info"
	}
	if config.Global.LogType == "" {
		config.Global.LogType = "console"
	}
	if config.Global.DNSRecordType == "" {
		config.Global.DNSRecordType = "A"
	}
	if config.Global.DNSRecordTTL <= 0 {
		config.Global.DNSRecordTTL = 300 // 5 minutes
	}
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
				log.Error("Failed to read secret file %s: %v", filePath, err)
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
