package config

import (
	"container-dns-companion/pkg/log"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Default configuration paths to check
var DefaultConfigPaths = []string{
	"dns-companion.conf",           // Current directory
	"./config/dns-companion.conf",  // Config subdirectory
	"/etc/dns-companion.conf",      // System config
	"~/.config/dns-companion.conf", // User config
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

// FindConfigFile locates a configuration file by checking common locations
// If explicitPath is provided, it only checks that path
func FindConfigFile(explicitPath string) (string, error) {
	// If an explicit path is provided, use that
	if explicitPath != "" {
		if fileExists(explicitPath) {
			return explicitPath, nil
		}
		return "", fmt.Errorf("configuration file not found: %s", explicitPath)
	}

	// Check default paths
	for _, path := range DefaultConfigPaths {
		// Expand home directory if needed
		if strings.HasPrefix(path, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				continue
			}
			path = filepath.Join(home, path[2:])
		}

		if fileExists(path) {
			return path, nil
		}
	}

	return "", fmt.Errorf("no configuration file found")
}

// fileExists checks if a file exists and can be read
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// LoadConfig loads the configuration from a file
func LoadConfig(configPath string) (*ConfigFile, error) {
	// If no path provided, try to find a config file
	if configPath == "" {
		var err error
		configPath, err = FindConfigFile("")
		if err != nil {
			return nil, err
		}
	}

	// Load the configuration file
	return LoadConfigFile(configPath)
}

// GetEnvVar gets an environment variable with a default value
// This directly uses the cache system for better performance
func GetEnvVar(key, defaultValue string) string {
	return GetCachedEnvVar(key, defaultValue)
}

// SetEnvVar sets an environment variable in both the OS environment
// and the cache for consistent access
func SetEnvVar(key, value string) {
	os.Setenv(key, value)
	CacheEnvVar(key, value)
}

// GetEnvVarBool gets a boolean environment variable with a default value
func GetEnvVarBool(key string, defaultValue bool) bool {
	return EnvToBool(key, defaultValue)
}

// GetEnvVarInt gets an integer environment variable with a default value
func GetEnvVarInt(key string, defaultValue int) int {
	return EnvToInt(key, defaultValue)
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
		log.Debug("Loading %s from file: %s", key, filePath)

		// Read the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Error("Failed to read %s from file %s: %v", key, filePath, err)
			return ""
		}

		// Trim whitespace and return
		return strings.TrimSpace(string(content))
	}

	return value
}

// ApplyConfigToEnv applies configuration values to environment variables
// This makes configuration accessible to various components that might expect env vars
func ApplyConfigToEnv(cfg *ConfigFile, profileName string) {
	if cfg == nil {
		return
	}

	// Apply global configuration
	if cfg.Global.LogLevel != "" {
		os.Setenv("LOG_LEVEL", cfg.Global.LogLevel)
	}

	// Apply DNS provider configuration
	if cfg.Global.DNSProvider != "" {
		os.Setenv("DNS_PROVIDER", cfg.Global.DNSProvider)
	}

	// Apply poll profiles configuration
	if len(cfg.Global.PollProfiles) > 0 {
		os.Setenv("POLL_PROFILES", strings.Join(cfg.Global.PollProfiles, ","))
	}

	// Apply domain configurations to environment variables
	for _, domainCfg := range cfg.Domain {
		domainKey := strings.ReplaceAll(domainCfg.Name, ".", "_")
		prefix := "DOMAIN_" + strings.ToUpper(domainKey) + "_"

		// Set domain name
		os.Setenv(prefix+"NAME", domainCfg.Name)

		// Set provider
		if domainCfg.Provider != "" {
			os.Setenv(prefix+"PROVIDER", domainCfg.Provider)
		}

		// Set zone ID
		if domainCfg.ZoneID != "" {
			os.Setenv(prefix+"ZONE_ID", domainCfg.ZoneID)
		}

		// Set TTL
		if domainCfg.TTL > 0 {
			os.Setenv(prefix+"TTL", fmt.Sprintf("%d", domainCfg.TTL))
		}

		// Set record type
		if domainCfg.RecordType != "" {
			os.Setenv(prefix+"RECORD_TYPE", domainCfg.RecordType)
		}

		// Set target
		if domainCfg.Target != "" {
			os.Setenv(prefix+"TARGET", domainCfg.Target)
		}

		// Set update existing record flag
		os.Setenv(prefix+"UPDATE_EXISTING_RECORD", fmt.Sprintf("%t", domainCfg.UpdateExistingRecord))

		// Apply additional options
		for k, v := range domainCfg.Options {
			envKey := prefix + strings.ToUpper(k)
			os.Setenv(envKey, v)
		}
	}

	// If a profile is specified, apply profile-specific settings
	if profileName != "" && cfg.Profile != nil {
		if profile, exists := cfg.Profile[profileName]; exists {
			// Apply profile log level
			if profile.LogLevel != "" {
				os.Setenv("LOG_LEVEL", profile.LogLevel)
			}

			// Apply profile poll profiles
			if len(profile.PollProfiles) > 0 {
				os.Setenv("POLL_PROFILES", strings.Join(profile.PollProfiles, ","))
			}

			// Apply dry run setting
			os.Setenv("DRY_RUN", fmt.Sprintf("%t", profile.DryRun))
		}
	}

	log.Debug("[config] Applied configuration to environment variables")
}
