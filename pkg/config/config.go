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
		return "", fmt.Errorf("[config] configuration file not found: %s", explicitPath)
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

	return "", fmt.Errorf("[config] no configuration file found")
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
