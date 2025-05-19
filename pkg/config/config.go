// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"container-dns-companion/pkg/log"

	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
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

// Default configuration paths to check
var DefaultConfigPaths = []string{
	"container-dns-companion.yml",       // Current directory
	"container-dns-companion.yaml",      // Current directory (alt ext)
	"/etc/container-dns-companion.yml",  // System config
	"/etc/container-dns-companion.yaml", // System config (alt ext)
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
	candidateFiles := []string{}
	if configPath != "" {
		candidateFiles = append(candidateFiles, configPath)
	} else {
		candidateFiles = append(candidateFiles,
			"./dns-companion.conf",
			"./dns-companion.yaml",
			"./dns-companion.yml",
			"/etc/dns-companion.conf",
			"/etc/dns-companion.yaml",
			"/etc/dns-companion.yml",
		)
	}
	var lastErr error
	for _, file := range candidateFiles {
		if _, err := os.Stat(file); err == nil {
			cfg, err := loadYAMLConfig(file)
			if err == nil {
				if cfg != nil && len(cfg.Polls) == 1 && (len(cfg.General.PollProfiles) == 0 || cfg.General.PollProfiles == nil) {
					for k := range cfg.Polls {
						cfg.General.PollProfiles = []string{k}
					}
				}
				return cfg, nil
			}
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("[config/file] failed to load config: %w", lastErr)
	}
	return nil, fmt.Errorf("[config/file] no config file found in candidates: %v", candidateFiles)
}

func loadYAMLConfig(path string) (*ConfigFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var cfg ConfigFile
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("[config/file] failed to parse YAML: %w", err)
	}
	return &cfg, nil
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
