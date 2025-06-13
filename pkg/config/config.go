// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"

	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
)

type ConfigFile struct {
	General   GeneralConfig                 `yaml:"general"`
	Defaults  DefaultsConfig                `yaml:"defaults"`
	Providers map[string]DNSProviderConfig  `yaml:"providers"`
	Polls     map[string]PollProviderConfig `yaml:"polls"`
	Domains   map[string]DomainConfig       `yaml:"domains"`
	Outputs   map[string]interface{}        `yaml:"outputs" json:"outputs"`
	API       *APIConfig                    `yaml:"api" json:"api"` // New aggregator API config
}

// APIConfig defines configuration for the aggregator HTTP API server
type APIConfig struct {
	Enabled       bool                           `yaml:"enabled" json:"enabled"`
	Port          string                         `yaml:"port" json:"port"`
	Listen        []string                       `yaml:"listen" json:"listen"`         // Interface patterns to listen on
	TokenFile     string                         `yaml:"token_file" json:"token_file"`
	OutputProfile string                         `yaml:"output_profile" json:"output_profile"`
	ClientExpiry  string                         `yaml:"client_expiry" json:"client_expiry"`
	Endpoint      string                         `yaml:"endpoint" json:"endpoint"`
	Profiles      map[string]APIClientProfile    `yaml:"profiles" json:"profiles"`
	TLS           *APITLSConfig                  `yaml:"tls" json:"tls"`
	LogLevel      string                         `yaml:"log_level" json:"log_level"` // Provider-specific log level override
}

// APITLSConfig defines TLS configuration for the API server
type APITLSConfig struct {
	Verify bool   `yaml:"verify" json:"verify"`     // TLS certificate verification (default: true)
	CA     string `yaml:"ca" json:"ca"`             // Custom CA certificate file
	Cert   string `yaml:"cert" json:"cert"`         // Server certificate file
	Key    string `yaml:"key" json:"key"`           // Server private key file
}

// APIClientProfile defines configuration for individual API clients
type APIClientProfile struct {
	Token         string `yaml:"token" json:"token"`
	OutputProfile string `yaml:"output_profile" json:"output_profile"`
}

type GeneralConfig struct {
	LogLevel       string   `yaml:"log_level"`
	LogTimestamps  bool     `yaml:"log_timestamps"`
	LogType        string   `yaml:"log_type"`
	PollProfiles   []string `yaml:"poll_profiles"`
	OutputProfiles []string `yaml:"output_profiles"`
	DryRun         bool     `yaml:"dry_run"`
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
	Name              string                            `yaml:"name"`
	Provider          string                            `yaml:"provider"`
	ZoneID            string                            `yaml:"zone_id"`
	Record            RecordConfig                      `yaml:"record"`
	Options           map[string]string                 `yaml:"options"`
	ExcludeSubdomains []string                          `yaml:"exclude_subdomains"`
	IncludeSubdomains []string                          `yaml:"include_subdomains"`
	Outputs           map[string]map[string]interface{} `yaml:"outputs"`
}

// Global domain configuration storage
var (
	domainConfigsMu sync.RWMutex
	domainConfigs   = make(map[string]map[string]string)
)

// GlobalConfig holds the loaded configuration file
var GlobalConfig ConfigFile

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

// LoadFileConfig loads a configuration value from a file if it starts with "file://"
func LoadFileConfig(value, fieldName string) (string, error) {
	if !strings.HasPrefix(value, "file://") {
		return value, nil
	}

	filePath := value[7:] // Remove "file://" prefix
	log.Debug("[config] Loading %s from file: %s", fieldName, filePath)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s from file %s: %w", fieldName, filePath, err)
	}

	result := strings.TrimSpace(string(content))
	if result == "" {
		return "", fmt.Errorf("%s file %s is empty", fieldName, filePath)
	}

	log.Verbose("[config] Successfully loaded %s from file", fieldName)
	return result, nil
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
		switch val := v.(type) {
		case string:
			options[k] = val
		case int:
			options[k] = fmt.Sprintf("%d", val)
		case int64:
			options[k] = fmt.Sprintf("%d", val)
		case float64:
			options[k] = fmt.Sprintf("%v", val)
		case bool:
			options[k] = fmt.Sprintf("%t", val)
		default:
			options[k] = fmt.Sprintf("%v", val)
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
	// Always include type field - this is critical for provider loading
	if dpc.Type != "" {
		options["type"] = dpc.Type
	}

	// Process file-based configuration values for DNS providers
	fileConfigFields := []string{"api_token", "api_key", "api_email", "zone_id"}

	for _, field := range fileConfigFields {
		if value, exists := options[field]; exists {
			if resolvedValue, err := LoadFileConfig(value, field); err != nil {
				log.Error("[config] Failed to load %s for DNS provider: %v", field, err)
			} else {
				options[field] = resolvedValue
			}
		}
	}

	return options
}

// Add PollProviderConfig methods here since struct is defined in this file
func (ppc *PollProviderConfig) GetOptions(profileName string) map[string]string {
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
		options[k] = fmt.Sprintf("%v", v)
	}

	// Process file-based configuration values
	fileConfigFields := []string{
		"api_url", "api_auth_user", "api_auth_pass", "tailnet", "domain",
		"network_id", "api_token", "remote_url", "remote_auth_user", "remote_auth_pass",
	}

	for _, field := range fileConfigFields {
		if value, exists := options[field]; exists {
			if resolvedValue, err := LoadFileConfig(value, field); err != nil {
				log.Error("[config] Failed to load %s for poll provider %s: %v", field, profileName, err)
			} else {
				options[field] = resolvedValue
			}
		}
	}

	// Always add profile_name and name
	options["profile_name"] = profileName
	options["name"] = profileName

	return options
}

// InitializeOutputManager initializes the output manager with profiles from config
func InitializeOutputManager() error {
	return InitializeOutputManagerWithProfiles(GlobalConfig.Outputs, GlobalConfig.General.OutputProfiles)
}

// InitializeOutputManagerWithProfiles initializes the output manager with specific profiles from config
func InitializeOutputManagerWithProfiles(outputConfigs map[string]interface{}, enabledProfiles []string) error {
	outputManager := output.NewOutputManager()

	log.Trace("[config/output] Starting output manager initialization")

	if outputConfigs != nil {
		log.Debug("[config/output] Found outputs configuration")

		// Create a set for faster lookup
		enabledSet := make(map[string]bool)
		for _, profile := range enabledProfiles {
			enabledSet[profile] = true
		}

		// Treat everything under outputs as profile names directly
		for profileName, profileConfig := range outputConfigs {
			// Skip profiles not in the enabled list (if list is provided)
			if len(enabledProfiles) > 0 && !enabledSet[profileName] {
				log.Debug("[config/output] Skipping disabled profile: %s", profileName)
				continue
			}

			log.Debug("[config/output] Processing profile: %s", profileName)
			if configMap, ok := profileConfig.(map[string]interface{}); ok {
				format, _ := configMap["format"].(string)
				path, _ := configMap["path"].(string)
				domainsRaw := configMap["domains"]

				log.Trace("[config/output] Output Profile %s: format=%s, path=%s, domains=%v", profileName, format, path, domainsRaw)

				var domains []string
				switch v := domainsRaw.(type) {
				case string:
					if v == "ALL" {
						domains = []string{"ALL"}
					} else {
						domains = []string{v}
					}
				case []interface{}:
					for _, d := range v {
						if ds, ok := d.(string); ok {
							domains = append(domains, ds)
						}
					}
				}

				// Remove known keys to get the rest of the config
				profileConfigCopy := make(map[string]interface{})
				for k, v := range configMap {
					if k != "format" && k != "path" && k != "domains" {
						profileConfigCopy[k] = v
					}
				}

				err := outputManager.AddProfile(profileName, format, path, domains, profileConfigCopy)
				if err != nil {
					log.Error("[output] Failed to add output profile '%s': %v", profileName, err)
					return err
				} else {
					log.Verbose("[output] Registered output profile '%s' (%s)", profileName, format)
				}
			} else {
				log.Warn("[config/output] Profile '%s' has invalid configuration type", profileName)
			}
		}
	} else {
		log.Debug("[config/output] No outputs configuration found")
	}

	output.SetGlobalOutputManager(outputManager)
	return nil
}

// GetGlobalConfig returns the current global configuration
func GetGlobalConfig() *ConfigFile {
	return &GlobalConfig
}
