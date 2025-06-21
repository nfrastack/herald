// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"herald/pkg/log"
	"herald/pkg/output"

	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
)

type ConfigFile struct {
	General  GeneralConfig                  `yaml:"general"`
	Defaults DefaultsConfig                 `yaml:"defaults"`
	Inputs   map[string]InputProviderConfig `yaml:"inputs"`
	Domains  map[string]DomainConfig        `yaml:"domains"`
	Outputs  map[string]interface{}         `yaml:"outputs" json:"outputs"`
	API      *APIConfig                     `yaml:"api" json:"api"`
}

// APIConfig defines configuration for the aggregator HTTP API server
type APIConfig struct {
	Enabled       bool                        `yaml:"enabled" json:"enabled"`
	Port          string                      `yaml:"port" json:"port"`
	Listen        []string                    `yaml:"listen" json:"listen"` // Interface patterns to listen on
	TokenFile     string                      `yaml:"token_file" json:"token_file"`
	OutputProfile string                      `yaml:"output_profile" json:"output_profile"`
	ClientExpiry  string                      `yaml:"client_expiry" json:"client_expiry"`
	Endpoint      string                      `yaml:"endpoint" json:"endpoint"`
	Profiles      map[string]APIClientProfile `yaml:"profiles" json:"profiles"`
	TLS           *APITLSConfig               `yaml:"tls" json:"tls"`
	LogLevel      string                      `yaml:"log_level" json:"log_level"` // Provider-specific log level override
}

// APITLSConfig defines TLS configuration for the API server
type APITLSConfig struct {
	Verify bool   `yaml:"verify" json:"verify"` // TLS certificate verification (default: true)
	CA     string `yaml:"ca" json:"ca"`         // Custom CA certificate file
	Cert   string `yaml:"cert" json:"cert"`     // Server certificate file
	Key    string `yaml:"key" json:"key"`       // Server private key file
}

// APIClientProfile defines configuration for individual API clients
type APIClientProfile struct {
	Token         string `yaml:"token" json:"token"`
	OutputProfile string `yaml:"output_profile" json:"output_profile"`
}

type GeneralConfig struct {
	LogLevel             string   `yaml:"log_level"`
	LogTimestamps        bool     `yaml:"log_timestamps"`
	LogType              string   `yaml:"log_type"`
	InputProfiles        []string `yaml:"input_profiles"` // New input profiles list
	OutputProfiles       []string `yaml:"output_profiles"`
	DryRun               bool     `yaml:"dry_run"`
	SkipDomainValidation bool     `yaml:"skip_domain_validation"`
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

type InputProviderConfig struct {
	Type             string                 `yaml:"type"`
	ExposeContainers bool                   `yaml:"expose_containers"`
	DefaultTTL       int                    `yaml:"default_ttl"`
	Options          map[string]interface{} `yaml:",inline"`
}

type DomainConfig struct {
	Name              string            `yaml:"name"`
	Record            RecordConfig      `yaml:"record"`
	Options           map[string]string `yaml:"options"`
	ExcludeSubdomains []string          `yaml:"exclude_subdomains"`
	IncludeSubdomains []string          `yaml:"include_subdomains"`
	Profiles          *DomainProfiles   `yaml:"profiles"` // Primary structured format
}

// GetInputProfiles returns the input profiles from the profiles structure
func (dc *DomainConfig) GetInputProfiles() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Inputs
	}
	return []string{}
}

// GetOutputs returns the outputs from the profiles structure
func (dc *DomainConfig) GetOutputs() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Outputs
	}
	return []string{}
}

// DomainProfiles represents the structured profiles configuration
type DomainProfiles struct {
	Inputs  []string `yaml:"inputs" json:"inputs"`
	Outputs []string `yaml:"outputs" json:"outputs"`
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

// GetConfig retrieves a configuration key, handling file and env references
func GetConfig(config map[string]string, key string) string {
	value, ok := config[key]
	if !ok || value == "" {
		return ""
	}

	// Check if the value is a file reference
	if len(value) > 7 && value[:7] == "file://" {
		// Extract file path
		filePath := value[7:]
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

	// Check if the value is an environment variable reference
	if len(value) > 6 && value[:6] == "env://" {
		// Extract environment variable name
		envVar := value[6:]
		log.Debug("[config] Loading %s from environment variable: %s", key, envVar)

		// Read the environment variable
		if envValue := os.Getenv(envVar); envValue != "" {
			return envValue
		}

		log.Warn("[config] Environment variable %s not found for %s", envVar, key)
		return ""
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

// InputProviderConfig methods
func (ipc *InputProviderConfig) GetOptions(profileName string) map[string]string {
	options := make(map[string]string)
	// Add all struct fields from the InputProviderConfig struct itself
	val := reflect.ValueOf(*ipc)
	typ := reflect.TypeOf(*ipc)
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
	for k, v := range ipc.Options {
		// Special handling for filter configuration - convert to JSON
		if k == "filter" {
			if filterData, err := json.Marshal(v); err == nil {
				options[k] = string(filterData)
				log.Debug("[config] Converted filter to JSON for %s: %s", profileName, string(filterData))
			} else {
				log.Error("[config] Failed to convert filter to JSON for %s: %v", profileName, err)
				// Fallback to original behavior
				options[k] = fmt.Sprintf("%v", v)
			}
		} else {
			options[k] = fmt.Sprintf("%v", v)
		}
	}

	// Always add profile_name and name
	options["profile_name"] = profileName
	options["name"] = profileName

	return options
}

// ConfigFile methods for interface compliance

// GetDomains returns the domains map for output filtering interface
func (cf *ConfigFile) GetDomains() map[string]output.DomainConfig {
	result := make(map[string]output.DomainConfig)
	for key, domainConfig := range cf.Domains {
		result[key] = &domainConfig
	}
	return result
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
			log.Debug("[config/output] Raw config for %s: %+v", profileName, profileConfig)

			if configMap, ok := profileConfig.(map[string]interface{}); ok {
				// Debug what keys exist
				log.Debug("[config/output] Available keys for %s: %v", profileName, func() []string {
					keys := make([]string, 0, len(configMap))
					for k := range configMap {
						keys = append(keys, k)
					}
					return keys
				}())

				// Determine output type and format correctly
				outputType, _ := configMap["type"].(string)

				var format string
				switch outputType {
				case "file":
					// For file type, require format field (zone, hosts, yaml, json)
					format = "file"
					if fileFormat, exists := configMap["format"].(string); exists {
						log.Debug("[config/output] File type with format: %s", fileFormat)
					} else {
						log.Error("[config/output] File type requires 'format' field (zone, hosts, yaml, json)")
						continue
					}
				case "remote":
					// For remote type, format is always "remote"
					format = "remote"
					log.Debug("[config/output] Remote type detected")
				case "dns":
					// For dns type, format is "dns" and requires provider field
					format = "dns"
					if provider, exists := configMap["provider"].(string); exists {
						log.Debug("[config/output] DNS type with provider: %s", provider)
					} else {
						log.Error("[config/output] DNS type requires 'provider' field")
						continue
					}
				default:
					// Legacy support - try to infer from format field
					format, _ = configMap["format"].(string)
					if format == "" {
						log.Error("[config/output] No 'type' field specified for profile '%s'. Must be 'file', 'remote', or 'dns'", profileName)
						continue
					}
				}

				log.Debug("[config/output] Determined format for %s: '%s' (type: %s)", profileName, format, outputType)

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
					if k != "format" && k != "path" && k != "domains" && k != "type" {
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

// ValidateConfiguration performs comprehensive validation of the configuration
func ValidateConfiguration(cfg *ConfigFile) error {
	var errors []string

	// Skip domain validation if requested
	if cfg.General.SkipDomainValidation {
		log.Debug("[config] Skipping domain validation as requested by skip_domain_validation=true")
		return nil
	}

	// Validate domain configurations
	if err := ValidateDomainConfiguration(cfg.Domains, cfg.Inputs, cfg.Outputs); err != nil {
		errors = append(errors, err.Error())
	}

	// Validate input provider references
	if err := ValidateInputProviderReferences(cfg.Domains, cfg.Inputs); err != nil {
		errors = append(errors, err.Error())
	}

	// Validate output profile references
	if err := ValidateOutputProfileReferences(cfg.Domains, cfg.Outputs); err != nil {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// ValidateDomainConfiguration validates all domain configurations
func ValidateDomainConfiguration(domains map[string]DomainConfig, inputProfiles map[string]InputProviderConfig, outputProfiles map[string]interface{}) error {
	var errors []string

	for domainName, domain := range domains {
		// Get effective input profiles using helper method
		effectiveInputProfiles := domain.GetInputProfiles()

		// Get effective outputs using helper method
		effectiveOutputs := domain.GetOutputs()

		// Validate input_profiles exist
		for _, inputProvider := range effectiveInputProfiles {
			if _, exists := inputProfiles[inputProvider]; !exists {
				availableInputs := make([]string, 0, len(inputProfiles))
				for name := range inputProfiles {
					availableInputs = append(availableInputs, name)
				}
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent input provider '%s' (available: %s)",
					domainName, inputProvider, strings.Join(availableInputs, ", ")))
			}
		}

		// Validate outputs exist
		for _, output := range effectiveOutputs {
			if _, exists := outputProfiles[output]; !exists {
				availableOutputs := make([]string, 0, len(outputProfiles))
				for name := range outputProfiles {
					availableOutputs = append(availableOutputs, name)
				}
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent output '%s' (available: %s)",
					domainName, output, strings.Join(availableOutputs, ", ")))
			}
		}

		// Ensure domain has at least one destination
		if len(effectiveOutputs) == 0 {
			errors = append(errors, fmt.Sprintf("domain '%s' has no destination configured (must have either a DNS provider or output profiles)", domainName))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "; "))
	}
	return nil
}

// ValidateInputProviderReferences validates that referenced input providers exist
func ValidateInputProviderReferences(domains map[string]DomainConfig, inputProfiles map[string]InputProviderConfig) error {
	var errors []string

	for domainName, domain := range domains {
		for _, inputProvider := range domain.GetInputProfiles() {
			if _, exists := inputProfiles[inputProvider]; !exists {
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent input provider '%s'", domainName, inputProvider))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "; "))
	}
	return nil
}

// ValidateOutputProfileReferences validates that referenced output profiles exist
func ValidateOutputProfileReferences(domains map[string]DomainConfig, outputProfiles map[string]interface{}) error {
	var errors []string

	for domainName, domain := range domains {
		// Check outputs using helper method
		for _, outputProfile := range domain.GetOutputs() {
			if _, exists := outputProfiles[outputProfile]; !exists {
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent output '%s'", domainName, outputProfile))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "; "))
	}
	return nil
}

// SetEnvVar sets an environment variable in the OS environment
func SetEnvVar(key, value string) {
	os.Setenv(key, value)
}

// ExtractDomainAndSubdomainForProvider extracts domain config key and subdomain for a specific provider
func ExtractDomainAndSubdomainForProvider(fqdn, providerName, logPrefix string) (string, string) {
	log.Trace("%s Extracting domain config for FQDN '%s' with provider '%s'", logPrefix, fqdn, providerName)

	// Remove trailing dot if present
	fqdn = strings.TrimSuffix(fqdn, ".")

	if GlobalConfig.Domains == nil {
		log.Error("%s No global config available for domain extraction", logPrefix)
		return "", ""
	}

	// Try to match domain configs that include this provider
	for configKey, domainConfig := range GlobalConfig.Domains {
		if domainConfig.Name == "" {
			continue
		}

		// Check if this provider is allowed for this domain config
		providerAllowed := false
		for _, inputProfile := range domainConfig.Profiles.Inputs {
			if inputProfile == providerName {
				providerAllowed = true
				break
			}
		}

		if !providerAllowed {
			log.Trace("%s Provider '%s' not allowed for domain config '%s' (inputs: %v)",
				logPrefix, providerName, configKey, domainConfig.Profiles.Inputs)
			continue
		}

		// Check if FQDN matches this domain
		domain := domainConfig.Name
		if fqdn == domain {
			// Exact match (root domain)
			log.Debug("%s Provider '%s' allowed for domain '%s' via config '%s'",
				logPrefix, providerName, domain, configKey)
			return configKey, "@"
		} else if strings.HasSuffix(fqdn, "."+domain) {
			// Subdomain match
			subdomain := strings.TrimSuffix(fqdn, "."+domain)
			log.Debug("%s Provider '%s' allowed for domain '%s' via config '%s'",
				logPrefix, providerName, domain, configKey)
			return configKey, subdomain
		}
	}

	log.Debug("%s No matching domain config found for FQDN '%s' with provider '%s'",
		logPrefix, fqdn, providerName)
	return "", ""
}
