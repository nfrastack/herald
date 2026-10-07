// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output"

	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
)

type ConfigFile struct {
	General    GeneralConfig                  `yaml:"general"`
	Defaults   DefaultsConfig                 `yaml:"defaults"`
	Inputs     map[string]InputProviderConfig `yaml:"inputs"`
	Domains    map[string]DomainConfig        `yaml:"domains"`
	Outputs    map[string]interface{}         `yaml:"outputs" json:"outputs"`
	API        *APIConfig                     `yaml:"api" json:"api"`
	StateDir   string                         `yaml:"state_dir" json:"state_dir"`
	StaleAfter string                         `yaml:"stale_after" json:"stale_after"`
}

func ExtractDomainAndSubdomainForProvider(fqdn, providerName, logPrefix string) (string, string) {
	log.NewScopedLogger("", "").With("action", "domain.match").Trace("%s domain config for FQDN '%s' with provider '%s'", logPrefix, fqdn, providerName)

	fqdn = strings.TrimSuffix(fqdn, ".")

	if GlobalConfig.Domains == nil {
		log.NewScopedLogger("", "").With("action", "config.error").Error("%s No global config available for domain extraction", logPrefix)
		return "", ""
	}

	for configKey, domainConfig := range GlobalConfig.Domains {
		if domainConfig.Name == "" {
			continue
		}

		providerAllowed := false
		for _, inputProfile := range domainConfig.Profiles.Inputs {
			if inputProfile == providerName {
				providerAllowed = true
				break
			}
		}

		if !providerAllowed {
			log.NewScopedLogger("", "").With("action", "domain.skip").Trace("%s Provider '%s' not allowed for domain config '%s' (inputs: %v)",
				logPrefix, providerName, configKey, domainConfig.Profiles.Inputs)
			continue
		}

		domain := domainConfig.Name
		if fqdn == domain {
			log.NewScopedLogger("", "").With("action", "domain.match").Debug("%s Provider '%s' allowed for domain '%s' via config '%s'",
				logPrefix, providerName, domain, configKey)
			return configKey, "@"
		} else if strings.HasSuffix(fqdn, "."+domain) {
			subdomain := strings.TrimSuffix(fqdn, "."+domain)
			log.NewScopedLogger("", "").With("action", "domain.match").Debug("%s Provider '%s' allowed for domain '%s' via config '%s'",
				logPrefix, providerName, domain, configKey)
			return configKey, subdomain
		}
	}

	log.NewScopedLogger("", "").With("action", "domain.skip").Debug("%s No matching domain config found for FQDN '%s' with provider '%s'",
		logPrefix, fqdn, providerName)
	return "", ""
}

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

type APITLSConfig struct {
	Verify bool   `yaml:"verify" json:"verify"` // TLS certificate verification (default: true)
	CA     string `yaml:"ca" json:"ca"`         // Custom CA certificate file
	Cert   string `yaml:"cert" json:"cert"`     // Server certificate file
	Key    string `yaml:"key" json:"key"`       // Server private key file
}

type APIClientProfile struct {
	Token         string   `yaml:"token" json:"token"`
	OutputProfile string   `yaml:"output_profile" json:"output_profile"`
	Domains       []string `yaml:"domains" json:"domains"`
	Hostnames     []string `yaml:"hostnames" json:"hostnames"`
	SharedWrites  bool     `yaml:"shared_writes" json:"shared_writes"`
}

type GeneralConfig struct {
	LogLevel             string   `yaml:"log_level"`
	LogTimestamps        bool     `yaml:"log_timestamps"`
	LogType              string   `yaml:"log_type"`
	LogFormat            string   `yaml:"log_format"`
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
	Proxied        bool   `yaml:"proxied"`
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

func GetConfig(config map[string]string, key string) string {
	value, ok := config[key]
	if !ok || value == "" {
		return ""
	}

	if len(value) > 7 && value[:7] == "file://" {
		filePath := value[7:]
		log.NewScopedLogger("", "").With("action", "config.load").Debug("[config] %s from file: %s", key, filePath)

		content, err := os.ReadFile(filePath)
		if err != nil {
			log.NewScopedLogger("", "").With("action", "config.error").Error("[config] read %s from file %s: %v", key, filePath, err)
			return ""
		}

		return strings.TrimSpace(string(content))
	}

	if len(value) > 6 && value[:6] == "env://" {
		envVar := value[6:]
		log.NewScopedLogger("", "").With("action", "config.load").Debug("[config] %s from environment variable: %s", key, envVar)

		if envValue := os.Getenv(envVar); envValue != "" {
			return envValue
		}

		log.NewScopedLogger("", "").With("action", "config.error").Warn("[config] Environment variable %s not found for %s", envVar, key)
		return ""
	}

	return value
}

func GetDomainConfig(domain string) map[string]string {
	domainConfigsMu.RLock()
	defer domainConfigsMu.RUnlock()

	if config, exists := domainConfigs[domain]; exists {
		return config
	}

	normalizedDomain := strings.ReplaceAll(domain, ".", "_")
	if config, exists := domainConfigs[normalizedDomain]; exists {
		return config
	}

	for _, config := range domainConfigs {
		if actualDomain, exists := config["name"]; exists && actualDomain == domain {
			return config
		}
	}

	return nil
}

func (cf *ConfigFile) GetDomains() map[string]output.DomainConfig {
	result := make(map[string]output.DomainConfig)
	for key, domainConfig := range cf.Domains {
		result[key] = &domainConfig
	}
	return result
}

type DomainProfiles struct {
	Inputs  []string `yaml:"inputs" json:"inputs"`
	Outputs []string `yaml:"outputs" json:"outputs"`
}

var (
	domainConfigsMu sync.RWMutex
	domainConfigs   = make(map[string]map[string]string)
)

var GlobalConfig ConfigFile

func GetGlobalConfig() *ConfigFile {
	return &GlobalConfig
}

func (dc *DomainConfig) GetInputProfiles() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Inputs
	}
	return []string{}
}

func (dc *DomainConfig) GetName() string {
	return dc.Name
}

func (ipc *InputProviderConfig) GetOptions(profileName string) map[string]string {
	options := make(map[string]string)
	val := reflect.ValueOf(*ipc)
	typ := reflect.TypeOf(*ipc)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		key := field.Tag.Get("yaml")
		if key == "" {
			key = strings.ToLower(field.Name)
		}
		if key == ",inline" {
			continue
		}
		if field.Type.Kind() == reflect.String {
			valStr := val.Field(i).String()
			if valStr != "" {
				options[key] = valStr
			}
		}
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
	for k, v := range ipc.Options {
		if k == "filter" {
			if filterData, err := json.Marshal(v); err == nil {
				options[k] = string(filterData)
				log.NewScopedLogger("", "").With("action", "config.load").Debug("[config] filter to JSON for %s: %s", profileName, string(filterData))
			} else {
				log.NewScopedLogger("", "").With("action", "config.error").Error("[config] convert filter to JSON for %s: %v", profileName, err)
				options[k] = fmt.Sprintf("%v", v)
			}
		} else {
			options[k] = fmt.Sprintf("%v", v)
		}
	}

	options["profile_name"] = profileName
	options["name"] = profileName

	return options
}

func (dc *DomainConfig) GetOutputs() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Outputs
	}
	return []string{}
}

func InitializeOutputManager() error {
	return InitializeOutputManagerWithProfiles(GlobalConfig.Outputs, GlobalConfig.General.OutputProfiles)
}

func InitializeOutputManagerWithProfiles(outputConfigs map[string]interface{}, enabledProfiles []string) error {
	outputManager := output.NewOutputManager()

	log.NewScopedLogger("", "").With("action", "provider.init").Trace("[config/output] output manager initialization")

	if outputConfigs != nil {
		profileNames := make([]string, 0, len(outputConfigs))
		for k := range outputConfigs {
			profileNames = append(profileNames, k)
		}
		log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] Output profiles found in config: %v", profileNames)

		enabledSet := make(map[string]bool)
		for _, profile := range enabledProfiles {
			enabledSet[profile] = true
		}

		for profileName, profileConfig := range outputConfigs {
			if len(enabledProfiles) > 0 && !enabledSet[profileName] {
				log.NewScopedLogger("", "").With("action", "sync.skip").Debug("[config/output] disabled profile: %s", profileName)
				continue
			}

			log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] profile: %s", profileName)
			log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] Raw config for %s: %+v", profileName, profileConfig)

			if configMap, ok := profileConfig.(map[string]interface{}); ok {
				log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] Available keys for %s: %v", profileName, func() []string {
					keys := make([]string, 0, len(configMap))
					for k := range configMap {
						keys = append(keys, k)
					}
					return keys
				}())

				outputType, _ := configMap["type"].(string)

				var format string
				switch outputType {
				case "file":
					format = "file"
					if fileFormat, exists := configMap["format"].(string); exists {
						log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] File type with format: %s", fileFormat)
					} else {
						log.NewScopedLogger("", "").With("action", "config.error").Error("[config/output] File type requires 'format' field (zone, hosts, yaml, json)")
						continue
					}
				case "remote":
					format = "remote"
					log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] remote type")
				case "dns":
					format = "dns"
					if provider, exists := configMap["provider"].(string); exists {
						log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] DNS type with provider: %s", provider)
					} else {
						log.NewScopedLogger("", "").With("action", "config.error").Error("[config/output] DNS type requires 'provider' field")
						continue
					}
				default:
					format, _ = configMap["format"].(string)
					if format == "" {
						log.NewScopedLogger("", "").With("action", "config.error").Error("[config/output] No 'type' field specified for profile '%s'. Must be 'file', 'remote', or 'dns'", profileName)
						continue
					}
				}

				log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] format for %s: '%s' (type: %s)", profileName, format, outputType)

				path, _ := configMap["path"].(string)
				domainsRaw := configMap["domains"]

				log.NewScopedLogger("", "").With("action", "config.load").Trace("[config/output] Output Profile %s: format=%s, path=%s, domains=%v", profileName, format, path, domainsRaw)

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

				profileConfigCopy := make(map[string]interface{})
				for k, v := range configMap {
					if k != "format" && k != "path" && k != "domains" && k != "type" {
						profileConfigCopy[k] = v
					}
				}

				err := outputManager.AddProfile(profileName, path, domains, profileConfigCopy)
				if err != nil {
					log.NewScopedLogger("", "").With("action", "output.write").Error("[output] add output profile '%s': %v", profileName, err)
					return err
				} else {
					log.NewScopedLogger("", "").With("action", "output.write").Verbose("[output] output profile '%s' (%s)", profileName, format)
				}
			} else {
				log.NewScopedLogger("", "").With("action", "config.validate").Warn("[config/output] profile '%s' invalid configuration type", profileName)
			}
		}
	} else {
		log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] no outputs configuration")
	}

	log.NewScopedLogger("", "").With("action", "config.load").Debug("[config/output] output profiles: %v", outputManager.ListProfileNames())

	output.SetGlobalOutputManager(outputManager)
	return nil
}

func LoadFileConfig(value, fieldName string) (string, error) {
	if !strings.HasPrefix(value, "file://") {
		return value, nil
	}

	filePath := value[7:] // Remove "file://" prefix
	log.NewScopedLogger("", "").With("action", "config.load").Debug("[config] %s from file: %s", fieldName, filePath)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s from file %s: %w", fieldName, filePath, err)
	}

	result := strings.TrimSpace(string(content))
	if result == "" {
		return "", fmt.Errorf("%s file %s is empty", fieldName, filePath)
	}

	log.NewScopedLogger("", "").With("action", "config.load").Verbose("[config] %s from file", fieldName)
	return result, nil
}

func (cf *ConfigFile) ResolveStateDir() string {
	if cf != nil && cf.StateDir != "" {
		return cf.StateDir
	}
	if env := os.Getenv("STATE_PATH"); env != "" {
		return env
	}
	return "/var/lib/herald"
}

func SetDomainConfigs(configs map[string]map[string]string) {
	domainConfigsMu.Lock()
	defer domainConfigsMu.Unlock()
	domainConfigs = configs
}

func SetEnvVar(key, value string) {
	os.Setenv(key, value)
}

func ValidateConfiguration(cfg *ConfigFile) error {
	var errors []string

	if cfg.General.SkipDomainValidation {
		log.NewScopedLogger("", "").With("action", "config.validate").Debug("[config] domain validation skipped as requested by skip_domain_validation=true")
		return nil
	}

	if err := ValidateDomainConfiguration(cfg.Domains, cfg.Inputs, cfg.Outputs); err != nil {
		errors = append(errors, err.Error())
	}

	if err := ValidateInputProviderReferences(cfg.Domains, cfg.Inputs); err != nil {
		errors = append(errors, err.Error())
	}

	if err := ValidateOutputProfileReferences(cfg.Domains, cfg.Outputs); err != nil {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

func ValidateDomainConfiguration(domains map[string]DomainConfig, inputProfiles map[string]InputProviderConfig, outputProfiles map[string]interface{}) error {
	var errors []string

	for domainName, domain := range domains {
		effectiveInputProfiles := domain.GetInputProfiles()

		effectiveOutputs := domain.GetOutputs()

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

		if len(effectiveOutputs) == 0 {
			errors = append(errors, fmt.Sprintf("domain '%s' has no destination configured (must have either a DNS provider or output profiles)", domainName))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

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
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

func ValidateOutputProfileReferences(domains map[string]DomainConfig, outputProfiles map[string]interface{}) error {
	var errors []string

	for domainName, domain := range domains {
		for _, outputProfile := range domain.GetOutputs() {
			if _, exists := outputProfiles[outputProfile]; !exists {
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent output '%s'", domainName, outputProfile))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}
