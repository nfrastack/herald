// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"dns-companion/pkg/log"

	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Environment variable handling
var (
	// envCacheLock protects the environment variable cache
	envCacheLock sync.RWMutex

	// EnvCache is a cache of environment variables
	EnvCache = make(map[string]string)

	// Regular expressions to match environment variable patterns
	domainNameRegex = regexp.MustCompile(`^DOMAIN_([A-Za-z0-9_]+)_(.+)$`)
	pollRegex       = regexp.MustCompile(`^POLL_([A-Za-z0-9_]+)_(.+)$`)
	providerRegex   = regexp.MustCompile(`^PROVIDER_([A-Za-z0-9_]+)_(.+)$`)
)

// LoadFromEnvironment loads configuration values from environment variables and overrides values in the provided config
func LoadFromEnvironment(cfg *ConfigFile) {
	// Load .env file if present
	if _, err := os.Stat(".env"); err == nil {
		file, err := os.Open(".env")
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if eq := strings.Index(line, "="); eq != -1 {
					key := strings.TrimSpace(line[:eq])
					val := strings.TrimSpace(line[eq+1:])
					if os.Getenv(key) == "" {
						os.Setenv(key, val)
					}
				}
			}
			file.Close()
		}
	}

	// General application settings
	setLogLevelFromEnv(cfg)

	// Determine effective log_timestamps (env > config > default)
	logTimestamps := true // default
	if val := os.Getenv("LOG_TIMESTAMPS"); val != "" {
		valLower := strings.ToLower(val)
		if valLower == "false" || valLower == "0" || valLower == "no" {
			logTimestamps = false
		} else if valLower == "true" || valLower == "1" || valLower == "yes" {
			logTimestamps = true
		}
	} else {
		logTimestamps = cfg.General.LogTimestamps
	}
	cfg.General.LogTimestamps = logTimestamps

	// Process poll environment variables
	processPollsFromEnv(cfg)

	// Process provider environment variables
	processProvidersFromEnv(cfg)

	// Process output profiles from environment
	processOutputProfilesFromEnv(cfg)

	// Domain configurations
	setDomainSettingsFromEnv(cfg)

	// Ensure cfg.Domains, cfg.Polls, and cfg.Providers are fully merged and ready for use
	mergeEnvironmentOverrides(cfg)

	// Log what we've loaded
	log.Debug("[config/env] Loaded configuration from environment variables")
}

// processPollsFromEnv handles POLL_<name>_<option> environment variables
func processPollsFromEnv(cfg *ConfigFile) {
	pollTypes := make(map[string]string)
	// First, find all poll definitions from environment variables
	for _, envVar := range getAllEnvVars() {
		matches := pollRegex.FindStringSubmatch(envVar)
		if len(matches) == 3 {
			profileName := strings.ToLower(matches[1])
			optionName := strings.ToLower(matches[2])
			if optionName == "type" {
				value := os.Getenv(envVar)
				if value != "" {
					pollTypes[profileName] = value
					log.Debug("[config/env] Found poll profile '%s' with type '%s'", profileName, value)
					if _, exists := cfg.Polls[profileName]; !exists {
						cfg.Polls[profileName] = PollProviderConfig{
							Type:    value,
							Options: make(map[string]interface{}),
						}
					} else {
						poll := cfg.Polls[profileName]
						poll.Type = value
						cfg.Polls[profileName] = poll
					}
				}
			}
		}
	}
	// Now process all other options for the polls
	for _, envVar := range getAllEnvVars() {
		matches := pollRegex.FindStringSubmatch(envVar)
		if len(matches) != 3 || strings.ToLower(matches[2]) == "type" {
			continue
		}
		profileName := strings.ToLower(matches[1])
		option := strings.ToLower(matches[2])
		value := os.Getenv(envVar)
		if value == "" {
			continue
		}
		pollType, hasType := pollTypes[profileName]
		if !hasType || pollType == "" {
			continue // skip if no type set for this profile
		}
		if _, exists := cfg.Polls[profileName]; !exists {
			cfg.Polls[profileName] = PollProviderConfig{
				Type:    pollType,
				Options: make(map[string]interface{}),
			}
		}
		// Special case for expose_containers
		if option == "expose_containers" {
			poll := cfg.Polls[profileName]
			poll.ExposeContainers = EnvToBool(envVar, false)
			cfg.Polls[profileName] = poll
			log.Debug("[config/env] Set poll profile '%s' option 'expose_containers' to '%v'", profileName, cfg.Polls[profileName].ExposeContainers)
			continue
		}
		if cfg.Polls[profileName].Options == nil {
			poll := cfg.Polls[profileName]
			poll.Options = make(map[string]interface{})
			cfg.Polls[profileName] = poll
		}
		poll := cfg.Polls[profileName]
		poll.Options[option] = value
		cfg.Polls[profileName] = poll
		log.Debug("[config/env] Set poll profile '%s' option '%s' to '%s'", profileName, option, value)
	}
}

// processProvidersFromEnv handles PROVIDER_<name>_<option> environment variables
func processProvidersFromEnv(cfg *ConfigFile) {
	// Map to store provider names and their types
	providerTypes := make(map[string]string)

	// First, find all provider definitions from environment variables
	// Look for PROVIDER_<NAME>_TYPE variables to determine the providers
	for _, envVar := range getAllEnvVars() {
		matches := providerRegex.FindStringSubmatch(envVar)
		if len(matches) == 3 {
			providerName := strings.ToLower(matches[1])
			optionName := strings.ToLower(matches[2])

			// If this is a TYPE variable, record the provider type
			if optionName == "type" {
				value := os.Getenv(envVar)
				if value != "" {
					providerTypes[providerName] = value
					log.Debug("[config/env] Found provider '%s' with type '%s'", providerName, value)

					// Create provider if it doesn't exist
					if _, exists := cfg.Providers[providerName]; !exists {
						cfg.Providers[providerName] = DNSProviderConfig{
							Type:    value,
							Options: make(map[string]interface{}),
						}
					} else {
						// Update the type of existing provider
						provider := cfg.Providers[providerName]
						provider.Type = value
						cfg.Providers[providerName] = provider
					}
				}
			}
		}
	}

	// Now process all other options for the providers
	for _, envVar := range getAllEnvVars() {
		matches := providerRegex.FindStringSubmatch(envVar)
		if len(matches) != 3 || strings.ToLower(matches[2]) == "type" {
			// Skip if not a provider variable or if it's a TYPE variable (already processed)
			continue
		}

		providerName := strings.ToLower(matches[1])
		optionFullName := strings.ToLower(matches[2])
		value := os.Getenv(envVar)

		// Skip if value is empty
		if value == "" {
			continue
		}

		log.Debug("[config/env] Processing provider env var: %s=%s", envVar, value)

		// Create provider if it doesn't exist
		if _, exists := cfg.Providers[providerName]; !exists {
			// If we don't know the type yet, default to the provider name
			providerType := providerTypes[providerName]
			if providerType == "" {
				providerType = providerName
			}

			cfg.Providers[providerName] = DNSProviderConfig{
				Type:    providerType,
				Options: make(map[string]interface{}),
			}
		}

		// Split the option name to get specific provider type and actual option
		// Format: PROVIDER_<NAME>_<PROVIDER-TYPE>_<OPTION> or PROVIDER_<NAME>_<OPTION>
		parts := strings.SplitN(optionFullName, "_", 2)

		// If there's just one part, it's a direct field
		var option string
		if len(parts) == 1 {
			option = parts[0]
		} else {
			providerPrefix := parts[0]
			option = parts[1]

			// Check if this option should be processed based on the provider's type
			providerType := strings.ToLower(cfg.Providers[providerName].Type)

			// Only process if the provider prefix matches the provider type
			// or if this is a generic option
			if providerPrefix != providerType && providerPrefix != "option" {
				continue
			}
		}

		// Handle direct fields based on option name
		switch option {
		case "api_token":
			provider := cfg.Providers[providerName]
			provider.APIToken = value
			cfg.Providers[providerName] = provider
		case "api_key":
			provider := cfg.Providers[providerName]
			provider.APIKey = value
			cfg.Providers[providerName] = provider
		case "api_email", "email":
			provider := cfg.Providers[providerName]
			provider.APIEmail = value
			cfg.Providers[providerName] = provider
		case "default_ttl", "ttl":
			_, err := strconv.Atoi(value)
			if err == nil {
				log.Warn("[config/env] Default TTL is no longer supported in provider configuration. Use cfg.Defaults.Record.TTL instead.")
			} else {
				log.Warn("[config/env] Invalid TTL value for provider %s: %s", providerName, value)
			}
		default:
			// For any other option, store it in the options map
			if cfg.Providers[providerName].Options == nil {
				provider := cfg.Providers[providerName]
				provider.Options = make(map[string]interface{})
				cfg.Providers[providerName] = provider
			}
			provider := cfg.Providers[providerName]
			provider.Options[option] = value
			cfg.Providers[providerName] = provider
		}

		log.Debug("[config/env] Set provider '%s' option '%s'", providerName, option)
	}

	// Don't set default DNS provider unless explicitly configured
}

// processOutputProfilesFromEnv handles OUTPUT_PROFILES environment variable
func processOutputProfilesFromEnv(cfg *ConfigFile) {
	if outputProfiles := GetEnvVar("OUTPUT_PROFILES", ""); outputProfiles != "" {
		profiles := strings.Split(outputProfiles, ",")
		// Trim whitespace from each profile
		for i := range profiles {
			profiles[i] = strings.TrimSpace(profiles[i])
		}
		cfg.General.OutputProfiles = profiles
		log.Debug("[config/env] Set output_profiles from environment: %v", cfg.General.OutputProfiles)
	}
}

// getAllEnvVars returns all environment variables as a slice of strings
func getAllEnvVars() []string {
	result := []string{}
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) > 0 {
			result = append(result, parts[0])
		}
	}
	return result
}

// setLogLevelFromEnv sets the log level from environment
func setLogLevelFromEnv(cfg *ConfigFile) {
	if level := GetEnvVar("LOG_LEVEL", ""); level != "" {
		upperLevel := strings.ToUpper(level)
		// Only update the config struct, do not set the logger here
		// Logger will be initialized later with the final value
		switch upperLevel {
		case "TRACE":
			cfg.General.LogLevel = "trace"
		case "DEBUG":
			cfg.General.LogLevel = "debug"
		case "VERBOSE":
			cfg.General.LogLevel = "verbose"
		case "INFO":
			cfg.General.LogLevel = "info"
		case "WARN", "WARNING":
			cfg.General.LogLevel = "warn"
		case "ERROR":
			cfg.General.LogLevel = "error"
		default:
			log.Warn("[config/env] Unknown log level '%s', using current level", level)
		}
		log.Debug("[config/env] Set log level to '%s' from environment", cfg.General.LogLevel)
	}
}

// setDomainSettingsFromEnv configures domains from environment variables
func setDomainSettingsFromEnv(cfg *ConfigFile) {
	// Process named domains (DOMAIN_<NAME>_*) format

	// First, find all domain names from environment variables
	domainNames := make(map[string]string) // map[domainKeyInEnvVar]actualDomainName

	for _, envVar := range getAllEnvVars() {
		matches := domainNameRegex.FindStringSubmatch(envVar)
		if len(matches) == 3 && matches[2] == "NAME" {
			domainKey := strings.ToLower(matches[1])
			domainName := GetEnvVar(envVar, "")

			if domainName != "" {
				domainNames[domainKey] = domainName
				log.Debug("[config/env] Found named domain '%s' with key '%s'", domainName, domainKey)
			}
		}
	}

	// Now process all domain settings
	for domainKey, domainName := range domainNames {
		// Create domain mapping if it doesn't exist
		if cfg.Domains == nil {
			cfg.Domains = make(map[string]DomainConfig)
		}

		// Convert dots to underscores for the config key
		configKey := strings.ReplaceAll(domainName, ".", "_")

		// Create or update domain config
		domainCfg, exists := cfg.Domains[configKey]
		if !exists {
			domainCfg = DomainConfig{
				Name: domainName,
			}
		}

		// Process all environment variables for this domain
		setNamedDomainConfigFromEnv(domainKey, domainName, configKey, &domainCfg)

		// Save the domain config
		cfg.Domains[configKey] = domainCfg
	}
}

// setNamedDomainConfigFromEnv configures a specific domain from environment variables using named format
func setNamedDomainConfigFromEnv(domainKey, domainName, configKey string, domainCfg *DomainConfig) {
	prefix := fmt.Sprintf("DOMAIN_%s_", strings.ToUpper(domainKey))

	// Zone ID
	if zoneID := GetEnvVar(prefix+"ZONE_ID", ""); zoneID != "" {
		domainCfg.ZoneID = zoneID
		log.Debug("[config/env] Set zone ID for domain '%s' to '%s'", domainName, zoneID)
	}

	// Provider specific
	if provider := GetEnvVar(prefix+"PROVIDER", ""); provider != "" {
		domainCfg.Provider = provider
		log.Debug("[config/env] Set provider for domain '%s' to '%s'", domainName, provider)
	}

	// TTL
	if ttlStr := GetEnvVar(prefix+"TTL", ""); ttlStr != "" {
		if ttl, err := strconv.Atoi(ttlStr); err == nil {
			domainCfg.Record.TTL = ttl
			log.Debug("[config/env] Set TTL for domain '%s' to %d", domainName, ttl)
		} else {
			log.Warn("[config/env] Invalid TTL value '%s' for domain '%s'", ttlStr, domainName)
		}
	}

	// Target domain
	if target := GetEnvVar(prefix+"TARGET", ""); target != "" {
		domainCfg.Record.Target = target
		log.Debug("[config/env] Set target for domain '%s' to '%s'", domainName, target)
	}

	// Record type
	if recordType := GetEnvVar(prefix+"RECORD_TYPE", ""); recordType != "" {
		domainCfg.Record.Type = recordType
		log.Debug("[config/env] Set record type for domain '%s' to '%s'", domainName, recordType)
	}

	// Proxied (Cloudflare specific) - Add to Options map since Proxied field doesn't exist
	if proxiedStr := GetEnvVar(prefix+"PROXIED", ""); proxiedStr != "" {
		if domainCfg.Options == nil {
			domainCfg.Options = make(map[string]string)
		}
		domainCfg.Options["proxied"] = proxiedStr
		log.Debug("[config/env] Set proxied for domain '%s' to %s", domainName, proxiedStr)
	}

	// Update existing records
	if updateStr := GetEnvVar(prefix+"UPDATE_EXISTING", ""); updateStr != "" {
		domainCfg.Record.UpdateExisting = EnvToBool(prefix+"UPDATE_EXISTING", domainCfg.Record.UpdateExisting)
		log.Debug("[config/env] Set record update existing for domain '%s' to %v", domainName, domainCfg.Record.UpdateExisting)
	}

	// Excluded subdomains - Add to Options map since ExcludedSubdomains field doesn't exist
	if excluded := GetEnvVar(prefix+"EXCLUDED_SUBDOMAINS", ""); excluded != "" {
		if domainCfg.Options == nil {
			domainCfg.Options = make(map[string]string)
		}
		domainCfg.Options["excluded_subdomains"] = excluded
		log.Debug("[config/env] Set excluded subdomains for domain '%s' to %s", domainName, excluded)
	}

	// RecordTypeAMultiple
	if v := GetEnvVar(prefix+"RECORD_TYPE_A_MULTIPLE", ""); v != "" {
		domainCfg.Record.AllowMultiple = EnvToBool(prefix+"RECORD_TYPE_A_MULTIPLE", false)
		log.Debug("[config/env] Set record type A multiple for domain '%s' to %v", domainName, domainCfg.Record.AllowMultiple)
	}

	// RecordTypeAAAAMultiple (not directly supported in struct, but can be added to Options if needed)
	if v := GetEnvVar(prefix+"RECORD_TYPE_AAAA_MULTIPLE", ""); v != "" {
		if domainCfg.Options == nil {
			domainCfg.Options = make(map[string]string)
		}
		domainCfg.Options["record_type_aaaa_multiple"] = v
		log.Debug("[config/env] Set record type AAAA multiple for domain '%s' to %v", domainName, v)
	}

	// Process any options with prefix DOMAIN_<NAME>_OPTION_
	optionPrefix := prefix + "OPTION_"
	for _, envVar := range getAllEnvVars() {
		if strings.HasPrefix(envVar, optionPrefix) {
			optionName := strings.ToLower(envVar[len(optionPrefix):])
			value := GetEnvVar(envVar, "")

			if value != "" {
				if domainCfg.Options == nil {
					domainCfg.Options = make(map[string]string)
				}
				domainCfg.Options[optionName] = value
				log.Debug("[config/env] Set custom option '%s' for domain '%s' to '%s'", optionName, domainName, value)
			}
		}
	}
}

// mergeEnvironmentOverrides ensures cfg.Domains, cfg.Polls, and cfg.Providers are fully merged and ready for use
func mergeEnvironmentOverrides(cfg *ConfigFile) {
	// Merge domains
	for domainKey, domainCfg := range cfg.Domains {
		if domainCfg.Options == nil {
			domainCfg.Options = make(map[string]string)
		}
		cfg.Domains[domainKey] = domainCfg
	}

	// Merge polls
	for pollKey, pollCfg := range cfg.Polls {
		if pollCfg.Options == nil {
			pollCfg.Options = make(map[string]interface{})
		}
		cfg.Polls[pollKey] = pollCfg
	}

	// Merge providers
	for providerKey, providerCfg := range cfg.Providers {
		if providerCfg.Options == nil {
			providerCfg.Options = make(map[string]interface{})
		}
		cfg.Providers[providerKey] = providerCfg
	}
}

// ApplyConfigToEnv applies configuration settings to environment variables
// This allows environment-aware components to use config values
func ApplyConfigToEnv(cfg *ConfigFile, prefix string) {
	// Only set environment variables if they were already present in the environment
	setIfPresent := func(key, value string) {
		if _, present := os.LookupEnv(key); present {
			os.Setenv(key, value)
		}
	}

	// Set up basic global settings as environment variables
	if cfg.General.LogLevel != "" {
		setIfPresent("LOG_LEVEL", cfg.General.LogLevel)
	}

	if cfg.Defaults.Record.Type != "" {
		setIfPresent("GLOBAL_RECORD_TYPE", cfg.Defaults.Record.Type)
	}

	if cfg.Defaults.Record.Target != "" {
		setIfPresent("GLOBAL_TARGET", cfg.Defaults.Record.Target)
	}

	if cfg.Defaults.Record.TTL > 0 {
		setIfPresent("GLOBAL_TTL", strconv.Itoa(cfg.Defaults.Record.TTL))
	}

	setIfPresent("GLOBAL_UPDATE_EXISTING", strconv.FormatBool(cfg.Defaults.Record.UpdateExisting))

	for providerName, provider := range cfg.Providers {
		prefix := fmt.Sprintf("PROVIDER_%s_", strings.ToUpper(providerName))
		setIfPresent(prefix+"TYPE", provider.Type)
		providerTypePrefix := fmt.Sprintf("PROVIDER_%s_%s_", strings.ToUpper(providerName), strings.ToUpper(provider.Type))
		if provider.APIToken != "" {
			setIfPresent(prefix+"API_TOKEN", provider.APIToken)
			setIfPresent(providerTypePrefix+"API_TOKEN", provider.APIToken)
		}
		if provider.APIKey != "" {
			setIfPresent(prefix+"API_KEY", provider.APIKey)
			setIfPresent(providerTypePrefix+"API_KEY", provider.APIKey)
		}
		if provider.APIEmail != "" {
			setIfPresent(prefix+"API_EMAIL", provider.APIEmail)
			setIfPresent(providerTypePrefix+"API_EMAIL", provider.APIEmail)
		}
		if providerName == "cloudflare" || provider.Type == "cloudflare" {
			if provider.APIEmail != "" {
				setIfPresent("CF_EMAIL", provider.APIEmail)
			}
			if provider.APIToken != "" {
				setIfPresent("CF_TOKEN", provider.APIToken)
			}
		}
		for option, value := range provider.Options {
			setIfPresent(prefix+strings.ToUpper(option), fmt.Sprintf("%v", value))
			setIfPresent(providerTypePrefix+strings.ToUpper(option), fmt.Sprintf("%v", value))
		}
	}
}

// Cache-related functions

// CacheEnvVar adds or updates a value in the environment variable cache
func CacheEnvVar(key, value string) {
	envCacheLock.Lock()
	defer envCacheLock.Unlock()
	EnvCache[key] = value
}

// GetCachedEnvVar retrieves a value from the cache, or if not present,
// reads it from the environment and adds it to the cache
func GetCachedEnvVar(key, defaultValue string) string {
	// First try to get from cache
	envCacheLock.RLock()
	value, exists := EnvCache[key]
	envCacheLock.RUnlock()

	if exists {
		return value
	}

	// If not in cache, get from environment
	value = os.Getenv(key)
	if value == "" {
		value = defaultValue
	}

	// If value starts with file: or file://, read the file contents
	if strings.HasPrefix(value, "file://") {
		filePath := strings.TrimPrefix(value, "file://")
		if data, err := os.ReadFile(filePath); err == nil {
			value = strings.TrimSpace(string(data))
		}
	} else if strings.HasPrefix(value, "file:") {
		filePath := strings.TrimPrefix(value, "file:")
		if data, err := os.ReadFile(filePath); err == nil {
			value = strings.TrimSpace(string(data))
		}
	}

	// Cache the value for future use
	CacheEnvVar(key, value)

	return value
}

// ClearEnvCache empties the environment variable cache
func ClearEnvCache() {
	envCacheLock.Lock()
	defer envCacheLock.Unlock()
	EnvCache = make(map[string]string)
}

// Environment helper functions

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

// EnvToBool converts an environment variable to a boolean value
// Supports "true", "false", "1", "0", "yes", "no" (case-insensitive)
func EnvToBool(key string, defaultValue bool) bool {
	value := GetEnvVar(key, "")
	if value == "" {
		return defaultValue
	}

	valueLower := strings.ToLower(value)
	if valueLower == "true" || valueLower == "1" || valueLower == "yes" {
		return true
	} else if valueLower == "false" || valueLower == "0" || valueLower == "no" {
		return false
	}

	return defaultValue
}

// EnvToInt converts an environment variable to an integer value
func EnvToInt(key string, defaultValue int) int {
	value := GetEnvVar(key, "")
	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return intValue
}

// GetEnvVarBool gets a boolean environment variable with a default value
func GetEnvVarBool(key string, defaultValue bool) bool {
	return EnvToBool(key, defaultValue)
}

// GetEnvVarInt gets an integer environment variable with a default value
func GetEnvVarInt(key string, defaultValue int) int {
	return EnvToInt(key, defaultValue)
}

// ApplyLoggingConfig initializes the logger using the effective log level and log_timestamps from config
func ApplyLoggingConfig(cfg *ConfigFile) {
	level := cfg.General.LogLevel
	if level == "" {
		level = "info"
	}
	showTimestamps := cfg.General.LogTimestamps
	log.Initialize(level, showTimestamps)
}
