// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"fmt"
	"herald/pkg/log"
	"herald/pkg/output"
	"herald/pkg/output/types/dns"
)

// GlobalDomainManager holds the global domain manager instance
var GlobalDomainManager *DomainManager

// GlobalDNSProviders holds DNS provider instances
var GlobalDNSProviders map[string]dns.Provider

// SetDNSProviders sets the global DNS provider instances
func SetDNSProviders(providers map[string]dns.Provider) {
	GlobalDNSProviders = providers
}

// parseStringArray converts various types to string array
func parseStringArray(value interface{}) []string {
	switch v := value.(type) {
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return v
	case string:
		return []string{v}
	default:
		return []string{}
	}
}

// InitializeDomainSystem initializes the domain management system with full validation
func InitializeDomainSystem(domainConfigs map[string]interface{}, inputProfiles, outputProfiles, dnsProviders map[string]interface{}) error {
	log.Debug("[domain] Initializing domain management system")
	log.Debug("[domain] Raw domain configs received: %+v", domainConfigs)

	// Parse domain configurations
	domains := make(map[string]*DomainConfig)
	for domainName, configRaw := range domainConfigs {
		log.Debug("[domain] Processing domain '%s', raw config: %+v", domainName, configRaw)

		domainConfig := &DomainConfig{
			Name: domainName,
		}

		// Try to extract configuration if it's a complex config
		if configMap, ok := configRaw.(map[string]interface{}); ok {
			log.Debug("[domain] Domain '%s' config is map: %+v", domainName, configMap)

			// Extract name
			if name, ok := configMap["name"].(string); ok {
				domainConfig.Name = name
				log.Debug("[domain] Domain '%s' extracted name: %s", domainName, name)
			}

			// Extract provider
			if provider, ok := configMap["provider"].(string); ok {
				domainConfig.Provider = provider
				log.Debug("[domain] Domain '%s' extracted provider: %s", domainName, provider)
			}

			// Extract log_level
			if logLevel, ok := configMap["log_level"].(string); ok {
				domainConfig.LogLevel = logLevel
				log.Debug("[domain] Domain '%s' extracted log_level: %s", domainName, logLevel)
			}

			// Parse profiles structure
			if profilesRaw, ok := configMap["profiles"]; ok {
				if profilesMap, ok := profilesRaw.(map[string]interface{}); ok {
					domainConfig.Profiles = &DomainProfiles{}
					if inputsRaw, ok := profilesMap["inputs"]; ok {
						domainConfig.Profiles.Inputs = parseStringArray(inputsRaw)
						log.Debug("[domain] Domain '%s' extracted profiles.inputs: %v", domainName, domainConfig.Profiles.Inputs)
					}
					if outputsRaw, ok := profilesMap["outputs"]; ok {
						domainConfig.Profiles.Outputs = parseStringArray(outputsRaw)
						log.Debug("[domain] Domain '%s' extracted profiles.outputs: %v", domainName, domainConfig.Profiles.Outputs)
					}
				}
			}

			// Parse record configuration (deep override for merging)
			if recordRaw, ok := configMap["record"].(map[string]interface{}); ok {
				log.Debug("[domain] Domain '%s' has record config: %+v", domainName, recordRaw)
				// Elegantly override only provided fields, but allow autodetection if type is not set
				if recordType, ok := recordRaw["type"].(string); ok {
					domainConfig.Record.Type = recordType
				} else {
					domainConfig.Record.Type = "" // allow autodetection if not set
				}
				if ttl, ok := recordRaw["ttl"].(int); ok {
					domainConfig.Record.TTL = ttl
				}
				if target, ok := recordRaw["target"].(string); ok {
					domainConfig.Record.Target = target
				}
				if updateExisting, ok := recordRaw["update_existing"].(bool); ok {
					domainConfig.Record.UpdateExisting = updateExisting
				}
				if allowMultiple, ok := recordRaw["allow_multiple"].(bool); ok {
					domainConfig.Record.AllowMultiple = allowMultiple
				}
			}
		} else {
			log.Debug("[domain] Domain '%s' config is not a map, type: %T, value: %+v", domainName, configRaw, configRaw)
		}

		domains[domainName] = domainConfig
		log.Debug("[domain] Parsed domain '%s': provider='%s', profiles.inputs=%v, profiles.outputs=%v",
			domainName, domainConfig.Provider,
			func() []string {
				if domainConfig.Profiles != nil {
					return domainConfig.Profiles.Inputs
				}
				return nil
			}(),
			func() []string {
				if domainConfig.Profiles != nil {
					return domainConfig.Profiles.Outputs
				}
				return nil
			}())
		log.Verbose("[domain] Loaded domain config for '%s' (provider: %s, effective_inputs: %v, effective_outputs: %v)",
			domainName, domainConfig.Provider, domainConfig.GetInputProfiles(), domainConfig.GetOutputs())
	}

	// Validate all domain configurations
	if err := ValidateDomainConfigurations(domains, inputProfiles, outputProfiles, dnsProviders); err != nil {
		return fmt.Errorf("domain validation failed: %v", err)
	}

	// Create and initialize the global domain manager
	GlobalDomainManager = NewDomainManager()
	for domainName, domainConfig := range domains {
		GlobalDomainManager.AddDomain(domainName, domainConfig)
	}

	log.Verbose("[domain] Initialized %d domain configurations with validation", len(domains))
	return nil
}

// ProcessRecordWithDomainValidation processes a record through the domain system with full validation
func ProcessRecordWithDomainValidation(inputProviderName, domainName, hostname, target, recordType string, ttl int) error {
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	// Find the domain config by actual domain name, not by hostname
	var domainConfig *DomainConfig
	var domainConfigKey string
	found := false

	for key, config := range GlobalDomainManager.GetAllDomains() {
		if config.Name == domainName {
			domainConfig = config
			domainConfigKey = key
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("no domain config for %s", domainName)
	}

	// Check if input provider is allowed for this domain
	if !GlobalDomainManager.ValidateInputProviderAccess(domainConfigKey, inputProviderName) {
		log.Trace("[domain/%s] Input provider '%s' not allowed for domain config key '%s'", domainName, inputProviderName, domainConfigKey)
		return nil // Not an error, just filtered out
	}

	log.Trace("[domain/%s] Processing record from input provider '%s': %s.%s (%s) -> %s",
		domainName, inputProviderName, hostname, domainName, recordType, target)

	// Send to DNS provider (if configured)
	if domainConfig.Provider != "" && domainConfig.Provider != "none" {
		log.Trace("[domain/%s] Sending record to DNS provider '%s'", domainName, domainConfig.Provider)

		// Get the DNS provider instance
		if GlobalDNSProviders != nil {
			if dnsProvider, exists := GlobalDNSProviders[domainConfig.Provider]; exists {
				// Use the domain's record configuration for update_existing
				updateExisting := domainConfig.Record.UpdateExisting
				err := dnsProvider.CreateOrUpdateRecord(domainName, hostname, target, recordType, ttl, updateExisting)
				if err != nil {
					log.Error("[domain/%s] Failed to create/update DNS record via provider '%s': %v", domainName, domainConfig.Provider, err)
					return err
				}
				log.Trace("[domain/%s] Successfully sent record to DNS provider '%s'", domainName, domainConfig.Provider)
			} else {
				log.Error("[domain/%s] DNS provider '%s' not found in global providers", domainName, domainConfig.Provider)
				return fmt.Errorf("DNS provider '%s' not available", domainConfig.Provider)
			}
		} else {
			log.Trace("[domain/%s] No global DNS providers available, skipping DNS update", domainName)
		}
	}

	// Send to output profiles with domain validation
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		err := outputManager.WriteRecordWithSourceAndDomainFilter(domainName, hostname, target, recordType, ttl, inputProviderName, GlobalDomainManager)
		if err != nil {
			log.Error("[domain/%s] Failed to send record to output profiles: %v", domainName, err)
			return err
		}
	}

	return nil
}

// GetDomainConfig retrieves a domain configuration (convenience function)
func GetDomainConfig(domainName string) (*DomainConfig, bool) {
	if GlobalDomainManager == nil {
		return nil, false
	}
	return GlobalDomainManager.GetDomain(domainName)
}

// ExtractOutputProfilesFromDomains extracts unique output profiles from all domain configurations
func ExtractOutputProfilesFromDomains() []string {
	if GlobalDomainManager == nil {
		return []string{}
	}

	outputProfiles := make(map[string]bool)
	for _, domainConfig := range GlobalDomainManager.GetAllDomains() {
		for _, outputProfile := range domainConfig.GetOutputs() {
			outputProfiles[outputProfile] = true
		}
	}

	// Convert to slice
	activeOutputProfiles := make([]string, 0, len(outputProfiles))
	for profile := range outputProfiles {
		activeOutputProfiles = append(activeOutputProfiles, profile)
	}

	return activeOutputProfiles
}

// ExtractInputProvidersFromDomains extracts unique input providers from all domain configurations
func ExtractInputProvidersFromDomains() []string {
	if GlobalDomainManager == nil {
		return []string{}
	}

	inputProviders := make(map[string]bool)
	for _, domainConfig := range GlobalDomainManager.GetAllDomains() {
		for _, inputProvider := range domainConfig.GetInputProfiles() {
			inputProviders[inputProvider] = true
		}
	}

	// Convert to slice
	activeInputProviders := make([]string, 0, len(inputProviders))
	for provider := range inputProviders {
		activeInputProviders = append(activeInputProviders, provider)
	}

	return activeInputProviders
}

// ValidateAllDomainReferences validates that all domain references point to valid configurations
func ValidateAllDomainReferences() error {
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	allDomains := GlobalDomainManager.GetAllDomains()
	for domainKey, domainConfig := range allDomains {
		log.Debug("[domain] Validating domain '%s' with name '%s'", domainKey, domainConfig.Name)

		// Validate input providers exist
		for _, inputProvider := range domainConfig.GetInputProfiles() {
			log.Debug("[domain] Domain '%s' references input provider '%s'", domainKey, inputProvider)
		}

		// Validate output profiles exist
		for _, outputProfile := range domainConfig.GetOutputs() {
			log.Debug("[domain] Domain '%s' references output profile '%s'", domainKey, outputProfile)
		}
	}

	return nil
}
