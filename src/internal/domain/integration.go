// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"fmt"
	"github.com/nfrastack/herald/internal/common"
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output"
	"github.com/nfrastack/herald/internal/output/types/dns"
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
	log.Debug("[domain] Raw domain configs received: %+v", domainConfigs)

	// Parse domain configurations
	domains := make(map[string]*DomainConfig)
	for domainName, configRaw := range domainConfigs {
		log.NewScopedLogger("", "").With("domain", domainName).Debug("Processing domain, raw config: %+v", configRaw)

		domainConfig := &DomainConfig{
			Name: domainName,
		}

		// Try to extract configuration if it's a complex config
		if configMap, ok := configRaw.(map[string]interface{}); ok {
			log.NewScopedLogger("", "").With("domain", domainName).Debug("Domain config is map: %+v", configMap)

			// Extract name
			if name, ok := configMap["name"].(string); ok {
				domainConfig.Name = name
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted name: %s", name)
			}

			// Extract provider
			if provider, ok := configMap["provider"].(string); ok {
				domainConfig.Provider = provider
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted provider: %s", provider)
			}

			// Extract log_level
			if logLevel, ok := configMap["log_level"].(string); ok {
				domainConfig.LogLevel = logLevel
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted log_level: %s", logLevel)
			}

			// Parse profiles structure
			if profilesRaw, ok := configMap["profiles"]; ok {
				if profilesMap, ok := profilesRaw.(map[string]interface{}); ok {
					domainConfig.Profiles = &DomainProfiles{}
					if inputsRaw, ok := profilesMap["inputs"]; ok {
						domainConfig.Profiles.Inputs = parseStringArray(inputsRaw)
						log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted profiles.inputs: %v", domainConfig.Profiles.Inputs)
					}
					if outputsRaw, ok := profilesMap["outputs"]; ok {
						domainConfig.Profiles.Outputs = parseStringArray(outputsRaw)
						log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted profiles.outputs: %v", domainConfig.Profiles.Outputs)
					}
				}
			}

			// Parse record configuration (deep override for merging)
			if recordRaw, ok := configMap["record"].(map[string]interface{}); ok {
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Has record config: %+v", recordRaw)
				// Elegantly override only provided fields, but allow autodetection if type is not set
				if recordType, ok := recordRaw["type"].(string); ok {
					domainConfig.Record.Type = recordType
				} else {
					domainConfig.Record.Type = ""
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
				if proxied, ok := recordRaw["proxied"].(bool); ok {
					domainConfig.Record.Proxied = proxied
				}
			}
		} else {
			log.NewScopedLogger("", "").With("domain", domainName).Debug("Config is not a map, type: %T, value: %+v", configRaw, configRaw)
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

	return nil
}

// ProcessRecordWithDomainValidation processes a record through the domain system with full validation
func ProcessRecordWithDomainValidation(inputProviderName, domainName, hostname, target, recordType string, ttl int) error {
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	// Find the domain config by actual domain name AND input provider
	var domainConfig *DomainConfig
	var domainConfigKey string
	found := false

	for key, config := range GlobalDomainManager.GetAllDomains() {
		if config.Name == domainName && GlobalDomainManager.ValidateInputProviderAccess(key, inputProviderName) {
			domainConfig = config
			domainConfigKey = key
			found = true
			break
		}
	}

	if !found {
		log.NewScopedLogger("", "").With("domain", domainName, "input", inputProviderName).Trace("No domain config for input provider")
		return nil // Not an error, just filtered out
	}

	// Check if input provider is allowed for this domain
	if !GlobalDomainManager.ValidateInputProviderAccess(domainConfigKey, inputProviderName) {
		log.NewScopedLogger("", "").With("domain", domainName, "input", inputProviderName, "config", domainConfigKey).Trace("Input provider not allowed for domain config key")
		return nil // Not an error, just filtered out
	}

	log.NewScopedLogger("", "").With("domain", domainName, "input", inputProviderName).Trace("Processing record: %s.%s (%s) -> %s", hostname, domainName, recordType, target)
	// Determine proxied flag once for use by both DNS provider and output manager
	proxiedFlag := domainConfig.Record.Proxied
	// Log where proxied came from for easier debugging
	if domainConfig.Record.Proxied {
		log.NewScopedLogger("", "").With("config", domainConfigKey).Debug("Proxied set from record config (record.proxied=true)")
	} else {
		log.NewScopedLogger("", "").With("config", domainConfigKey).Trace("Proxied not set for this domain/record")
	}

	// Send to DNS provider (if configured)
	// DNS provider writes are handled by the output manager to avoid duplicate writes.
	// The output manager will route to DNS output profiles (including the configured provider)
	// and honor the domain-level proxied flag. This avoids calling providers twice.

	// Send to output profiles with domain validation
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		err := outputManager.WriteRecordWithSourceAndDomainFilter(domainConfigKey, domainName, hostname, target, recordType, ttl, inputProviderName, proxiedFlag, false, GlobalDomainManager)
		if err != nil {
			log.NewScopedLogger("", "").With("domain", domainName, "input", inputProviderName).Error("Failed to send record to output profiles: %v", err)
			return err
		}
	}

	return nil
}

// GetDomainConfig retrieves a domain configuration
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
		log.NewScopedLogger("", "").With("domain", domainKey).Debug("Validating domain with name '%s'", domainConfig.Name)

		// Validate input providers exist
		for _, inputProvider := range domainConfig.GetInputProfiles() {
			log.NewScopedLogger("", "").With("domain", domainKey).Debug("Domain references input provider '%s'", inputProvider)
		}

		// Validate output profiles exist
		for _, outputProfile := range domainConfig.GetOutputs() {
			log.NewScopedLogger("", "").With("domain", domainKey).Debug("Domain references output profile '%s'", outputProfile)
		}
	}

	return nil
}

// IntegrateDomain integrates a domain configuration into the system
func IntegrateDomain(domainConfigKey string, domainConfig *DomainConfig) error {
	logPrefix := common.GetDomainLogPrefix(domainConfigKey, domainConfig.Name)
	logger := log.NewScopedLogger(logPrefix, domainConfig.LogLevel)
	logger.Info("%s Integrating domain", logPrefix)

	// Validate the domain configuration (add a Validate method if needed)
	// For now, just check Name
	if domainConfig.Name == "" {
		logger.Error("%s Validation failed: domain name is empty", logPrefix)
		return fmt.Errorf("domain name is empty")
	}

	// Check for existing domain with the same name
	existingDomain, found := GlobalDomainManager.GetDomain(domainConfig.Name)
	if found {
		// Merge with existing domain configuration (implement Merge if needed)
		logger.Info("%s Merging with existing domain configuration", logPrefix)
		// For now, just overwrite
		*existingDomain = *domainConfig
		logger.Info("%s Merge successful", logPrefix)
	} else {
		// Add as new domain
		logger.Info("%s Adding as new domain", logPrefix)
		GlobalDomainManager.AddDomain(domainConfig.Name, domainConfig)
	}

	// Update DNS records if configured
	if domainConfig.Provider != "" && domainConfig.Provider != "none" {
		logger.Info("%s Updating DNS records via provider '%s'", logPrefix, domainConfig.Provider)
		if dnsProvider, exists := GlobalDNSProviders[domainConfig.Provider]; exists {
			// Only one record supported in this config structure
			record := domainConfig.Record
			// Determine proxied flag for integration-time update (only record-level proxied supported)
			proxiedFlag := record.Proxied
			// When integrating a domain, create/update the apex record (hostname="@")
			if err := dnsProvider.CreateOrUpdateRecord(domainConfig.Name, record.Type, "@", record.Target, record.TTL, proxiedFlag, record.UpdateExisting); err != nil {
				logger.Error("%s DNS record update failed: %v", logPrefix, err)
				return err
			}
			logger.Info("%s DNS records updated successfully", logPrefix)
		} else {
			logger.Warn("%s DNS provider '%s' not found, skipping DNS record update", logPrefix, domainConfig.Provider)
		}
	} else {
		logger.Info("%s No DNS provider configured, skipping DNS record update", logPrefix)
	}

	// Send to output profiles
	logger.Info("%s Sending to output profiles: %v", logPrefix, domainConfig.GetOutputs())
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		proxiedFlag := domainConfig.Record.Proxied
		for _, profile := range domainConfig.GetOutputs() {
			if err := outputManager.WriteRecordWithSourceAndDomainFilter(domainConfigKey, domainConfig.Name, "", "", "", 0, "", proxiedFlag, false, GlobalDomainManager); err != nil {
				logger.Error("%s Failed to send to output profile '%s': %v", logPrefix, profile, err)
				return err
			}
		}
		logger.Info("%s Successfully sent to output profiles", logPrefix)
	} else {
		logger.Warn("%s Output manager not available, skipping output profile delivery", logPrefix)
	}

	logger.Info("%s Integration successful", logPrefix)
	return nil
}
