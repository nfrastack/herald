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

var GlobalDomainManager *DomainManager

var GlobalDNSProviders map[string]dns.Provider

func SetDNSProviders(providers map[string]dns.Provider) {
	GlobalDNSProviders = providers
}

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

func InitializeDomainSystem(domainConfigs map[string]interface{}, inputProfiles, outputProfiles, dnsProviders map[string]interface{}) error {
	log.Debug("[domain] Raw domain configs received: %+v", domainConfigs)

	domains := make(map[string]*DomainConfig)
	for domainName, configRaw := range domainConfigs {
		log.NewScopedLogger("", "").With("domain", domainName).Debug("Processing domain, raw config: %+v", configRaw)

		domainConfig := &DomainConfig{
			Name: domainName,
		}

		if configMap, ok := configRaw.(map[string]interface{}); ok {
			log.NewScopedLogger("", "").With("domain", domainName).Debug("Domain config is map: %+v", configMap)

			if name, ok := configMap["name"].(string); ok {
				domainConfig.Name = name
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted name: %s", name)
			}

			if provider, ok := configMap["provider"].(string); ok {
				domainConfig.Provider = provider
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted provider: %s", provider)
			}

			if logLevel, ok := configMap["log_level"].(string); ok {
				domainConfig.LogLevel = logLevel
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Extracted log_level: %s", logLevel)
			}

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

			if recordRaw, ok := configMap["record"].(map[string]interface{}); ok {
				log.NewScopedLogger("", "").With("domain", domainName).Debug("Has record config: %+v", recordRaw)
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

	if err := ValidateDomainConfigurations(domains, inputProfiles, outputProfiles, dnsProviders); err != nil {
		return fmt.Errorf("domain validation failed: %v", err)
	}

	GlobalDomainManager = NewDomainManager()
	for domainName, domainConfig := range domains {
		GlobalDomainManager.AddDomain(domainName, domainConfig)
	}

	return nil
}

func ProcessRecordWithDomainValidation(inputProviderName, domainName, hostname, target, recordType string, ttl int) error {
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

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

	if !GlobalDomainManager.ValidateInputProviderAccess(domainConfigKey, inputProviderName) {
		log.NewScopedLogger("", "").With("domain", domainName, "input", inputProviderName, "config", domainConfigKey).Trace("Input provider not allowed for domain config key")
		return nil // Not an error, just filtered out
	}

	log.NewScopedLogger("", "").With("domain", domainName, "input", inputProviderName).Trace("Processing record: %s.%s (%s) -> %s", hostname, domainName, recordType, target)
	proxiedFlag := domainConfig.Record.Proxied
	if domainConfig.Record.Proxied {
		log.NewScopedLogger("", "").With("config", domainConfigKey).Debug("Proxied set from record config (record.proxied=true)")
	} else {
		log.NewScopedLogger("", "").With("config", domainConfigKey).Trace("Proxied not set for this domain/record")
	}

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

func GetDomainConfig(domainName string) (*DomainConfig, bool) {
	if GlobalDomainManager == nil {
		return nil, false
	}
	return GlobalDomainManager.GetDomain(domainName)
}

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

	activeOutputProfiles := make([]string, 0, len(outputProfiles))
	for profile := range outputProfiles {
		activeOutputProfiles = append(activeOutputProfiles, profile)
	}

	return activeOutputProfiles
}

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

	activeInputProviders := make([]string, 0, len(inputProviders))
	for provider := range inputProviders {
		activeInputProviders = append(activeInputProviders, provider)
	}

	return activeInputProviders
}

func ValidateAllDomainReferences() error {
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	allDomains := GlobalDomainManager.GetAllDomains()
	for domainKey, domainConfig := range allDomains {
		log.NewScopedLogger("", "").With("domain", domainKey).Debug("Validating domain with name '%s'", domainConfig.Name)

		for _, inputProvider := range domainConfig.GetInputProfiles() {
			log.NewScopedLogger("", "").With("domain", domainKey).Debug("Domain references input provider '%s'", inputProvider)
		}

		for _, outputProfile := range domainConfig.GetOutputs() {
			log.NewScopedLogger("", "").With("domain", domainKey).Debug("Domain references output profile '%s'", outputProfile)
		}
	}

	return nil
}

func IntegrateDomain(domainConfigKey string, domainConfig *DomainConfig) error {
	logPrefix := common.GetDomainLogPrefix(domainConfigKey, domainConfig.Name)
	logger := log.NewScopedLogger(logPrefix, domainConfig.LogLevel)
	logger.Info("%s Integrating domain", logPrefix)

	if domainConfig.Name == "" {
		logger.Error("%s Validation failed: domain name is empty", logPrefix)
		return fmt.Errorf("domain name is empty")
	}

	existingDomain, found := GlobalDomainManager.GetDomain(domainConfig.Name)
	if found {
		logger.Info("%s Merging with existing domain configuration", logPrefix)
		*existingDomain = *domainConfig
		logger.Info("%s Merge successful", logPrefix)
	} else {
		logger.Info("%s Adding as new domain", logPrefix)
		GlobalDomainManager.AddDomain(domainConfig.Name, domainConfig)
	}

	if domainConfig.Provider != "" && domainConfig.Provider != "none" {
		logger.Info("%s Updating DNS records via provider '%s'", logPrefix, domainConfig.Provider)
		if dnsProvider, exists := GlobalDNSProviders[domainConfig.Provider]; exists {
			record := domainConfig.Record
			proxiedFlag := record.Proxied
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
