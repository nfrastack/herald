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

func InitializeDomainSystem(domainConfigs map[string]interface{}, inputProfiles, outputProfiles, dnsProviders map[string]interface{}, allowMissingOutputs bool) error {
	log.NewScopedLogger("", "").With("action", "config.load").Debug("domain configs received: %+v", domainConfigs)

	domains := make(map[string]*DomainConfig)
	for domainName, configRaw := range domainConfigs {
		log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("raw config: %+v", configRaw)

		domainConfig := &DomainConfig{
			Name: domainName,
		}

		if configMap, ok := configRaw.(map[string]interface{}); ok {
			log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("config is map: %+v", configMap)

			if name, ok := configMap["name"].(string); ok {
				domainConfig.Name = name
				log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("name: %s", name)
			}

			if provider, ok := configMap["provider"].(string); ok {
				domainConfig.Provider = provider
				log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("provider: %s", provider)
			}

			if logLevel, ok := configMap["log_level"].(string); ok {
				domainConfig.LogLevel = logLevel
				log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("log_level: %s", logLevel)
			}

			if profilesRaw, ok := configMap["profiles"]; ok {
				if profilesMap, ok := profilesRaw.(map[string]interface{}); ok {
					domainConfig.Profiles = &DomainProfiles{}
					if inputsRaw, ok := profilesMap["inputs"]; ok {
						domainConfig.Profiles.Inputs = parseStringArray(inputsRaw)
						log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("profiles.inputs: %v", domainConfig.Profiles.Inputs)
					}
					if outputsRaw, ok := profilesMap["outputs"]; ok {
						domainConfig.Profiles.Outputs = parseStringArray(outputsRaw)
						log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("profiles.outputs: %v", domainConfig.Profiles.Outputs)
					}
				}
			}

			if recordRaw, ok := configMap["record"].(map[string]interface{}); ok {
				log.NewScopedLogger("", "").With("action", "config.load", "domain", domainName).Debug("record config: %+v", recordRaw)
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
			log.NewScopedLogger("", "").With("action", "config.error", "domain", domainName).Debug("not a map, type: %T, value: %+v", configRaw, configRaw)
		}

		domains[domainName] = domainConfig
		log.NewScopedLogger("", "").With("action", "config.load").Debug("parsed domain '%s': provider='%s', profiles.inputs=%v, profiles.outputs=%v",
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
		log.NewScopedLogger("", "").With("action", "config.load").Verbose("domain config for '%s' (provider: %s, effective_inputs: %v, effective_outputs: %v)",
			domainName, domainConfig.Provider, domainConfig.GetInputProfiles(), domainConfig.GetOutputs())
	}

	if err := ValidateDomainConfigurations(domains, inputProfiles, outputProfiles, dnsProviders, allowMissingOutputs); err != nil {
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
		log.NewScopedLogger("", "").With("action", "domain.skip", "domain", domainName, "input", inputProviderName).Trace("no domain config for input provider")
		return nil // Not an error, just filtered out
	}

	if !GlobalDomainManager.ValidateInputProviderAccess(domainConfigKey, inputProviderName) {
		log.NewScopedLogger("", "").With("action", "domain.skip", "domain", domainName, "input", inputProviderName, "config", domainConfigKey).Trace("not allowed for domain config key")
		return nil // Not an error, just filtered out
	}

	log.NewScopedLogger("", "").With("action", "record.sync", "domain", domainName, "input", inputProviderName).Trace("record: %s.%s (%s) -> %s", hostname, domainName, recordType, target)
	proxiedFlag := domainConfig.Record.Proxied
	if domainConfig.Record.Proxied {
		log.NewScopedLogger("", "").With("action", "record.sync", "config", domainConfigKey).Debug("set from record config (record.proxied=true)")
	} else {
		log.NewScopedLogger("", "").With("action", "record.sync", "config", domainConfigKey).Trace("not set for this domain/record")
	}

	outputManager := output.GetOutputManager()
	if outputManager != nil {
		err := outputManager.WriteRecordWithSourceAndDomainFilter(domainConfigKey, domainName, hostname, target, recordType, ttl, inputProviderName, proxiedFlag, false, GlobalDomainManager)
		if err != nil {
			log.NewScopedLogger("", "").With("action", "output.write", "domain", domainName, "input", inputProviderName).Error("to output profiles: %v", err)
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
		log.NewScopedLogger("", "").With("action", "config.validate", "domain", domainKey).Debug("domain with name '%s'", domainConfig.Name)

		for _, inputProvider := range domainConfig.GetInputProfiles() {
			log.NewScopedLogger("", "").With("action", "domain.route", "domain", domainKey).Debug("references input provider '%s'", inputProvider)
		}

		for _, outputProfile := range domainConfig.GetOutputs() {
			log.NewScopedLogger("", "").With("action", "domain.route", "domain", domainKey).Debug("references output profile '%s'", outputProfile)
		}
	}

	return nil
}

func IntegrateDomain(domainConfigKey string, domainConfig *DomainConfig) error {
	logPrefix := common.GetDomainLogPrefix(domainConfigKey, domainConfig.Name)
	logger := log.NewScopedLogger(logPrefix, domainConfig.LogLevel)
	logger.With("action", "domain.route").Info("%s domain", logPrefix)

	if domainConfig.Name == "" {
		logger.With("action", "config.error").Error("%s: domain name is empty", logPrefix)
		return fmt.Errorf("domain name is empty")
	}

	existingDomain, found := GlobalDomainManager.GetDomain(domainConfig.Name)
	if found {
		logger.With("action", "domain.route").Info("%s with existing domain configuration", logPrefix)
		*existingDomain = *domainConfig
		logger.With("action", "domain.route").Info("%s successful", logPrefix)
	} else {
		logger.With("action", "domain.route").Info("%s as new domain", logPrefix)
		GlobalDomainManager.AddDomain(domainConfig.Name, domainConfig)
	}

	if domainConfig.Provider != "" && domainConfig.Provider != "none" {
		logger.With("action", "record.update").Info("%s DNS records via provider '%s'", logPrefix, domainConfig.Provider)
		if dnsProvider, exists := GlobalDNSProviders[domainConfig.Provider]; exists {
			record := domainConfig.Record
			proxiedFlag := record.Proxied
			if err := dnsProvider.CreateOrUpdateRecord(domainConfig.Name, record.Type, "@", record.Target, record.TTL, proxiedFlag, record.UpdateExisting); err != nil {
				logger.With("action", "record.update").Error("%s update failed: %v", logPrefix, err)
				return err
			}
			logger.With("action", "record.update").Info("%s updated successfully", logPrefix)
		} else {
			logger.With("action", "record.skip").Warn("%s provider '%s' not found, skipping record update", logPrefix, domainConfig.Provider)
		}
	} else {
		logger.With("action", "record.skip").Info("%s no provider configured, skipping record update", logPrefix)
	}

	logger.With("action", "output.write").Info("%s to output profiles: %v", logPrefix, domainConfig.GetOutputs())
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		proxiedFlag := domainConfig.Record.Proxied
		for _, profile := range domainConfig.GetOutputs() {
			if err := outputManager.WriteRecordWithSourceAndDomainFilter(domainConfigKey, domainConfig.Name, "", "", "", 0, "", proxiedFlag, false, GlobalDomainManager); err != nil {
				logger.With("action", "output.write").Error("%s to output profile '%s': %v", logPrefix, profile, err)
				return err
			}
		}
		logger.With("action", "output.write").Info("%s sent to output profiles", logPrefix)
	} else {
		logger.With("action", "output.write").Warn("%s manager not available, skipping output profile delivery", logPrefix)
	}

	logger.With("action", "domain.route").Info("%s successful", logPrefix)
	return nil
}
