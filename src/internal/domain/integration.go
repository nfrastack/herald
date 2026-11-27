// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"fmt"

	"github.com/nfrastack/herald/internal/log"
)

var GlobalDomainManager *DomainManager

func parseStringArray(value any) []string {
	switch v := value.(type) {
	case []any:
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

func InitializeDomainSystem(domainConfigs map[string]any, inputProfiles, outputProfiles, dnsProviders map[string]any, allowMissingOutputs, skipValidation bool) error {
	log.NewScopedLogger("[domain]", "").With("action", "config.load").Debug("domain configs received: %+v", domainConfigs)

	domains := make(map[string]*DomainConfig)
	for domainName, configRaw := range domainConfigs {
		log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("raw config: %+v", configRaw)

		domainConfig := &DomainConfig{
			Name: domainName,
		}

		if configMap, ok := configRaw.(map[string]any); ok {
			log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("config is map: %+v", configMap)

			if name, ok := configMap["name"].(string); ok {
				domainConfig.Name = name
				log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("name: %s", name)
			}

			if provider, ok := configMap["provider"].(string); ok {
				domainConfig.Provider = provider
				log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("provider: %s", provider)
			}

			if logLevel, ok := configMap["log_level"].(string); ok {
				domainConfig.LogLevel = logLevel
				log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("log_level: %s", logLevel)
			}

			if profilesRaw, ok := configMap["profiles"]; ok {
				if profilesMap, ok := profilesRaw.(map[string]any); ok {
					domainConfig.Profiles = &DomainProfiles{}
					if inputsRaw, ok := profilesMap["inputs"]; ok {
						domainConfig.Profiles.Inputs = parseStringArray(inputsRaw)
						log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("profiles.inputs: %v", domainConfig.Profiles.Inputs)
					}
					if outputsRaw, ok := profilesMap["outputs"]; ok {
						domainConfig.Profiles.Outputs = parseStringArray(outputsRaw)
						log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("profiles.outputs: %v", domainConfig.Profiles.Outputs)
					}
				}
			}

			if recordRaw, ok := configMap["record"].(map[string]any); ok {
				log.NewScopedLogger("[domain]", "").With("action", "config.load", "domain", domainName).Debug("record config: %+v", recordRaw)
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
			log.NewScopedLogger("[domain]", "").With("action", "config.error", "domain", domainName).Debug("not a map, type: %T, value: %+v", configRaw, configRaw)
		}

		domains[domainName] = domainConfig
		log.NewScopedLogger("[domain]", "").With("action", "config.load").Debug("parsed domain '%s': provider='%s', profiles.inputs=%v, profiles.outputs=%v",
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
		log.NewScopedLogger("[domain]", "").With("action", "config.load").Trace("domain config for '%s' (provider: %s, effective_inputs: %v, effective_outputs: %v)",
			domainName, domainConfig.Provider, domainConfig.GetInputProfiles(), domainConfig.GetOutputs())
	}

	if !skipValidation {
		if err := ValidateDomainConfigurations(domains, inputProfiles, outputProfiles, dnsProviders, allowMissingOutputs); err != nil {
			return fmt.Errorf("domain validation failed: %v", err)
		}
	}

	GlobalDomainManager = NewDomainManager()
	for domainName, domainConfig := range domains {
		GlobalDomainManager.AddDomain(domainName, domainConfig)
	}

	return nil
}

func GetDomainConfig(domainName string) (*DomainConfig, bool) {
	if GlobalDomainManager == nil {
		return nil, false
	}
	return GlobalDomainManager.GetDomain(domainName)
}
