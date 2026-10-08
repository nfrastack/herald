// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"github.com/nfrastack/herald/internal/common"
	"github.com/nfrastack/herald/internal/log"

	"fmt"
	"strings"
)

type DomainProfiles struct {
	Inputs  []string `yaml:"inputs" json:"inputs"`
	Outputs []string `yaml:"outputs" json:"outputs"`
}

type DomainConfig struct {
	Name     string          `yaml:"name" json:"name"`
	Provider string          `yaml:"provider" json:"provider"`
	Profiles *DomainProfiles `yaml:"profiles" json:"profiles"`
	Record   struct {
		Type           string `yaml:"type" json:"type"`
		TTL            int    `yaml:"ttl" json:"ttl"`
		Target         string `yaml:"target" json:"target"`
		UpdateExisting bool   `yaml:"update_existing" json:"update_existing"`
		AllowMultiple  bool   `yaml:"allow_multiple" json:"allow_multiple"`
		Proxied        bool   `yaml:"proxied" json:"proxied"`
	} `yaml:"record" json:"record"`
	LogLevel string `yaml:"log_level" json:"log_level"`
}

func (dc *DomainConfig) GetInputProfiles() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Inputs
	}
	return nil
}

func (dc *DomainConfig) GetOutputs() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Outputs
	}
	return nil
}

func (dc *DomainConfig) GetName() string {
	return dc.Name
}

type DomainManager struct {
	domains map[string]*DomainConfig
	logger  *log.ScopedLogger
}

func NewDomainManager() *DomainManager {
	return &DomainManager{
		domains: make(map[string]*DomainConfig),
		logger:  log.NewScopedLogger("[domain]", ""),
	}
}

func (dm *DomainManager) AddDomain(name string, config *DomainConfig) {
	dm.domains[name] = config
}

func (dm *DomainManager) GetDomain(name string) (*DomainConfig, bool) {
	domain, exists := dm.domains[name]
	return domain, exists
}

func (dm *DomainManager) GetAllDomains() map[string]*DomainConfig {
	return dm.domains
}

func ValidateDomainConfigurations(domains map[string]*DomainConfig, inputProfiles, outputProfiles, dnsProviders map[string]interface{}, allowMissingOutputs bool) error {
	var errors []string
	validateLog := log.NewScopedLogger("[domain]", "")

	for domainName, domain := range domains {
		inputProfilesToValidate := domain.GetInputProfiles()

		for _, inputProfile := range inputProfilesToValidate {
			if _, exists := inputProfiles[inputProfile]; !exists {
				availableInputs := getMapKeys(inputProfiles)
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent input profile '%s' (available: %s)",
					domainName, inputProfile, strings.Join(availableInputs, ", ")))
			}
		}

		outputsToValidate := domain.GetOutputs()

		if allowMissingOutputs {
			kept := outputsToValidate[:0]
			for _, output := range outputsToValidate {
				if _, exists := outputProfiles[output]; !exists {
					validateLog.With("action", "domain.skip", "domain", domainName).Warn("domain references non-existent output '%s', skipping it (allow_missing_outputs=true)", output)
					continue
				}
				kept = append(kept, output)
			}
			if domain.Profiles != nil {
				domain.Profiles.Outputs = kept
			}
			outputsToValidate = kept
		} else {
			for _, output := range outputsToValidate {
				if _, exists := outputProfiles[output]; !exists {
					availableOutputs := getMapKeys(outputProfiles)
					errors = append(errors, fmt.Sprintf("domain '%s' references non-existent output '%s' (available: %s)",
						domainName, output, strings.Join(availableOutputs, ", ")))
				}
			}
		}

		if domain.Provider != "" && domain.Provider != "none" {
			if _, exists := dnsProviders[domain.Provider]; !exists {
				availableProviders := getMapKeys(dnsProviders)
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent DNS provider '%s' (available: %s)",
					domainName, domain.Provider, strings.Join(availableProviders, ", ")))
			}
		}

		hasDestination := (domain.Provider != "" && domain.Provider != "none") || len(domain.GetOutputs()) > 0
		if !hasDestination {
			if allowMissingOutputs {
				validateLog.With("action", "domain.skip", "domain", domainName).Warn("domain has no destination configured, skipping it (allow_missing_outputs=true)")
				delete(domains, domainName)
				continue
			}
			errors = append(errors, fmt.Sprintf("domain '%s' has no destination configured (must have either a DNS provider or outputs)", domainName))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("domain configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

func (dm *DomainManager) ValidateInputProviderAccess(domainName, inputProviderName string) bool {
	domain, exists := dm.domains[domainName]
	if !exists {
		dm.logger.With("action", "domain.skip").Debug("'%s' not found for input provider '%s'", domainName, inputProviderName)
		return false
	}

	inputProfiles := domain.GetInputProfiles()

	if len(inputProfiles) == 0 {
		return true
	}

	for _, allowedProvider := range inputProfiles {
		if allowedProvider == inputProviderName {
			return true
		}
	}

	dm.logger.With("action", "domain.skip").Debug("'%s' not allowed for domain '%s' (allowed: %s)",
		inputProviderName, domainName, strings.Join(inputProfiles, ", "))
	return false
}

func (dm *DomainManager) ValidateOutputProfileAccess(domainName, outputProfileName string) bool {
	domain, exists := dm.domains[domainName]
	if !exists {
		dm.logger.With("action", "domain.skip").Debug("'%s' not found for output profile '%s'", domainName, outputProfileName)
		return false
	}

	outputs := domain.GetOutputs()

	if len(outputs) == 0 {
		return false
	}

	for _, allowedProfile := range outputs {
		if allowedProfile == outputProfileName {
			return true
		}
	}

	dm.logger.With("action", "domain.skip").Debug("'%s' not allowed for domain '%s' (allowed: %s)",
		outputProfileName, domainName, strings.Join(outputs, ", "))
	return false
}

func (dm *DomainManager) ProcessRecord(inputProviderName, domainName, hostname, target, recordType string, ttl int) error {
	if !dm.ValidateInputProviderAccess(domainName, inputProviderName) {
		dm.logger.With("action", "record.skip").Debug("from input provider '%s' for domain '%s' (not allowed)", inputProviderName, domainName)
		return nil
	}

	domain, exists := dm.domains[domainName]
	if !exists {
		return fmt.Errorf("domain '%s' not configured", domainName)
	}

	logPrefix := common.GetDomainLogPrefix(domain.Name, domain.Name)
	dm.logger.With("action", "record.sync").Verbose("%s from input provider '%s': %s.%s (%s) -> %s",
		logPrefix, inputProviderName, hostname, domainName, recordType, target)

	if domain.Provider != "" && domain.Provider != "none" {
		dm.logger.With("action", "record.sync").Debug("to DNS provider '%s' for domain '%s'", domain.Provider, domainName)
	}

	for _, outputProfile := range domain.GetOutputs() {
		dm.logger.With("action", "output.write").Debug("to output profile '%s' for domain '%s'", outputProfile, domainName)
	}

	return nil
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

func (c *DomainConfig) Load() error {

	err := simulateLoadProcess()
	if err != nil {
		return err
	}

	return nil
}

func simulateLoadProcess() error {
	return nil
}
