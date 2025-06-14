// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"herald/pkg/log"

	"fmt"
	"strings"
)

// DomainProfiles represents the new profiles structure for domains
type DomainProfiles struct {
	Inputs  []string `yaml:"inputs" json:"inputs"`
	Outputs []string `yaml:"outputs" json:"outputs"`
}

// DomainConfig represents a domain configuration with targeting capabilities
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
	} `yaml:"record" json:"record"`
	LogLevel string `yaml:"log_level" json:"log_level"`
}

// GetInputProfiles returns the effective input profiles
func (dc *DomainConfig) GetInputProfiles() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Inputs
	}
	return nil
}

// GetOutputs returns the effective outputs
func (dc *DomainConfig) GetOutputs() []string {
	if dc.Profiles != nil {
		return dc.Profiles.Outputs
	}
	return nil
}

// DomainManager manages domain configurations and their access controls
type DomainManager struct {
	domains map[string]*DomainConfig
	logger  *log.ScopedLogger
}

// NewDomainManager creates a new domain manager
func NewDomainManager() *DomainManager {
	return &DomainManager{
		domains: make(map[string]*DomainConfig),
		logger:  log.NewScopedLogger("[domain]", ""),
	}
}

// AddDomain adds a domain configuration
func (dm *DomainManager) AddDomain(name string, config *DomainConfig) {
	dm.domains[name] = config
}

// GetDomain retrieves a domain configuration
func (dm *DomainManager) GetDomain(name string) (*DomainConfig, bool) {
	domain, exists := dm.domains[name]
	return domain, exists
}

// GetAllDomains returns all domain configurations
func (dm *DomainManager) GetAllDomains() map[string]*DomainConfig {
	return dm.domains
}

// ValidateDomainConfigurations validates that all domain configurations reference existing providers and profiles
func ValidateDomainConfigurations(domains map[string]*DomainConfig, inputProfiles, outputProfiles, dnsProviders map[string]interface{}) error {
	var errors []string

	for domainName, domain := range domains {
		// Get effective input profiles
		inputProfilesToValidate := domain.GetInputProfiles()

		// Validate input_profiles exist
		for _, inputProfile := range inputProfilesToValidate {
			if _, exists := inputProfiles[inputProfile]; !exists {
				availableInputs := getMapKeys(inputProfiles)
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent input profile '%s' (available: %s)",
					domainName, inputProfile, strings.Join(availableInputs, ", ")))
			}
		}

		// Get effective outputs
		outputsToValidate := domain.GetOutputs()

		// Validate outputs exist
		for _, output := range outputsToValidate {
			if _, exists := outputProfiles[output]; !exists {
				availableOutputs := getMapKeys(outputProfiles)
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent output '%s' (available: %s)",
					domainName, output, strings.Join(availableOutputs, ", ")))
			}
		}

		// Validate DNS provider exists (if specified and not empty)
		if domain.Provider != "" && domain.Provider != "none" {
			if _, exists := dnsProviders[domain.Provider]; !exists {
				availableProviders := getMapKeys(dnsProviders)
				errors = append(errors, fmt.Sprintf("domain '%s' references non-existent DNS provider '%s' (available: %s)",
					domainName, domain.Provider, strings.Join(availableProviders, ", ")))
			}
		}

		// Validate that domain has at least one destination (DNS provider or outputs)
		hasDestination := (domain.Provider != "" && domain.Provider != "none") || len(domain.GetOutputs()) > 0
		if !hasDestination {
			errors = append(errors, fmt.Sprintf("domain '%s' has no destination configured (must have either a DNS provider or outputs)", domainName))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("domain configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// ValidateInputProviderAccess checks if an input provider is allowed to use a specific domain
func (dm *DomainManager) ValidateInputProviderAccess(domainName, inputProviderName string) bool {
	domain, exists := dm.domains[domainName]
	if !exists {
		dm.logger.Debug("Domain '%s' not found for input provider '%s'", domainName, inputProviderName)
		return false
	}

	// Get effective input profiles
	inputProfiles := domain.GetInputProfiles()

	// If no input_profiles specified, allow all
	if len(inputProfiles) == 0 {
		return true
	}

	// Check if this input provider is in the allowed list
	for _, allowedProvider := range inputProfiles {
		if allowedProvider == inputProviderName {
			return true
		}
	}

	dm.logger.Debug("Input provider '%s' not allowed for domain '%s' (allowed: %s)",
		inputProviderName, domainName, strings.Join(inputProfiles, ", "))
	return false
}

// ValidateOutputProfileAccess checks if an output profile should process records for a specific domain
func (dm *DomainManager) ValidateOutputProfileAccess(domainName, outputProfileName string) bool {
	domain, exists := dm.domains[domainName]
	if !exists {
		dm.logger.Debug("Domain '%s' not found for output profile '%s'", domainName, outputProfileName)
		return false
	}

	// Get effective outputs
	outputs := domain.GetOutputs()

	// If no outputs specified, don't send to any outputs
	if len(outputs) == 0 {
		return false
	}

	// Check if this output profile is in the allowed list
	for _, allowedProfile := range outputs {
		if allowedProfile == outputProfileName {
			return true
		}
	}

	dm.logger.Debug("Output profile '%s' not allowed for domain '%s' (allowed: %s)",
		outputProfileName, domainName, strings.Join(outputs, ", "))
	return false
}

// ProcessRecord processes a record from an input provider, applying access controls
func (dm *DomainManager) ProcessRecord(inputProviderName, domainName, hostname, target, recordType string, ttl int) error {
	// Check if input provider is allowed for this domain
	if !dm.ValidateInputProviderAccess(domainName, inputProviderName) {
		dm.logger.Debug("Skipping record from input provider '%s' for domain '%s' (not allowed)", inputProviderName, domainName)
		return nil
	}

	domain, exists := dm.domains[domainName]
	if !exists {
		return fmt.Errorf("domain '%s' not configured", domainName)
	}

	dm.logger.Verbose("Processing record from input provider '%s': %s.%s (%s) -> %s",
		inputProviderName, hostname, domainName, recordType, target)

	// Process DNS provider (if configured)
	if domain.Provider != "" && domain.Provider != "none" {
		dm.logger.Debug("Sending record to DNS provider '%s' for domain '%s'", domain.Provider, domainName)
		// TODO: Integrate with DNS provider system
	}

	// Process output profiles
	for _, outputProfile := range domain.GetOutputs() {
		dm.logger.Debug("Sending record to output profile '%s' for domain '%s'", outputProfile, domainName)
		// TODO: Integrate with output manager system
	}

	return nil
}

// getMapKeys extracts keys from a map for error messages
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
