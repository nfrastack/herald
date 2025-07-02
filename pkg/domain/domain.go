// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"errors"
	"fmt"
	"herald/pkg/common"
	"herald/pkg/log"
	"net"
	"strings"
)

type RouterState struct {
	Name                 string
	Rule                 string
	EntryPoints          []string
	Service              string
	SourceType           string // e.g. "container", "router", "file", "remote", etc.
	RecordType           string // DNS record type (A, AAAA, CNAME) - from input provider
	ForceServiceAsTarget bool   // When true, always use Service field as target (for VPN providers)
}

// getDomainLogger creates a scoped logger for domain-specific operations
func getDomainLogger(domain string, domainConfig map[string]string) *log.ScopedLogger {
	logLevel := ""
	if val, ok := domainConfig["log_level"]; ok {
		logLevel = val
	}

	logPrefix := fmt.Sprintf("[domain/%s]", domain)
	return log.NewScopedLogger(logPrefix, logLevel)
}

// EnsureDNSForRouterState merges config, validates, and performs DNS add/update for a router event
func EnsureDNSForRouterState(domain, fqdn string, state RouterState) error {
	return EnsureDNSForRouterStateWithProvider(domain, fqdn, state, "", nil)
}

// EnsureDNSForRouterStateWithProvider merges config, validates, and performs DNS add/update for a router event with input provider filtering and an OutputWriter.
func EnsureDNSForRouterStateWithProvider(domain, fqdn string, state RouterState, inputProviderName string, outputWriter OutputWriter) error {
	// Use the new domain system
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	// Find the domain config by actual domain name AND input provider compatibility
	var domainConfig *DomainConfig
	var domainConfigKey string
	found := false

	for key, config := range GlobalDomainManager.GetAllDomains() {
		if config.Name == domain {
			// Input provider must be specified and allowed
			if inputProviderName == "" {
				continue
			}

			// Check if this domain config allows the input provider
			if GlobalDomainManager.ValidateInputProviderAccess(key, inputProviderName) {
				domainConfig = config
				domainConfigKey = key
				found = true
				// Create a proper log prefix with domain config key
				logPrefix := fmt.Sprintf("[domain/%s/%s]", domainConfigKey, domain)
				log.Debug("%s Found domain config '%s' for input provider '%s'", logPrefix, key, inputProviderName)
				break
			} else {
				log.Debug("[domain/%s] Domain config '%s' does not allow input provider '%s'", domain, key, inputProviderName)
			}
		}
	}

	if !found {
		log.Debug("[domain/%s] No domain config found for input provider '%s' on domain '%s'", domain, inputProviderName, fqdn)
		return nil // Not an error - just filtered out
	}

	// Enforce skip/allow/aggregate logic for input providers writing to API output profiles
	var filteredOutputs []string
	for _, outputProfile := range domainConfig.GetOutputs() {
		isAPIOutput := strings.HasPrefix(outputProfile, "api_")
		if isAPIOutput && inputProviderName != "" {
			// Check if this is a dedicated mapping (single input, single output, both match)
			inputs := domainConfig.GetInputProfiles()
			outputs := domainConfig.GetOutputs()
			isDedicated := len(inputs) == 1 && len(outputs) == 1 && inputs[0] == inputProviderName && outputs[0] == outputProfile
			if isDedicated {
				log.Info("[domain/%s] ALLOW: Input provider '%s' allowed to write to API output profile '%s' (dedicated mapping)", domain, inputProviderName, outputProfile)
				filteredOutputs = append(filteredOutputs, outputProfile)
			} else {
				log.Warn("[domain/%s] SKIP: Input provider '%s' not allowed to write to API output profile '%s' (not a dedicated mapping)", domain, inputProviderName, outputProfile)
				continue
			}
		} else {
			log.Debug("[domain/%s] AGGREGATE: Input provider '%s' writing to output profile '%s'", domain, inputProviderName, outputProfile)
			filteredOutputs = append(filteredOutputs, outputProfile)
		}
	}

	if len(filteredOutputs) == 0 {
		log.Warn("[domain/%s] No output profiles allowed for input provider '%s' after skip/allow/aggregate filtering", domain, inputProviderName)
		return nil
	}

	// Prepare record details
	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}

	// Get record details
	recordType := state.RecordType
	target := ""

	log.Debug("[domain/%s/%s] Initial state: RecordType='%s', Service='%s'", domainConfigKey, domain, recordType, state.Service)

	// Get target from domain config first
	if domainConfig.Record.Target != "" {
		target = domainConfig.Record.Target
		log.Debug("[domain/%s/%s] Using target from domain config: '%s'", domainConfigKey, domain, target)
	} else if state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			target = state.Service
			log.Debug("[domain/%s/%s] Using Service as target (IP): '%s'", domainConfigKey, domain, target)
		} else if strings.Contains(state.Service, ".") {
			target = state.Service
			log.Debug("[domain/%s/%s] Using Service as target (hostname): '%s'", domainConfigKey, domain, target)
		}
	}

	// Apply VPN provider logic
	if state.ForceServiceAsTarget && state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			if target != state.Service {
				log.Verbose("[domain/%s/%s] Input provider supplying IP '%s' for hostname '%s' (overriding domain target '%s')", domainConfigKey, domain, state.Service, hostname, target)
			} else {
				log.Verbose("[domain/%s/%s] Input provider supplying IP '%s' for hostname '%s'", domainConfigKey, domain, state.Service, hostname)
			}
			target = state.Service
		} else {
			log.Error("[domain/%s/%s] ForceServiceAsTarget=true but Service field '%s' is not a valid IP address (SourceType=%s)", domainConfigKey, domain, state.Service, state.SourceType)
			return fmt.Errorf("invalid IP address in Service field for VPN provider: %s", state.Service)
		}
	}

	// Smart record type detection if not set or incorrectly set
	if target != "" {
		expectedRecordType := ""
		if ip := net.ParseIP(target); ip != nil {
			// Target is a valid IP address
			if ip.To4() != nil {
				expectedRecordType = "A"
			} else {
				expectedRecordType = "AAAA"
			}
		} else if strings.Contains(target, ".") {
			// Target contains a dot and is not an IP - it's a hostname/FQDN, so use CNAME
			expectedRecordType = "CNAME"
		} else {
			// Target has no dots and is not an IP - assume it's a simple hostname, use CNAME
			expectedRecordType = "CNAME"
		}

		// Track if type was explicitly set in config
		explicitType := domainConfig.Record.Type != ""

		// If config omits type, always use autodetected type, regardless of input provider
		if !explicitType {
			recordType = expectedRecordType
			log.Debug("[domain/%s/%s] Auto-detected record type: %s (target: %s)", domainConfigKey, domain, recordType, target)
		} else if recordType == "" {
			// If config sets type but input provider omits, use config type
			recordType = domainConfig.Record.Type
		}

		// If type is set (from config or input), only warn/correct if it's wrong for the target
		if explicitType && recordType != expectedRecordType {
			if (expectedRecordType == "A" || expectedRecordType == "AAAA") && (recordType != "A" && recordType != "AAAA") {
				log.Warn("[domain/%s/%s] Record type mismatch: configured as '%s' but target '%s' requires '%s' - correcting to %s", domainConfigKey, domain, recordType, target, expectedRecordType, expectedRecordType)
				recordType = expectedRecordType
			} else if expectedRecordType == "CNAME" && (recordType == "A" || recordType == "AAAA") {
				log.Warn("[domain/%s/%s] Record type mismatch: configured as '%s' but target '%s' requires '%s' - correcting to %s", domainConfigKey, domain, recordType, target, expectedRecordType, expectedRecordType)
				recordType = expectedRecordType
			}
		}
	}

	ttl := 60
	if domainConfig.Record.TTL > 0 {
		ttl = domainConfig.Record.TTL
	}

	if target == "" {
		log.Error("[domain/%s/%s] No target specified for domain '%s' (fqdn: %s, service: %s)", domainConfigKey, domain, domain, fqdn, state.Service)
		return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
	}

	log.Debug("[domain/%s/%s] Output params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", domainConfigKey, domain, domain, recordType, hostname, target, ttl)

	if outputWriter == nil {
		log.Error("[domain/%s/%s] Output writer not provided", domainConfigKey, domain)
		return fmt.Errorf("output writer not provided")
	}

	outputErr := outputWriter.WriteRecordToOutputs(filteredOutputs, domain, hostname, target, recordType, ttl, state.SourceType)
	if outputErr != nil {
		log.Error("[domain/%s/%s] Failed to write to output system: %v", domainConfigKey, domain, outputErr)
		return outputErr
	} else {
		log.Debug("[domain/%s/%s] Successfully wrote to output system", domainConfigKey, domain)
	}
	return nil
}

// EnsureDNSRemoveForRouterState removes DNS records for a router event
func EnsureDNSRemoveForRouterState(domain, fqdn string, state RouterState, outputWriter OutputWriter) error {
	return EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn, state, "", outputWriter)
}

// EnsureDNSRemoveForRouterStateWithProvider removes DNS records for a router event with input provider filtering and an OutputWriter.
func EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn string, state RouterState, inputProviderName string, outputWriter OutputWriter) error {
	// Use the new domain system
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	// Find the domain config by actual domain name AND input provider compatibility
	var domainConfig *DomainConfig
	var domainConfigKey string
	found := false

	for key, config := range GlobalDomainManager.GetAllDomains() {
		if config.Name == domain {
			// Input provider must be specified and allowed
			if inputProviderName == "" {
				continue
			}

			// Check if this domain config allows the input provider
			if GlobalDomainManager.ValidateInputProviderAccess(key, inputProviderName) {
				domainConfig = config
				domainConfigKey = key
				found = true
				log.Debug("[domain/%s] Found domain config '%s' for input provider '%s' (removal)", domain, key, inputProviderName)
				break
			} else {
				log.Debug("[domain/%s] Domain config '%s' does not allow input provider '%s' (removal)", domain, key, inputProviderName)
			}
		}
	}

	if !found {
		log.Error("[domain/%s] No domain config found for '%s'", domain, fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}

	// Create scoped logger for this domain
	domainLogger := getDomainLogger(domain, make(map[string]string))

	// Check if this input provider is allowed to use this domain
	if inputProviderName != "" {
		if !GlobalDomainManager.ValidateInputProviderAccess(domainConfigKey, inputProviderName) {
			domainLogger.Debug("Input provider '%s' not allowed for domain '%s'", inputProviderName, domain)
			return fmt.Errorf("input provider '%s' not allowed for domain '%s'", inputProviderName, domain)
		}
		domainLogger.Trace("Input provider '%s' allowed for domain '%s'", inputProviderName, domain)
	}

	domainLogger.Debug("Removing record through unified output system for FQDN: %s | RouterState: %+v", fqdn, state)

	// Process hostname for output providers
	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}

	// Determine record type for removal
	recordType := state.RecordType
	if recordType == "" {
		target := ""
		if state.Service != "" {
			target = state.Service
		}
		if target != "" {
			if ip := net.ParseIP(target); ip != nil {
				if ip.To4() != nil {
					recordType = "A"
				} else {
					recordType = "AAAA"
				}
			} else {
				recordType = "CNAME"
			}
		} else {
			recordType = "A" // Default fallback
		}
	}

	domainLogger.Debug("Output removal params: domain=%s, recordType=%s, hostname=%s", domain, recordType, hostname)

	if outputWriter == nil {
		domainLogger.Error("Output writer not provided")
		return fmt.Errorf("output writer not provided")
	}

	outputErr := outputWriter.RemoveRecordFromOutputs(domainConfig.GetOutputs(), domain, hostname, recordType, state.SourceType)
	if outputErr != nil {
		domainLogger.Error("Failed to remove from output system: %v", outputErr)
		return outputErr
	}
	return nil
}

// FinalizeBatch triggers a sync of changes to the output manager if any changes were processed in this batch.
func (bp *BatchProcessor) FinalizeBatch() {
	if !bp.hasChanges {
		bp.logger.Debug("No changes in batch, skipping output sync")
		return
	}

	if bp.outputSyncer != nil {
		// Use source-specific sync to avoid syncing other providers' changes
		err := bp.outputSyncer.SyncAllFromSource(bp.inputProvider)
		if err != nil {
			bp.logger.Error("Failed to sync output files: %v", err)
		}
	} else {
		bp.logger.Error("Output syncer not provided, cannot sync batch")
	}

	// Reset hasChanges after finalizing
	bp.hasChanges = false
}

// BatchProcessor helps input providers efficiently batch DNS record operations
type BatchProcessor struct {
	hasChanges    bool
	logPrefix     string
	inputProvider string // Track which input provider is using this batch
	logger        *log.ScopedLogger
	outputWriter  OutputWriter // Dependency for writing/removing records
	outputSyncer  OutputSyncer // Dependency for triggering syncs
}

// NewBatchProcessor creates a new batch processor for an input provider (backward compatible)
func NewBatchProcessor(logPrefix string, writer OutputWriter, syncer OutputSyncer) *BatchProcessor {
	provider := extractInputProviderFromLogPrefix(logPrefix)
	return newBatchProcessorInternal(logPrefix, provider, writer, syncer)
}

// NewBatchProcessorWithProvider creates a new batch processor with explicit provider name
func NewBatchProcessorWithProvider(logPrefix string, inputProviderName string, writer OutputWriter, syncer OutputSyncer) *BatchProcessor {
	return newBatchProcessorInternal(logPrefix, inputProviderName, writer, syncer)
}

// Internal shared initializer
func newBatchProcessorInternal(logPrefix string, inputProviderName string, writer OutputWriter, syncer OutputSyncer) *BatchProcessor {
	return &BatchProcessor{
		hasChanges:    false,
		logPrefix:     logPrefix,
		inputProvider: inputProviderName,
		logger:        log.NewScopedLogger(logPrefix, ""),
		outputWriter:  writer,
		outputSyncer:  syncer,
	}
}

// isInputProviderAllowed checks if an input provider is allowed to use a specific domain
func (bp *BatchProcessor) isInputProviderAllowed(domain, inputProviderName string) bool {
	// Look through all domain configurations to find one that matches the domain name
	// and allows this input provider
	for domainKey, domainConfig := range GlobalDomainManager.GetAllDomains() {
		// Check if this domain config matches the domain name
		if domainConfig.Name == domain {
			// Use the new helper method to get effective input profiles
			inputProfiles := domainConfig.GetInputProfiles()

			// Use a logger with the correct domain log prefix
			domainLogPrefix := GetDomainLogPrefix(domainKey, domain)
			domainLogger := log.NewScopedLogger(domainLogPrefix, "")

			domainLogger.Debug("Checking domain config '%s' for domain '%s' - allowed inputs: %v", domainKey, domain, inputProfiles)

			// Check if this input provider is in the allowed list
			for _, allowedProvider := range inputProfiles {
				if allowedProvider == inputProviderName {
					domainLogger.Debug("Input provider '%s' allowed for domain '%s' via config '%s'", inputProviderName, domain, domainKey)
					return true
				}
			}
		}
	}

	return false
}

func extractInputProviderFromLogPrefix(logPrefix string) string {
	if strings.HasPrefix(logPrefix, "[input/") && strings.HasSuffix(logPrefix, "]") {
		parts := strings.Split(logPrefix[7:len(logPrefix)-1], "/")
		if len(parts) >= 2 {
			return parts[1] // Return the profile name
		}
	}
	return ""
}

// ProcessRecord processes a single DNS record and tracks if changes occurred
func (bp *BatchProcessor) ProcessRecord(domain, fqdn string, state RouterState) error {
	// Check if this input provider is allowed for this domain
	if !bp.isInputProviderAllowed(domain, bp.inputProvider) {
		log.Debug("%s Input provider '%s' not allowed for domain '%s'", bp.logPrefix, bp.inputProvider, domain)
		return nil // Not an error, just filtered out
	}

	err := EnsureDNSForRouterStateWithProvider(domain, fqdn, state, bp.inputProvider, bp.outputWriter)
	if err == nil {
		bp.hasChanges = true
	}
	return err
}

// ProcessRecordRemoval processes a single DNS record removal and tracks if changes occurred
func (bp *BatchProcessor) ProcessRecordRemoval(domain, fqdn string, state RouterState) error {
	// Check if this input provider is allowed for this domain
	if !bp.isInputProviderAllowed(domain, bp.inputProvider) {
		log.Debug("%s Input provider '%s' not allowed for domain '%s' (removal)", bp.logPrefix, bp.inputProvider, domain)
		return nil // Not an error, just filtered out
	}

	err := EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn, state, bp.inputProvider, bp.outputWriter)
	if err == nil {
		bp.hasChanges = true
	}
	return err
}

// HasChanges returns whether any changes were processed in this batch
func (bp *BatchProcessor) HasChanges() bool {
	return bp.hasChanges
}

// Domain represents a single domain configuration
type Domain struct {
	Name      string
	ConfigKey string // Unique key for this domain's config
	// ... other fields ...
	logger *log.ScopedLogger
}

// SyncRecords syncs the given records for this domain
func (d *Domain) SyncRecords(records []common.Record) error {
	logPrefix := GetDomainLogPrefix(d.ConfigKey, d.Name)
	d.logger.Info("%s Syncing %d records", logPrefix, len(records))

	// define err if used
	var err error

	if err != nil {
		d.logger.Error("%s Failed to sync records: %v", logPrefix, err)
		return err
	}
	d.logger.Info("%s Successfully synced records", logPrefix)
	return nil
}

// Validate checks the domain configuration for validity
func (d *Domain) Validate() error {
	logPrefix := GetDomainLogPrefix(d.ConfigKey, d.Name)
	if d.Name == "" {
		d.logger.Error("%s Domain name is empty", logPrefix)
		return errors.New("domain name is empty")
	}

	if d.ConfigKey == "" {
		d.logger.Warn("%s Domain config key is empty", logPrefix)
	}
	return nil
}

// GetDomainLogPrefix returns a log prefix in the format [domain/domainKey/domain_name]
func GetDomainLogPrefix(domainConfigKey, domain string) string {
	if domainConfigKey != "" {
		return fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
	}
	return fmt.Sprintf("[domain/%s]", strings.ReplaceAll(domain, ".", "_"))
}
