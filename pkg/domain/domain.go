package domain

import (
	"herald/pkg/config"
	"herald/pkg/log"
	"herald/pkg/output"

	"fmt"
	"net"
	"strings"
	"sync"
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
	return EnsureDNSForRouterStateWithProvider(domain, fqdn, state, "")
}

// EnsureDNSForRouterStateWithProvider merges config, validates, and performs DNS add/update for a router event with input provider filtering
func EnsureDNSForRouterStateWithProvider(domain, fqdn string, state RouterState, inputProviderName string) error {
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
				logPrefix := fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
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

	// Create a proper log prefix with domain config key
	logPrefix := fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
	log.Debug("%s Processing record through unified output system", logPrefix)

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

	log.Debug("[domain/%s/%s] Initial state: RecordType='%s', Service='%s'", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), recordType, state.Service)

	// Get target from domain config first
	if domainConfig.Record.Target != "" {
		target = domainConfig.Record.Target
		log.Debug("[domain/%s/%s] Using target from domain config: '%s'", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), target)
	} else if state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			target = state.Service
			log.Debug("[domain/%s/%s] Using Service as target (IP): '%s'", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), target)
		} else if strings.Contains(state.Service, ".") {
			target = state.Service
			log.Debug("[domain/%s/%s] Using Service as target (hostname): '%s'", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), target)
		}
	}

	// Apply VPN provider logic
	if state.ForceServiceAsTarget && state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			if target != state.Service {
				log.Verbose("[domain/%s/%s] Input provider supplying IP '%s' for hostname '%s' (overriding domain target '%s')", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), state.Service, hostname, target)
			} else {
				log.Verbose("[domain/%s/%s] Input provider supplying IP '%s' for hostname '%s'", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), state.Service, hostname)
			}
			target = state.Service
		} else {
			log.Error("[domain/%s/%s] ForceServiceAsTarget=true but Service field '%s' is not a valid IP address (SourceType=%s)", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), state.Service, state.SourceType)
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

		// If recordType is empty, auto-detect based on target
		if recordType == "" {
			recordType = expectedRecordType
			log.Debug("[domain/%s/%s] Auto-detected record type: %s (target: %s)", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), recordType, target)
		} else if recordType != expectedRecordType {
			// Record type is explicitly set but doesn't match the target - this is a configuration error that needs correction
			log.Warn("[domain/%s/%s] Record type mismatch: configured as '%s' but target '%s' requires '%s' - correcting to %s", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), recordType, target, expectedRecordType, expectedRecordType)
			recordType = expectedRecordType
		}
	}

	ttl := 60
	if domainConfig.Record.TTL > 0 {
		ttl = domainConfig.Record.TTL
	}

	if target == "" {
		log.Error("[domain/%s/%s] No target specified for domain '%s' (fqdn: %s, service: %s)", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), domain, fqdn, state.Service)
		return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
	}

	log.Debug("[domain/%s/%s] Output params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), domain, recordType, hostname, target, ttl)

	// Send to ONLY the configured outputs for this domain
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		// Use the new method that filters outputs by domain configuration
		outputErr := outputManager.WriteRecordWithSourceAndDomainFilter(domain, hostname, target, recordType, ttl, state.SourceType, GlobalDomainManager)
		if outputErr != nil {
			log.Error("[domain/%s/%s] Failed to write to output system: %v", domainConfigKey, strings.ReplaceAll(domain, ".", "_"), outputErr)
			return outputErr
		} else {
			log.Debug("[domain/%s/%s] Successfully wrote to output system", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
		}
	} else {
		log.Error("[domain/%s/%s] No output manager available", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
		return fmt.Errorf("no output manager available")
	}

	return nil
}

// EnsureDNSRemoveForRouterState removes DNS records for a router event
func EnsureDNSRemoveForRouterState(domain, fqdn string, state RouterState) error {
	return EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn, state, "")
}

// EnsureDNSRemoveForRouterStateWithProvider removes DNS records for a router event with input provider filtering
func EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn string, state RouterState, inputProviderName string) error {
	// Use the new domain system
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	// Find the domain config by actual domain name AND input provider compatibility
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

	// Remove from output system
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		outputErr := outputManager.RemoveRecord(domain, hostname, recordType)
		if outputErr != nil {
			domainLogger.Error("Failed to remove from output system: %v", outputErr)
			return outputErr
		} else {
			domainLogger.Debug("Successfully removed from output system")
		}
	} else {
		domainLogger.Error("No output manager available")
		return fmt.Errorf("no output manager available")
	}

	return nil
}

// BatchProcessor helps input providers efficiently batch DNS record operations
type BatchProcessor struct {
	hasChanges    bool
	logPrefix     string
	inputProvider string // Track which input provider is using this batch
	logger        *log.ScopedLogger
	syncMutex     sync.Mutex // Prevent concurrent syncs from same provider
}

// NewBatchProcessor creates a new batch processor for an input provider
func NewBatchProcessor(logPrefix string) *BatchProcessor {
	return &BatchProcessor{
		hasChanges:    false,
		logPrefix:     logPrefix,
		inputProvider: extractInputProviderFromLogPrefix(logPrefix),
		logger:        log.NewScopedLogger(logPrefix, ""),
	}
}

// isInputProviderAllowed checks if an input provider is allowed to use a specific domain
func (bp *BatchProcessor) isInputProviderAllowed(domain, inputProviderName string) bool {
	// Look through all domain configurations to find one that matches the domain name
	// and allows this input provider
	for domainKey, domainConfig := range config.GlobalConfig.Domains {
		// Check if this domain config matches the domain name
		if domainConfig.Name == domain {
			// Use the new helper method to get effective input profiles
			inputProfiles := domainConfig.GetInputProfiles()

			log.Debug("%s Checking domain config '%s' for domain '%s' - allowed inputs: %v", bp.logPrefix, domainKey, domain, inputProfiles)

			// Check if this input provider is in the allowed list
			for _, allowedProvider := range inputProfiles {
				if allowedProvider == inputProviderName {
					log.Debug("%s Input provider '%s' allowed for domain '%s' via config '%s'", bp.logPrefix, inputProviderName, domain, domainKey)
					return true
				}
			}
		}
	}

	log.Debug("%s Input provider '%s' not allowed for domain '%s' (no matching domain config found)", bp.logPrefix, inputProviderName, domain)
	return false
}

// extractInputProviderFromLogPrefix extracts the input provider name from log prefix
// e.g., "[input/docker/main]" -> "main"
func extractInputProviderFromLogPrefix(logPrefix string) string {
	// Extract provider name from log prefix like "[input/ docker/ main]"
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

	err := EnsureDNSForRouterStateWithProvider(domain, fqdn, state, bp.inputProvider)
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

	err := EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn, state, bp.inputProvider)
	if err == nil {
		bp.hasChanges = true
	}
	return err
}

// FinalizeBatch completes the batch operation and syncs output files if there were changes
func (bp *BatchProcessor) FinalizeBatch() {
	// Prevent concurrent syncs from the same provider
	bp.syncMutex.Lock()
	defer bp.syncMutex.Unlock()

	if bp.hasChanges {
		log.Debug("%s Syncing output files after processing changes", bp.logPrefix)
		outputManager := output.GetOutputManager()
		if outputManager != nil {
			err := outputManager.SyncAll()
			if err != nil {
				log.Error("%s Failed to sync outputs: %v", bp.logPrefix, err)
			}
		}
	} else {
		log.Trace("%s No changes detected, skipping output sync", bp.logPrefix)
	}
}

// HasChanges returns whether any changes were processed in this batch
func (bp *BatchProcessor) HasChanges() bool {
	return bp.hasChanges
}
