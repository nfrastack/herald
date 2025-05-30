package domain

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/dns"
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"
	"dns-companion/pkg/utils"

	"fmt"
	"net"
	"strconv"
	"strings"
)

type RouterState struct {
	Name                 string
	Rule                 string
	EntryPoints          []string
	Service              string
	SourceType           string // e.g. "container", "router", "file", "remote", etc.
	RecordType           string // DNS record type (A, AAAA, CNAME) - from poll provider
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
	domainConfig := config.GetDomainConfig(domain)
	if domainConfig == nil {
		log.Error("[domain/%s] No domain config found for '%s'", domain, fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}

	// Create scoped logger for this domain
	domainLogger := getDomainLogger(domain, domainConfig)

	// Use domainLogger instead of log for domain-specific operations
	domainLogger.Trace("domainConfig: %+v", domainConfig)

	providerKey := domainConfig["provider"]
	if providerKey == "" {
		// If only one provider exists, use it
		if len(config.GlobalConfig.Providers) == 1 {
			for k := range config.GlobalConfig.Providers {
				providerKey = k
			}
		} else {
			providerKey = ""
		}
	}
	if providerKey == "none" || providerKey == "skip" {
		domainLogger.Trace("Skipping DNS provider for domain '%s' (provider: %s)", fqdn, providerKey)

		// Still call output providers even when DNS provider is 'none'
		outputManager := output.GetOutputManager()
		if outputManager != nil {
			// Process hostname for output providers
			hostname := fqdn
			if fqdn == domain {
				hostname = "@"
			} else if strings.HasSuffix(fqdn, "."+domain) {
				hostname = strings.TrimSuffix(fqdn, "."+domain)
			}

			// Get record details for output
			recordType := state.RecordType
			target := ""

			// Get target from domain config first
			if v, ok := domainConfig["target"]; ok && v != "" {
				target = v
			} else if state.Service != "" {
				if ip := net.ParseIP(state.Service); ip != nil {
					target = state.Service
				} else if strings.Contains(state.Service, ".") {
					target = state.Service
				}
			}
			// IMPORTANT: Apply VPN provider logic for output-only mode too!
			if state.ForceServiceAsTarget && state.Service != "" {
				if ip := net.ParseIP(state.Service); ip != nil {
					domainLogger.Info("Poll provider forcing IP '%s' for hostname '%s' (overriding domain target '%s')", state.Service, hostname, target)
					target = state.Service
				} else {
					domainLogger.Error("ForceServiceAsTarget=true but Service field '%s' is not a valid IP address (SourceType=%s)", state.Service, state.SourceType)
					return fmt.Errorf("invalid IP address in Service field for VPN provider: %s", state.Service)
				}
			}

			// Smart record type detection if not set
			if recordType == "" && target != "" {
				if ip := net.ParseIP(target); ip != nil {
					if ip.To4() != nil {
						recordType = "A"
					} else {
						recordType = "AAAA"
					}
				} else {
					recordType = "CNAME"
				}
			}

			ttl := 60
			if v, ok := domainConfig["ttl"]; ok && v != "" {
				if parsed, err := strconv.Atoi(v); err == nil {
					ttl = parsed
				}
			}

			if target == "" {
				domainLogger.Error("No target specified for domain '%s' (fqdn: %s, service: %s)", domain, fqdn, state.Service)
				return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
			}

			domainLogger.Debug("Output-only params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", domain, recordType, hostname, target, ttl)

			outputErr := outputManager.WriteRecordWithSource(domain, hostname, target, recordType, ttl, state.SourceType)
			if outputErr != nil {
				domainLogger.Error("Failed to write to output providers: %v", outputErr)
				return outputErr
			} else {
				domainLogger.Debug("Successfully wrote to output providers")
				// Don't sync here - let the caller handle batching
			}
		}
		return nil
	}
	if providerKey == "" {
		// Check if we have output providers configured for this domain
		outputManager := output.GetOutputManager()
		if outputManager != nil && len(outputManager.GetProfiles()) > 0 { // We have output providers, so warn but don't fail
			domainLogger.Warn("No DNS provider specified for domain '%s' (hostname: %s) - will use output providers only", domain, fqdn)

			// Only process output providers, skip DNS provider
			// Call output providers directly without DNS operations
			domainLogger.Debug("Attempting to call output providers only")

			// Process hostname for output providers
			hostname := fqdn
			if fqdn == domain {
				hostname = "@"
			} else if strings.HasSuffix(fqdn, "."+domain) {
				hostname = strings.TrimSuffix(fqdn, "."+domain)
			}

			// Get record details for output
			recordType := state.RecordType
			target := ""

			// Get target from domain config first
			if v, ok := domainConfig["target"]; ok && v != "" {
				target = v
			} else if state.Service != "" {
				if ip := net.ParseIP(state.Service); ip != nil {
					target = state.Service
				} else if strings.Contains(state.Service, ".") {
					target = state.Service
				}
			}

			// IMPORTANT: Apply VPN provider logic for output-only mode too!
			if state.ForceServiceAsTarget && state.Service != "" {
				if ip := net.ParseIP(state.Service); ip != nil {
					domainLogger.Info("Poll provider forcing IP '%s' for hostname '%s' (overriding domain target '%s')", state.Service, hostname, target)
					target = state.Service
				} else {
					domainLogger.Error("ForceServiceAsTarget=true but Service field '%s' is not a valid IP address for output-only no provider (SourceType=%s)", state.Service, state.SourceType)
					return fmt.Errorf("invalid IP address in Service field for VPN provider (output-only no provider): %s", state.Service)
				}
			}

			// Smart record type detection if not set
			if recordType == "" && target != "" {
				if ip := net.ParseIP(target); ip != nil {
					if ip.To4() != nil {
						recordType = "A"
					} else {
						recordType = "AAAA"
					}
				} else {
					recordType = "CNAME"
				}
			}

			ttl := 60

			if target == "" {
				domainLogger.Error("No target specified for domain '%s' (fqdn: %s, service: %s)", domain, fqdn, state.Service)
				return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
			}

			domainLogger.Debug("Output-only params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", domain, recordType, hostname, target, ttl)

			outputErr := outputManager.WriteRecordWithSource(domain, hostname, target, recordType, ttl, state.SourceType)
			if outputErr != nil {
				domainLogger.Error("Failed to write to output providers: %v", outputErr)
				return outputErr
			} else {
				domainLogger.Debug("Successfully wrote to output providers")
				// Don't sync here - let the caller batch multiple operations
			}
			return nil
		} else {
			// No output providers either, this is an error
			domainLogger.Error("No provider specified for domain '%s' (hostname: %s)", domain, fqdn)
			return fmt.Errorf("no provider for domain %s", domain)
		}
	}
	domainLogger.Trace("Looking up provider config for key: '%s'", providerKey)
	providerCfg, ok := config.GlobalConfig.Providers[providerKey]
	if !ok {
		domainLogger.Error("No provider config found for key '%s' (domain: %s)", providerKey, domain)
		// Get keys from map[string]config.DNSProviderConfig
		providerKeys := make([]string, 0, len(config.GlobalConfig.Providers))
		for k := range config.GlobalConfig.Providers {
			providerKeys = append(providerKeys, k)
		}
		domainLogger.Trace("Available provider keys: %v", providerKeys)
		return fmt.Errorf("no provider config for %s", providerKey)
	}
	domainLogger.Trace("providerCfg.Options: %+v", providerCfg.Options)
	// Merge provider options and domain config
	providerOptions := providerCfg.GetOptions()
	for k, v := range domainConfig {
		providerOptions[k] = v
	}

	// Ensure the provider type is set correctly
	if providerCfg.Type != "" {
		providerOptions["provider_type"] = providerCfg.Type
	}

	// Mask sensitive values before logging
	maskedProviderOptions := utils.MaskSensitiveOptions(providerOptions)
	domainLogger.Trace("Merged providerOptions: %v", maskedProviderOptions)

	// Check for required secrets (note: not all providers need all secrets)
	// This is just for informational purposes
	_ = []string{} // placeholder to avoid unused variable warning

	// Get the record type from RouterState first, fallback to domain config
	recordType := state.RecordType // Use record type from poll provider
	if recordType == "" {
		recordType = providerOptions["record_type"] // Use record_type from domain config as fallback
	}
	target := providerOptions["target"]
	// Log what we have before processing
	domainLogger.Trace("Initial target from config: '%s', Service from state: '%s', ForceServiceAsTarget: %t", target, state.Service, state.ForceServiceAsTarget)

	// Use the subdomain part for the hostname
	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}

	// If ForceServiceAsTarget is true (for VPN providers), ALWAYS use the Service field
	if state.ForceServiceAsTarget {
		domainLogger.Debug("ForceServiceAsTarget=true - checking Service field for mandatory IP override")
		if state.Service != "" {
			if ip := net.ParseIP(state.Service); ip != nil {
				domainLogger.Info("Poll provider forcing IP '%s' for hostname '%s' (overriding domain target '%s')", state.Service, hostname, target)
				target = state.Service
			} else {
				domainLogger.Error("ForceServiceAsTarget=true but Service field '%s' is not a valid IP address (SourceType=%s)", state.Service, state.SourceType)
				return fmt.Errorf("invalid IP address in Service field for VPN provider: %s", state.Service)
			}
		} else {
			domainLogger.Error("ForceServiceAsTarget=true but Service field is empty - this should never happen (SourceType=%s)", state.SourceType)
			return fmt.Errorf("empty Service field for VPN provider")
		}
	} else {
		// For non-VPN providers, use the original logic
		if state.Service != "" {
			if ip := net.ParseIP(state.Service); ip != nil {
				domainLogger.Debug("Non-VPN IP detected - overriding target '%s' with Service IP '%s'", target, state.Service)
				target = state.Service
			} else if strings.Contains(state.Service, ".") {
				domainLogger.Debug("Non-VPN FQDN detected - overriding target '%s' with Service FQDN '%s'", target, state.Service)
				target = state.Service
			} else {
				domainLogger.Trace("Service field '%s' is not a valid IP or FQDN, keeping config target '%s'", state.Service, target)
			}
		} else {
			domainLogger.Trace("No Service field provided, using config target '%s'", target)
		}
	}

	domainLogger.Debug("Final target resolved to: '%s'", target)
	if target == "" {
		domainLogger.Error("No target specified for domain '%s' (fqdn: %s, service: %s)", domain, fqdn, state.Service)
		return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
	}

	// Smart record type detection if not explicitly set
	if recordType == "" {
		if ip := net.ParseIP(target); ip != nil {
			if ip.To4() != nil {
				recordType = "A"
			} else {
				recordType = "AAAA"
			}
		} else {
			recordType = "CNAME"
		}
	}
	ttl := 60
	if v, ok := providerOptions["ttl"]; ok && v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			ttl = parsed
		}
	}
	overwrite := true
	if v, ok := providerOptions["update_existing"]; ok && v != "" {
		overwrite = v == "true" || v == "1"
	}
	// Use the subdomain part for the hostname
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}
	// Process the source type for proper labeling
	label := state.SourceType
	if strings.Contains(label, "|") {
		parts := strings.SplitN(label, "|", 2)
		label = parts[0]
	}
	if label == "" {
		label = "container"
	}

	domainLogger.Debug("DNS params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d, update=%v, %s=%s", domain, recordType, hostname, target, ttl, overwrite, label, state.Name)
	domainLogger.Debug("FINAL RESOLVED TARGET: '%s' (was config='%s', service='%s')", target, providerOptions["target"], state.Service)

	// Before calling LoadProviderFromConfig, merge global and provider-specific options
	providerOptionsIface := make(map[string]interface{})
	for k, v := range providerOptions {
		providerOptionsIface[k] = v
	}
	providerCfg = config.GlobalConfig.Providers[providerKey]
	globalOptions := (&providerCfg).GetOptions()
	mergedOptions := dns.MergeProviderOptions(globalOptions, providerOptionsIface)

	domainLogger.Trace("Loading DNS provider '%s' for domain operation", providerKey)
	dnsProvider, err := dns.LoadProviderFromConfig(providerKey, mergedOptions)
	if err != nil {
		domainLogger.Error("Failed to load DNS provider '%s': %v", providerKey, err)
		return err
	}

	// Log if we're updating an existing record with a different target
	if overwrite {
		domainLogger.Verbose("Updating DNS record: %s -> %s (type: %s, source: %s)", hostname, target, recordType, label)
	} else {
		domainLogger.Verbose("Creating DNS record: %s -> %s (type: %s, source: %s)", hostname, target, recordType, label)
	}
	if cfProvider, ok := dnsProvider.(interface {
		CreateOrUpdateRecordWithSource(string, string, string, string, int, bool, string, string) error
	}); ok {
		err = cfProvider.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, overwrite, state.Name, state.SourceType)
		// If no error, assume created/updated (provider logs the real action)
	} else {
		err = dnsProvider.CreateOrUpdateRecord(domain, recordType, hostname, target, ttl, overwrite)
	}
	if err != nil {
		return err
	}

	// Call output providers after successful DNS operation
	domainLogger.Debug("Attempting to call output providers")
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		domainLogger.Debug("Output manager found, writing record")
		// Use the actual domain name for output providers, not the normalized key
		domainLogger.Debug("Using domain '%s' for output providers", domain)
		outputErr := outputManager.WriteRecordWithSource(domain, hostname, target, recordType, ttl, state.SourceType)
		if outputErr != nil {
			domainLogger.Warn("Failed to write to output providers: %v", outputErr)
			// Don't fail the DNS operation if output fails
		} else {
			domainLogger.Debug("Successfully wrote to output providers")
			// Don't sync here - let the caller batch multiple operations
		}
	} else {
		domainLogger.Debug("No output manager found")
	}

	return nil
}

// EnsureDNSRemoveForRouterState removes DNS records for a router event
func EnsureDNSRemoveForRouterState(domain, fqdn string, state RouterState) error {
	domainConfig := config.GetDomainConfig(domain)
	if domainConfig == nil {
		log.Error("[domain/%s] No domain config found for '%s'", domain, fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}

	// Create scoped logger for this domain
	domainLogger := getDomainLogger(domain, domainConfig)
	domainLogger.Debug("Removing DNS for FQDN: %s | RouterState: %+v", fqdn, state)
	providerKey := domainConfig["provider"]
	if providerKey == "" {
		// If only one provider exists, use it
		if len(config.GlobalConfig.Providers) == 1 {
			for k := range config.GlobalConfig.Providers {
				providerKey = k
			}
		} else {
			providerKey = ""
		}
	}
	if providerKey == "none" || providerKey == "skip" {
		domainLogger.Trace("Skipping DNS provider for domain '%s' (provider: %s)", fqdn, providerKey)

		// Still call output providers even when DNS provider is 'none'
		outputManager := output.GetOutputManager()
		if outputManager != nil {
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

			domainLogger.Debug("Output-only removal params: domain=%s, recordType=%s, hostname=%s", domain, recordType, hostname)

			outputErr := outputManager.RemoveRecord(domain, hostname, recordType)
			if outputErr != nil {
				domainLogger.Warn("Failed to remove from output providers: %v", outputErr)
				// Don't fail for output-only removal
			} else {
				domainLogger.Debug("Successfully removed from output providers")
				// Don't sync here - let the caller handle batching
			}
		}
		return nil
	}
	if providerKey == "" {
		// Check if we have output providers configured for this domain
		outputManager := output.GetOutputManager()
		if outputManager != nil && len(outputManager.GetProfiles()) > 0 {
			// We have output providers, so warn but don't fail
			domainLogger.Warn("No DNS provider specified for domain '%s' (hostname: %s) - will use output providers only for removal", domain, fqdn)

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

			domainLogger.Debug("Output-only removal params: domain=%s, recordType=%s, hostname=%s", domain, recordType, hostname)

			outputErr := outputManager.RemoveRecord(domain, hostname, recordType)
			if outputErr != nil {
				domainLogger.Warn("Failed to remove from output providers: %v", outputErr)
				// Don't fail for output-only removal
			} else {
				domainLogger.Debug("Successfully removed from output providers")
				// Don't sync here - let the caller handle batching
			}
			return nil
		} else {
			// No output providers either, this is an error
			domainLogger.Error("No provider specified for domain '%s' (hostname: %s)", domain, fqdn)
			return fmt.Errorf("no provider for domain %s", domain)
		}
	}
	providerCfg, ok := config.GlobalConfig.Providers[providerKey]
	if !ok {
		domainLogger.Error("No provider config found for key '%s' (domain: %s)", providerKey, domain)
		return fmt.Errorf("no provider config for %s", providerKey)
	}
	providerOptions := providerCfg.GetOptions()
	for k, v := range domainConfig {
		providerOptions[k] = v
	}
	// Mask sensitive values before logging
	maskedProviderOptions := utils.MaskSensitiveOptions(providerOptions)
	domainLogger.Debug("Merged providerOptions for removal: %v", maskedProviderOptions)

	recordType := providerOptions["record_type"] // Use record_type instead of type
	target := providerOptions["target"]
	if state.Service != "" {
		target = state.Service
	}
	if recordType == "" {
		if ip := net.ParseIP(target); ip != nil {
			if ip.To4() != nil {
				recordType = "A"
			} else {
				recordType = "AAAA"
			}
		} else {
			recordType = "CNAME"
		}
	}

	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}
	domainLogger.Debug("Final DNS removal params: domain=%s, recordType=%s, hostname=%s", domain, recordType, hostname)

	// Before calling LoadProviderFromConfig, merge global and provider-specific options
	providerOptionsIface2 := make(map[string]interface{})
	for k, v := range providerOptions {
		providerOptionsIface2[k] = v
	}
	providerCfg2 := config.GlobalConfig.Providers[providerKey]
	globalOptions2 := (&providerCfg2).GetOptions()
	mergedOptions2 := dns.MergeProviderOptions(globalOptions2, providerOptionsIface2)

	domainLogger.Trace("Loading DNS provider '%s' for domain removal", providerKey)
	dnsProvider, err := dns.LoadProviderFromConfig(providerKey, mergedOptions2)
	if err != nil {
		domainLogger.Error("Failed to load DNS provider '%s': %v", providerKey, err)
		return err
	}
	if cfProvider, ok := dnsProvider.(interface {
		DeleteRecordWithSource(string, string, string, string, string) error
	}); ok {
		err = cfProvider.DeleteRecordWithSource(domain, recordType, hostname, state.Name, state.SourceType)
	} else {
		err = dnsProvider.DeleteRecord(domain, recordType, hostname)
	}
	if err != nil {
		domainLogger.Error("Failed to delete DNS record for '%s': %v", fqdn, err)
		return err
	}

	// Call output providers after successful DNS record removal
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		outputErr := outputManager.RemoveRecord(domain, hostname, recordType)
		if outputErr != nil {
			domainLogger.Warn("Failed to remove from output providers: %v", outputErr)
			// Don't fail the DNS operation if output fails
		} else {
			// Sync the outputs to write files to disk
			syncErr := outputManager.SyncAll()
			if syncErr != nil {
				domainLogger.Warn("Failed to sync output providers after removal: %v", syncErr)
			}
		}
	}

	label := state.SourceType
	if strings.Contains(label, "|") {
		parts := strings.SplitN(label, "|", 2)
		label = parts[0]
		// name := parts[1] // removed unused variable
	}
	if label == "" {
		label = "container"
	}
	// Use label and name for logging in provider
	return nil
}

// BatchProcessor helps poll providers efficiently batch DNS record operations
type BatchProcessor struct {
	hasChanges bool
	logPrefix  string
}

// NewBatchProcessor creates a new batch processor for a poll provider
func NewBatchProcessor(logPrefix string) *BatchProcessor {
	return &BatchProcessor{
		hasChanges: false,
		logPrefix:  logPrefix,
	}
}

// ProcessRecord processes a single DNS record and tracks if changes occurred
func (bp *BatchProcessor) ProcessRecord(domain, fqdn string, state RouterState) error {
	err := EnsureDNSForRouterState(domain, fqdn, state)
	if err == nil {
		bp.hasChanges = true
	}
	return err
}

// ProcessRecordRemoval processes a single DNS record removal and tracks if changes occurred
func (bp *BatchProcessor) ProcessRecordRemoval(domain, fqdn string, state RouterState) error {
	err := EnsureDNSRemoveForRouterState(domain, fqdn, state)
	if err == nil {
		bp.hasChanges = true
	}
	return err
}

// FinalizeBatch completes the batch operation and syncs output files if there were changes
func (bp *BatchProcessor) FinalizeBatch() {
	if bp.hasChanges {
		log.Debug("%s Syncing output files after processing changes", bp.logPrefix)
		outputManager := output.GetOutputManager()
		if outputManager != nil {
			outputManager.SyncAll()
		}
	} else {
		//log.Trace("%s No changes detected, skipping output sync", bp.logPrefix)
	}
}

// HasChanges returns whether any changes were processed in this batch
func (bp *BatchProcessor) HasChanges() bool {
	return bp.hasChanges
}
