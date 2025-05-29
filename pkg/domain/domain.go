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
	Name        string
	Rule        string
	EntryPoints []string
	Service     string
	SourceType  string // e.g. "container", "router", "file", "remote", etc.
	RecordType  string // DNS record type (A, AAAA, CNAME) - from poll provider
}

// EnsureDNSForRouterState merges config, validates, and performs DNS add/update for a router event
func EnsureDNSForRouterState(domain, fqdn string, state RouterState) error {
	logPrefix := fmt.Sprintf("[domain/%s]", domain)

	// Print all provider keys and their options at this point
	if len(config.GlobalConfig.Providers) == 0 {
		log.Warn("%s Providers map is EMPTY at EnsureDNSForRouterState", logPrefix)
	} else {
		for k, v := range config.GlobalConfig.Providers {
			log.Trace("%s Provider key: %s, Options: %+v", logPrefix, k, v.Options)
		}
	}

	domainConfig := config.GetDomainConfig(domain)
	if domainConfig == nil {
		log.Error("%s No domain config found for '%s'", logPrefix, fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}
	log.Trace("%s domainConfig: %+v", logPrefix, domainConfig)
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
		log.Trace("%s Skipping DNS provider for domain '%s' (provider: %s)", logPrefix, fqdn, providerKey)

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
				log.Error("%s No target specified for domain '%s' (fqdn: %s, service: %s)", logPrefix, domain, fqdn, state.Service)
				return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
			}

			log.Debug("%s Output-only params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", logPrefix, domain, recordType, hostname, target, ttl)

			outputErr := outputManager.WriteRecordWithSource(domain, hostname, target, recordType, ttl, state.SourceType)
			if outputErr != nil {
				log.Error("%s Failed to write to output providers: %v", logPrefix, outputErr)
				return outputErr
			} else {
				log.Debug("%s Successfully wrote to output providers", logPrefix)
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
			log.Warn("%s No DNS provider specified for domain '%s' (hostname: %s) - will use output providers only", logPrefix, domain, fqdn)

			// Only process output providers, skip DNS provider
			// Call output providers directly without DNS operations
			log.Debug("%s Attempting to call output providers only", logPrefix)

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
				log.Error("%s No target specified for domain '%s' (fqdn: %s, service: %s)", logPrefix, domain, fqdn, state.Service)
				return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
			}

			log.Debug("%s Output-only params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", logPrefix, domain, recordType, hostname, target, ttl)

			outputErr := outputManager.WriteRecordWithSource(domain, hostname, target, recordType, ttl, state.SourceType)
			if outputErr != nil {
				log.Error("%s Failed to write to output providers: %v", logPrefix, outputErr)
				return outputErr
			} else {
				log.Debug("%s Successfully wrote to output providers", logPrefix)
				// Don't sync here - let the caller batch multiple operations
			}
			return nil
		} else {
			// No output providers either, this is an error
			log.Error("%s No provider specified for domain '%s' (hostname: %s)", logPrefix, domain, fqdn)
			return fmt.Errorf("no provider for domain %s", domain)
		}
	}
	log.Trace("%s Looking up provider config for key: '%s'", logPrefix, providerKey)
	providerCfg, ok := config.GlobalConfig.Providers[providerKey]
	if !ok {
		log.Error("%s No provider config found for key '%s' (domain: %s)", logPrefix, providerKey, domain)
		// Get keys from map[string]config.DNSProviderConfig
		providerKeys := make([]string, 0, len(config.GlobalConfig.Providers))
		for k := range config.GlobalConfig.Providers {
			providerKeys = append(providerKeys, k)
		}
		log.Trace("%s Available provider keys: %v", logPrefix, providerKeys)
		return fmt.Errorf("no provider config for %s", providerKey)
	}
	log.Trace("%s providerCfg.Options: %+v", logPrefix, providerCfg.Options)
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
	log.Trace("%s Merged providerOptions: %v", logPrefix, maskedProviderOptions)

	// Check for required secrets (note: not all providers need all secrets)
	// This is just for informational purposes
	_ = []string{} // placeholder to avoid unused variable warning

	// Get the record type from RouterState first, fallback to domain config
	recordType := state.RecordType // Use record type from poll provider
	if recordType == "" {
		recordType = providerOptions["record_type"] // Use record_type from domain config as fallback
	}
	target := providerOptions["target"]
	// Only override target if state.Service is a valid FQDN or IP
	if state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			target = state.Service
		} else if strings.Contains(state.Service, ".") {
			target = state.Service
		}

	}
	if target == "" {
		log.Error("%s No target specified for domain '%s' (fqdn: %s, service: %s)", logPrefix, domain, fqdn, state.Service)
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
	hostname := fqdn
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

	log.Debug("%s DNS params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d, update=%v, %s=%s", logPrefix, domain, recordType, hostname, target, ttl, overwrite, label, state.Name)

	// Before calling LoadProviderFromConfig, merge global and provider-specific options
	providerOptionsIface := make(map[string]interface{})
	for k, v := range providerOptions {
		providerOptionsIface[k] = v
	}
	providerCfg = config.GlobalConfig.Providers[providerKey]
	globalOptions := (&providerCfg).GetOptions()
	mergedOptions := dns.MergeProviderOptions(globalOptions, providerOptionsIface)

	log.Trace("%s Loading DNS provider '%s' for domain operation", logPrefix, providerKey)
	dnsProvider, err := dns.LoadProviderFromConfig(providerKey, mergedOptions)
	if err != nil {
		log.Error("%s Failed to load DNS provider '%s': %v", logPrefix, providerKey, err)
		return err
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
	log.Debug("%s Attempting to call output providers", logPrefix)
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		log.Debug("%s Output manager found, writing record", logPrefix)
		// Use the actual domain name for output providers, not the normalized key
		log.Debug("%s Using domain '%s' for output providers", logPrefix, domain)
		outputErr := outputManager.WriteRecordWithSource(domain, hostname, target, recordType, ttl, state.SourceType)
		if outputErr != nil {
			log.Warn("%s Failed to write to output providers: %v", logPrefix, outputErr)
			// Don't fail the DNS operation if output fails
		} else {
			log.Debug("%s Successfully wrote to output providers", logPrefix)
			// Don't sync here - let the caller batch multiple operations
		}
	} else {
		log.Debug("%s No output manager found", logPrefix)
	}

	return nil
}

// EnsureDNSRemoveForRouterState removes DNS records for a router event
func EnsureDNSRemoveForRouterState(domain, fqdn string, state RouterState) error {
	logPrefix := fmt.Sprintf("[domain/%s]", domain)
	log.Debug("%s Removing DNS for FQDN: %s | RouterState: %+v", logPrefix, fqdn, state)

	domainConfig := config.GetDomainConfig(domain)
	if domainConfig == nil {
		log.Error("%s No domain config found for '%s'", logPrefix, fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}
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
		log.Trace("%s Skipping DNS provider for domain '%s' (provider: %s)", logPrefix, fqdn, providerKey)

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

			log.Debug("%s Output-only removal params: domain=%s, recordType=%s, hostname=%s", logPrefix, domain, recordType, hostname)

			outputErr := outputManager.RemoveRecord(domain, hostname, recordType)
			if outputErr != nil {
				log.Warn("%s Failed to remove from output providers: %v", logPrefix, outputErr)
				// Don't fail for output-only removal
			} else {
				log.Debug("%s Successfully removed from output providers", logPrefix)
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
			log.Warn("%s No DNS provider specified for domain '%s' (hostname: %s) - will use output providers only for removal", logPrefix, domain, fqdn)

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

			log.Debug("%s Output-only removal params: domain=%s, recordType=%s, hostname=%s", logPrefix, domain, recordType, hostname)

			outputErr := outputManager.RemoveRecord(domain, hostname, recordType)
			if outputErr != nil {
				log.Warn("%s Failed to remove from output providers: %v", logPrefix, outputErr)
				// Don't fail for output-only removal
			} else {
				log.Debug("%s Successfully removed from output providers", logPrefix)
				// Don't sync here - let the caller handle batching
			}
			return nil
		} else {
			// No output providers either, this is an error
			log.Error("%s No provider specified for domain '%s' (hostname: %s)", logPrefix, domain, fqdn)
			return fmt.Errorf("no provider for domain %s", domain)
		}
	}
	providerCfg, ok := config.GlobalConfig.Providers[providerKey]
	if !ok {
		log.Error("%s No provider config found for key '%s' (domain: %s)", logPrefix, providerKey, domain)
		return fmt.Errorf("no provider config for %s", providerKey)
	}
	providerOptions := providerCfg.GetOptions()
	for k, v := range domainConfig {
		providerOptions[k] = v
	}
	// Mask sensitive values before logging
	maskedProviderOptions := utils.MaskSensitiveOptions(providerOptions)
	log.Debug("%s Merged providerOptions for removal: %v", logPrefix, maskedProviderOptions)

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
	log.Debug("%s Final DNS removal params: domain=%s, recordType=%s, hostname=%s", logPrefix, domain, recordType, hostname)

	// Before calling LoadProviderFromConfig, merge global and provider-specific options
	providerOptionsIface2 := make(map[string]interface{})
	for k, v := range providerOptions {
		providerOptionsIface2[k] = v
	}
	providerCfg2 := config.GlobalConfig.Providers[providerKey]
	globalOptions2 := (&providerCfg2).GetOptions()
	mergedOptions2 := dns.MergeProviderOptions(globalOptions2, providerOptionsIface2)

	log.Trace("%s Loading DNS provider '%s' for domain removal", logPrefix, providerKey)
	dnsProvider, err := dns.LoadProviderFromConfig(providerKey, mergedOptions2)
	if err != nil {
		log.Error("%s Failed to load DNS provider '%s': %v", logPrefix, providerKey, err)
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
		log.Error("%s Failed to delete DNS record for '%s': %v", logPrefix, fqdn, err)
		return err
	}

	// Call output providers after successful DNS record removal
	outputManager := output.GetOutputManager()
	if outputManager != nil {
		outputErr := outputManager.RemoveRecord(domain, hostname, recordType)
		if outputErr != nil {
			log.Warn("%s Failed to remove from output providers: %v", logPrefix, outputErr)
			// Don't fail the DNS operation if output fails
		} else {
			// Sync the outputs to write files to disk
			syncErr := outputManager.SyncAll()
			if syncErr != nil {
				log.Warn("%s Failed to sync output providers after removal: %v", logPrefix, syncErr)
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
		log.Trace("%s No changes detected, skipping output sync", bp.logPrefix)
	}
}

// HasChanges returns whether any changes were processed in this batch
func (bp *BatchProcessor) HasChanges() bool {
	return bp.hasChanges
}
