// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package output

import (
	"herald/pkg/log"
	"herald/pkg/output/types/common"
	"herald/pkg/output/types/dns"
	fileoutput "herald/pkg/output/types/file"

	"fmt"
	"strings"
	"sync"
	"time"
)

// DomainConfig represents a minimal domain config for output filtering
// Now includes GetName() for domain identification
type DomainConfig interface {
	GetOutputs() []string
	GetName() string
}

// GlobalConfigForOutput represents the minimal config interface needed by output
type GlobalConfigForOutput interface {
	GetDomains() map[string]DomainConfig
}

// globalConfigGetter is a function that returns the global config
var globalConfigGetter func() GlobalConfigForOutput

// SetGlobalConfigGetter sets the function to retrieve global config
func SetGlobalConfigGetter(getter func() GlobalConfigForOutput) {
	globalConfigGetter = getter
}

// getGlobalConfigForOutput safely gets the global config without import cycles
func getGlobalConfigForOutput() GlobalConfigForOutput {
	if globalConfigGetter != nil {
		return globalConfigGetter()
	}
	return nil
}

// init automatically registers all output types when the package is imported
func init() {
	log.Debug("[output] Auto-registering core output types")

	// Register core output formats directly to avoid import cycles
	registerAllCoreFormats()
}

// registerAllCoreFormats registers all built-in output formats
func registerAllCoreFormats() {
	// Register only the canonical file output factory for all file-based formats
	RegisterFormat("file", fileoutput.NewFileOutput)
	RegisterFormat("file/json", fileoutput.NewFileOutput)
	RegisterFormat("file/yaml", fileoutput.NewFileOutput)
	RegisterFormat("file/zone", fileoutput.NewFileOutput)
	RegisterFormat("file/hosts", fileoutput.NewFileOutput)

	// Register DNS format
	RegisterFormat("dns", createDNSOutput)

	log.Debug("[output] Registered core formats: file, dns")
}

// createDNSOutput creates a DNS output instance without import cycle
func createDNSOutput(profileName string, config map[string]interface{}) (OutputFormat, error) {
	provider, ok := config["provider"].(string)
	if !ok || provider == "" {
		return nil, fmt.Errorf("dns output requires 'provider' field")
	}

	return &placeholderFormat{
		profileName: profileName,
		formatType:  fmt.Sprintf("dns/%s", provider),
	}, nil
}

// Global registry for output format creators
var (
	outputFormatRegistry   = make(map[string]func(string, map[string]interface{}) (OutputFormat, error))
	registryMutex          sync.RWMutex
	outputManagerInitCount int // Track how many times output manager is initialized
)

// RegisterFormat registers an output format creator function
func RegisterFormat(formatName string, createFunc func(string, map[string]interface{}) (OutputFormat, error)) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	if _, exists := outputFormatRegistry[formatName]; exists {
		log.Debug("[output] Format '%s' already registered, skipping duplicate registration", formatName)
		return
	}
	outputFormatRegistry[formatName] = createFunc
	log.Debug("[output] Registered format creator for '%s'", formatName)
}

// createFileFormat creates a file output format using dynamic loading to avoid import cycles
// func createFileFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
// 	// Try to dynamically load the file output package
// 	format, _ := config["format"].(string)
// 	if format == "" {
// 		format = "unknown"
// 	}

// 	log.Debug("[output] Attempting to create file format '%s' for profile '%s'", format, profileName)

// 	// Check if we have a registered creator for this file format
// 	registryMutex.RLock()
// 	createFunc, exists := outputFormatRegistry["file/"+format]
// 	if !exists {
// 		createFunc, exists = outputFormatRegistry["file"]
// 	}
// 	registryMutex.RUnlock()

// 	if exists {
// 		return createFunc(profileName, config)
// 	}

// 	// Fallback to placeholder implementation
// 	log.Debug("[output] No registered creator for file format '%s', using placeholder", format)
// 	return &placeholderFormat{
// 		profileName: profileName,
// 		formatType:  fmt.Sprintf("file/%s", format),
// 	}, nil
// }

// createDNSFormat creates a DNS output format using dynamic loading to avoid import cycles
// func createDNSFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
// 	provider, _ := config["provider"].(string)
// 	if provider == "" {
// 		return nil, fmt.Errorf("DNS format requires 'provider' field")
// 	}

// 	log.Debug("[output] Attempting to create DNS format with provider '%s' for profile '%s'", provider, profileName)

// 	// Check if we have a registered creator for this DNS provider
// 	registryMutex.RLock()
// 	createFunc, exists := outputFormatRegistry["dns/"+provider]
// 	if !exists {
// 		createFunc, exists = outputFormatRegistry["dns"]
// 	}
// 	registryMutex.RUnlock()

// 	if exists {
// 		return createFunc(profileName, config)
// 	}

// 	// Fallback to placeholder implementation
// 	log.Debug("[output] No registered creator for DNS provider '%s', using placeholder", provider)
// 	return &placeholderFormat{
// 		profileName: profileName,
// 		formatType:  fmt.Sprintf("dns/%s", provider),
// 	}, nil
// }

// GetOutputManager returns the global output manager instance
func GetOutputManager() *OutputManager {
	return GetGlobalOutputManager()
}

// OutputFormat defines the interface that all output formats must implement
// Use the canonical interface from fileoutput to avoid duplication and type mismatch
type OutputFormat = common.OutputFormat

// OutputManager manages multiple output formats
type OutputManager struct {
	profiles        map[string]OutputFormat
	mutex           sync.RWMutex
	syncMutex       sync.Mutex                 // Prevent concurrent sync operations
	lastSync        time.Time                  // Track last sync time
	syncCooldown    time.Duration              // Minimum time between syncs
	changedProfiles map[string]map[string]bool // Track which profiles have changes per source
	changesMutex    sync.RWMutex               // Protect changes tracking
}

// NewOutputManager creates a new output manager
func NewOutputManager() *OutputManager {
	return &OutputManager{
		profiles:        make(map[string]OutputFormat),
		syncCooldown:    0, // Disable cooldown for debugging
		changedProfiles: make(map[string]map[string]bool),
	}
}

// Global output manager instance
var globalOutputManager *OutputManager
var globalOutputManagerMutex sync.RWMutex

// SetGlobalOutputManager sets the global output manager instance
func SetGlobalOutputManager(manager *OutputManager) {
	globalOutputManagerMutex.Lock()
	defer globalOutputManagerMutex.Unlock()
	globalOutputManager = manager
}

// GetGlobalOutputManager returns the global output manager instance
func GetGlobalOutputManager() *OutputManager {
	globalOutputManagerMutex.RLock()
	defer globalOutputManagerMutex.RUnlock()
	return globalOutputManager
}

// WriteRecordWithSourceAndDomainFilter writes a DNS record with source and domain filtering
// Now requires domainConfigKey for strict config-based routing
func (om *OutputManager) WriteRecordWithSourceAndDomainFilter(domainConfigKey, domain, hostname, target, recordType string, ttl int, source string, domainManager interface{}) error {
	// Use domainConfigKey to get the correct domain config and allowed outputs
	var allowedOutputs []string

	// Try to get allowed outputs from domainManager if possible
	if dm, ok := domainManager.(interface {
		GetAllDomains() map[string]DomainConfig
	}); ok {
		if config, exists := dm.GetAllDomains()[domainConfigKey]; exists {
			allowedOutputs = config.GetOutputs()
		}
	}

	// Fallback: use global config if available
	if len(allowedOutputs) == 0 {
		globalConfig := getGlobalConfigForOutput()
		if globalConfig != nil {
			if config, exists := globalConfig.GetDomains()[domainConfigKey]; exists {
				allowedOutputs = config.GetOutputs()
			}
		}
	}

	// Extra safety: filter allowedOutputs using domainManager.ValidateOutputProfileAccess if available
	if dm, ok := domainManager.(interface {
		ValidateOutputProfileAccess(domainConfigKey, outputProfileName string) bool
	}); ok {
		filtered := make([]string, 0, len(allowedOutputs))
		for _, outputProfile := range allowedOutputs {
			if dm.ValidateOutputProfileAccess(domainConfigKey, outputProfile) {
				filtered = append(filtered, outputProfile)
			} else {
				log.Debug("[output/manager] Output profile '%s' not allowed for domain config key '%s' (filtered by ValidateOutputProfileAccess)", outputProfile, domainConfigKey)
			}
		}
		allowedOutputs = filtered
	}

	if len(allowedOutputs) == 0 {
		log.Warn("[output/manager] No outputs allowed for domain config key '%s' after filtering - skipping record write", domainConfigKey)
		return nil
	}

	log.Debug("[output/manager] Routing record write: domainConfigKey='%s', domain='%s', hostname='%s', target='%s', recordType='%s', ttl=%d, source='%s', allowedOutputs=%v", domainConfigKey, domain, hostname, target, recordType, ttl, source, allowedOutputs)

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	writtenCount := 0
	var errors []string

	for _, outputProfile := range allowedOutputs {
		if profile, exists := om.profiles[outputProfile]; exists {
			if err := profile.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source); err != nil {
				errors = append(errors, fmt.Sprintf("profile '%s': %v", outputProfile, err))
			} else {
				log.Debug("[output/manager] Successfully wrote record to profile '%s'", outputProfile)
				writtenCount++

				// Mark this profile as changed for this source
				om.changesMutex.Lock()
				if om.changedProfiles[source] == nil {
					om.changedProfiles[source] = make(map[string]bool)
				}
				om.changedProfiles[source][outputProfile] = true
				// Debug: print changedProfiles for this source
				log.Debug("[output/manager] changedProfiles[%s] after WriteRecordWithSourceAndDomainFilter: %v", source, om.changedProfiles[source])
				om.changesMutex.Unlock()
			}
		} else {
			log.Warn("[output/manager] Output profile '%s' not found (referenced by domain config key '%s')", outputProfile, domainConfigKey)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to write to some outputs: %s", strings.Join(errors, "; "))
	}

	if writtenCount > 0 {
		log.Debug("[output/manager] Successfully wrote to %d output profiles for domain config key '%s'", writtenCount, domainConfigKey)
	}

	return nil
}

// getAllowedOutputsForDomainConfig returns the output profiles allowed for a domain config
// This uses the global config to determine the allowed outputs dynamically
// func (om *OutputManager) getAllowedOutputsForDomainConfig(domainConfigKey string) []string {
// 	// Import the config package to access global configuration
// 	// This is safe as config doesn't import output
// 	globalConfig := getGlobalConfigForOutput()
// 	if globalConfig == nil {
// 		log.Debug("[output/manager] No global config available, falling back to all outputs")
// 		return []string{}
// 	}

// 	// Find the domain config by key
// 	if domainConfig, exists := globalConfig.GetDomains()[domainConfigKey]; exists {
// 		// Use the GetOutputs helper method to get effective outputs
// 		outputs := domainConfig.GetOutputs()
// 		log.Debug("[output/manager] Domain config '%s' allows outputs: %v", domainConfigKey, outputs)
// 		return outputs
// 	}

// 	log.Debug("[output/manager] Domain config '%s' not found, falling back to all outputs", domainConfigKey)
// 	return []string{} // No outputs = fall back to all
// }

// GetProfile returns a specific output profile by name
func (om *OutputManager) GetProfile(profileName string) OutputFormat {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	return om.profiles[profileName]
}

// AddProfile adds an output profile to the manager
func (om *OutputManager) AddProfile(profileName, path string, domains []string, config map[string]interface{}) error {
	om.mutex.Lock()
	defer om.mutex.Unlock()

	if _, exists := om.profiles[profileName]; exists {
		log.Debug("[output] Output profile '%s' already exists, skipping duplicate registration", profileName)
		return nil
	}

	var outputFormat OutputFormat
	var err error

	// Support both 'format' and 'type' as synonyms for output format
	format, _ := config["format"].(string)
	if format == "" {
		if t, ok := config["type"].(string); ok && t != "" {
			format = t
		}
	}

	// Patch: For file/hosts outputs, ensure the real DNS domain is passed as the first argument
	// and is also set in the config map for downstream constructors.
	if format == "file" || format == "json" || format == "yaml" || format == "hosts" || format == "zone" {
		domainArg := profileName // fallback
		if domainFromConfig, ok := config["domain"].(string); ok && domainFromConfig != "" {
			domainArg = domainFromConfig
		} else {
			// Try to infer from domains config if available
			globalConfig := getGlobalConfigForOutput()
			if globalConfig != nil {
				for _, domainConfig := range globalConfig.GetDomains() {
					for _, output := range domainConfig.GetOutputs() {
						if output == profileName {
							domainArg = domainConfig.GetName()
							break
						}
					}
				}
			}
		}
		// Always set the domain in the config for downstream constructors (hosts/zone need it)
		config["domain"] = domainArg
		// FIX: Pass the output profile name as the first argument, not the domain
		outputFormat, err = fileoutput.NewFileOutput(profileName, config)
	} else if format == "dns" {
		// Use the DNS provider registry to instantiate the provider
		providerName, ok := config["provider"].(string)
		if !ok || providerName == "" {
			return fmt.Errorf("dns output requires 'provider' field")
		}
		// Pass profileName in config for per-profile log prefixing
		providerConfig := make(map[string]string)
		for k, v := range config {
			if str, ok := v.(string); ok {
				providerConfig[k] = str
			}
		}
		providerConfig["profile_name"] = profileName
		provider, errProvider := dns.GetProvider(providerName, providerConfig)
		if errProvider != nil {
			return fmt.Errorf("failed to instantiate DNS provider '%s': %v", providerName, errProvider)
		}
		outputFormat = &dns.DNSOutputFormat{
			ProfileName: profileName,
			Provider:    provider,
			Config:      config,
		}
	} else {
		// Generic registry lookup for any other format (e.g., remote)
		registryMutex.RLock()
		createFunc, exists := outputFormatRegistry[format]
		registryMutex.RUnlock()
		if exists {
			outputFormat, err = createFunc(profileName, config)
		} else {
			return fmt.Errorf("unsupported output format: %s", format)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to create %s format: %v", format, err)
	}

	om.profiles[profileName] = outputFormat
	// Only log here, and only once, at INFO level
	log.Info("[output] Registered output profile '%s' (%s)", profileName, format)
	return nil
}

// WriteRecord writes a DNS record to all output formats
func (om *OutputManager) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return om.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

// WriteRecordWithSource writes a DNS record with source information to all output formats
func (om *OutputManager) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	for profileName, outputFormat := range om.profiles {
		err := outputFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
		if err != nil {
			log.Error("[output/manager/%s] Failed to write record to profile '%s': %v", strings.ReplaceAll(domain, ".", "_"), profileName, err)
			return err
		}

		// Mark this profile as changed for this source - use more specific key
		om.changesMutex.Lock()
		if om.changedProfiles[source] == nil {
			om.changedProfiles[source] = make(map[string]bool)
		}
		om.changedProfiles[source][profileName] = true
		// Debug: print changedProfiles for this source
		log.Debug("[output/manager] changedProfiles[%s] after WriteRecordWithSource: %v", source, om.changedProfiles[source])
		om.changesMutex.Unlock()
	}
	return nil
}

// RemoveRecord removes a DNS record from all output formats
func (om *OutputManager) RemoveRecord(domain, hostname, recordType string) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	for profileName, outputFormat := range om.profiles {
		err := outputFormat.RemoveRecord(domain, hostname, recordType)
		if err != nil {
			log.Error("[output/manager/%s] Failed to remove record from profile '%s': %v", strings.ReplaceAll(domain, ".", "_"), profileName, err)
			return err
		}
	}
	return nil
}

// SyncAll syncs all output formats
func (om *OutputManager) SyncAll() error {
	// Prevent concurrent sync operations
	om.syncMutex.Lock()
	defer om.syncMutex.Unlock()

	// Check if we're within the cooldown period
	if time.Since(om.lastSync) < om.syncCooldown {
		log.Debug("[output/manager] Sync throttled - last sync was %v ago (cooldown: %v)",
			time.Since(om.lastSync), om.syncCooldown)
		return nil
	}

	log.Debug("[output/manager] SyncAll called. lastSync=%v, syncCooldown=%v", om.lastSync, om.syncCooldown)

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	// Get list of changed profiles from all sources
	om.changesMutex.RLock()
	changedProfilesSet := make(map[string]bool)
	for _, profileMap := range om.changedProfiles {
		for profileName, changed := range profileMap {
			if changed {
				changedProfilesSet[profileName] = true
			}
		}
	}
	om.changesMutex.RUnlock()

	log.Debug("[output/manager] changedProfiles map at sync: %+v", om.changedProfiles)

	if len(changedProfilesSet) == 0 {
		log.Debug("[output/manager] No changed profiles to sync (changedProfilesSet empty)")
		return nil
	}

	changedProfiles := make([]string, 0, len(changedProfilesSet))
	for profileName := range changedProfilesSet {
		changedProfiles = append(changedProfiles, profileName)
	}

	log.Debug("[output/manager] Starting sync for %d changed output profiles: %v", len(changedProfiles), changedProfiles)

	for _, profileName := range changedProfiles {
		if outputFormat, exists := om.profiles[profileName]; exists {
			log.Debug("[output/manager] Syncing changed profile: %s", profileName)
			err := outputFormat.Sync()
			if err != nil {
				log.Error("[output/manager] Failed to sync profile '%s': %v", profileName, err)
				return err
			}
			log.Debug("[output/manager] Successfully synced profile: %s", profileName)
		}
	}

	// Clear change tracking after successful sync
	om.changesMutex.Lock()
	om.changedProfiles = make(map[string]map[string]bool)
	om.changesMutex.Unlock()

	// Update last sync time
	om.lastSync = time.Now()

	log.Debug("[output/manager] Completed sync for %d changed profiles", len(changedProfiles))
	return nil
}

// SyncAllFromSource syncs only output formats that have changes from a specific source
func (om *OutputManager) SyncAllFromSource(source string) error {
	// Prevent concurrent sync operations
	om.syncMutex.Lock()
	defer om.syncMutex.Unlock()

	// Check if we're within the cooldown period
	if time.Since(om.lastSync) < om.syncCooldown {
		log.Debug("[output/manager] Sync throttled for source '%s' - last sync was %v ago (cooldown: %v)",
			source, time.Since(om.lastSync), om.syncCooldown)
		return nil
	}

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	// Get list of changed profiles for this specific source
	om.changesMutex.RLock()
	sourceChanges, exists := om.changedProfiles[source]
	// Debug: print changedProfiles for this source at start of sync
	log.Debug("[output/manager] changedProfiles[%s] at start of SyncAllFromSource: %v", source, sourceChanges)
	if !exists || len(sourceChanges) == 0 {
		om.changesMutex.RUnlock()
		log.Debug("[output/manager] No changed profiles to sync for source '%s'", source)
		return nil
	}

	changedProfiles := make([]string, 0, len(sourceChanges))
	for profileName, changed := range sourceChanges {
		if changed {
			changedProfiles = append(changedProfiles, profileName)
		}
	}
	om.changesMutex.RUnlock()

	if len(changedProfiles) == 0 {
		log.Debug("[output/manager] No changed profiles to sync for source '%s'", source)
		return nil
	}

	log.Debug("[output/manager] Starting sync for %d changed output profiles from source '%s': %v", len(changedProfiles), source, changedProfiles)

	for _, profileName := range changedProfiles {
		if outputFormat, exists := om.profiles[profileName]; exists {
			log.Debug("[output/manager] Syncing changed profile: %s (source: %s)", profileName, source)
			err := outputFormat.Sync()
			if err != nil {
				log.Error("[output/manager] Failed to sync profile '%s' from source '%s': %v", profileName, source, err)
				return err
			}
			log.Debug("[output/manager] Successfully synced profile: %s (source: %s)", profileName, source)
		}
	}

	// Clear change tracking for this source after successful sync
	om.changesMutex.Lock()
	delete(om.changedProfiles, source)
	om.changesMutex.Unlock()

	// Update last sync time
	om.lastSync = time.Now()

	log.Debug("[output/manager] Completed sync for %d changed profiles from source '%s'", len(changedProfiles), source)
	return nil
}

// InitializeOutputManagerWithProfiles initializes the output manager with specific profiles from config
func InitializeOutputManagerWithProfiles(outputConfigs map[string]interface{}, enabledProfiles []string) error {
	outputManagerInitCount++
	log.Trace("[output] InitializeOutputManagerWithProfiles called %d time(s)", outputManagerInitCount)

	globalOutputManagerMutex.Lock()
	if globalOutputManager != nil {
		globalOutputManagerMutex.Unlock()
		return nil
	}
	globalOutputManagerMutex.Unlock()

	outputManager := NewOutputManager()

	log.Trace("[output] Starting output manager initialization with profiles: %v", enabledProfiles)

	if outputConfigs != nil {

		// Create a set for faster lookup
		enabledSet := make(map[string]bool)
		for _, profile := range enabledProfiles {
			enabledSet[profile] = true
		}

		// Register all profiles from config, not just enabledProfiles
		for profileName, profileConfig := range outputConfigs {
			log.Debug("[output] Processing profile: %s", profileName)

			configMap, ok := profileConfig.(map[string]interface{})
			if !ok {
				log.Error("[output] Invalid config for profile '%s', skipping", profileName)
				continue
			}
			path, _ := configMap["path"].(string)
			domains := []string{}
			if d, ok := configMap["domains"].([]interface{}); ok {
				for _, v := range d {
					if s, ok := v.(string); ok {
						domains = append(domains, s)
					}
				}
			}
			err := outputManager.AddProfile(profileName, path, domains, configMap)
			if err != nil {
				log.Error("[output] Failed to add profile '%s': %v", profileName, err)
			}
		}
	} else {
		log.Debug("[output] No outputs configuration found")
	}

	SetGlobalOutputManager(outputManager)
	return nil
}

// createPlaceholderFileFormat creates a placeholder file format that logs operations but doesn't write files
// func createPlaceholderFileFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
// 	return &placeholderFormat{
// 		profileName: profileName,
// 		formatType:  "file",
// 	}, nil
// }

// createPlaceholderDNSFormat creates a placeholder DNS format that logs operations but doesn't make DNS calls
// func createPlaceholderDNSFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
// 	return &placeholderFormat{
// 		profileName: profileName,
// 		formatType:  "dns",
// 	}, nil
// }

// placeholderFormat is a placeholder implementation for formats that aren't fully implemented
type placeholderFormat struct {
	profileName string
	formatType  string
}

func (p *placeholderFormat) GetName() string { return p.formatType }

func (p *placeholderFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return p.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

func (p *placeholderFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	log.Debug("[output/%s/%s] Would write record: %s %s -> %s (TTL: %d, Source: %s)",
		p.formatType, strings.ReplaceAll(domain, ".", "_"), hostname, recordType, target, ttl, source)
	return nil
}

func (p *placeholderFormat) RemoveRecord(domain, hostname, recordType string) error {
	log.Debug("[output/%s/%s] Would remove record: %s %s",
		p.formatType, strings.ReplaceAll(domain, ".", "_"), hostname, recordType)
	return nil
}

func (p *placeholderFormat) Sync() error {
	log.Debug("[output/%s] Would sync %s format (placeholder implementation)", p.formatType, p.formatType)
	return nil
}
