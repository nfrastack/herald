// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package output

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output/types/common"
	"github.com/nfrastack/herald/internal/output/types/dns"
	fileoutput "github.com/nfrastack/herald/internal/output/types/file"

	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DomainConfig interface {
	GetOutputs() []string
	GetName() string
}

type GlobalConfigForOutput interface {
	GetDomains() map[string]DomainConfig
}

var globalConfigGetter func() GlobalConfigForOutput

func SetGlobalConfigGetter(getter func() GlobalConfigForOutput) {
	globalConfigGetter = getter
}

func getGlobalConfigForOutput() GlobalConfigForOutput {
	if globalConfigGetter != nil {
		return globalConfigGetter()
	}
	return nil
}

func (om *OutputManager) writeToProfile(profileName string, profile OutputFormat, domain, hostname, target, recordType string, ttl int, source string, proxied bool, overwrite bool) (bool, string) {
	if df, ok := profile.(*dns.DNSOutputFormat); ok {
		if df.Provider == nil {
			return false, fmt.Sprintf("profile '%s': dns provider not initialized", profileName)
		}
		applyProxied := false
		if proxied && df.Provider.SupportsProxied() {
			applyProxied = true
		}
		if err := df.Provider.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, applyProxied, "", source, overwrite); err != nil {
			return false, fmt.Sprintf("profile '%s': %v", profileName, err)
		}
		mgrLog.With("profile", profileName).Debug("Successfully wrote record to DNS profile (proxied=%t)", applyProxied)
	} else {
		if err := profile.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source); err != nil {
			return false, fmt.Sprintf("profile '%s': %v", profileName, err)
		}
		mgrLog.With("profile", profileName).Debug("Successfully wrote record to profile")
	}

	om.changesMutex.Lock()
	if om.changedProfiles[source] == nil {
		om.changedProfiles[source] = make(map[string]bool)
	}
	om.changedProfiles[source][profileName] = true
	om.changesMutex.Unlock()

	return true, ""
}

var outLog = log.NewScopedLogger("[output]", "")

func init() {
	outLog.Debug("Auto-registering core output types")

	registerAllCoreFormats()
}

func registerAllCoreFormats() {
	RegisterFormat("file", fileoutput.NewFileOutput)
	RegisterFormat("file/json", fileoutput.NewFileOutput)
	RegisterFormat("file/yaml", fileoutput.NewFileOutput)
	RegisterFormat("file/zone", fileoutput.NewFileOutput)
	RegisterFormat("file/hosts", fileoutput.NewFileOutput)

	outLog.Debug("Registered core formats: file")
}

var (
	outputFormatRegistry   = make(map[string]func(string, map[string]interface{}) (OutputFormat, error))
	registryMutex          sync.RWMutex
	outputManagerInitCount int // Track how many times output manager is initialized
)

func RegisterFormat(formatName string, createFunc func(string, map[string]interface{}) (OutputFormat, error)) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	if _, exists := outputFormatRegistry[formatName]; exists {
		outLog.With("format", formatName).Debug("Format already registered, skipping duplicate registration")
		return
	}
	outputFormatRegistry[formatName] = createFunc
	outLog.With("format", formatName).Debug("Registered format creator")
}

func GetOutputManager() *OutputManager {
	return GetGlobalOutputManager()
}

type OutputFormat = common.OutputFormat

type OutputManager struct {
	profiles        map[string]OutputFormat
	mutex           sync.RWMutex
	syncMutex       sync.Mutex                 // Prevent concurrent sync operations
	lastSync        time.Time                  // Track last sync time
	syncCooldown    time.Duration              // Minimum time between syncs
	changedProfiles map[string]map[string]bool // Track which profiles have changes per source
	changesMutex    sync.RWMutex               // Protect changes tracking
}

func NewOutputManager() *OutputManager {
	return &OutputManager{
		profiles:        make(map[string]OutputFormat),
		syncCooldown:    0, // Disable cooldown for debugging
		changedProfiles: make(map[string]map[string]bool),
	}
}

var globalOutputManager *OutputManager
var globalOutputManagerMutex sync.RWMutex

func SetGlobalOutputManager(manager *OutputManager) {
	globalOutputManagerMutex.Lock()
	defer globalOutputManagerMutex.Unlock()
	globalOutputManager = manager
}

func GetGlobalOutputManager() *OutputManager {
	globalOutputManagerMutex.RLock()
	defer globalOutputManagerMutex.RUnlock()
	return globalOutputManager
}

func (om *OutputManager) WriteRecordWithSourceAndDomainFilter(domainConfigKey, domain, hostname, target, recordType string, ttl int, source string, proxied bool, overwrite bool, domainManager interface{}) error {
	var allowedOutputs []string

	if dm, ok := domainManager.(interface {
		GetAllDomains() map[string]DomainConfig
	}); ok {
		if config, exists := dm.GetAllDomains()[domainConfigKey]; exists {
			allowedOutputs = config.GetOutputs()
		}
	}

	if len(allowedOutputs) == 0 {
		globalConfig := getGlobalConfigForOutput()
		if globalConfig != nil {
			if config, exists := globalConfig.GetDomains()[domainConfigKey]; exists {
				allowedOutputs = config.GetOutputs()
			}
		}
	}

	if dm, ok := domainManager.(interface {
		ValidateOutputProfileAccess(domainConfigKey, outputProfileName string) bool
	}); ok {
		filtered := make([]string, 0, len(allowedOutputs))
		for _, outputProfile := range allowedOutputs {
			if dm.ValidateOutputProfileAccess(domainConfigKey, outputProfile) {
				filtered = append(filtered, outputProfile)
			} else {
				mgrLog.With("profile", outputProfile, "config", domainConfigKey).Debug("Output profile not allowed for domain config key (filtered by ValidateOutputProfileAccess)")
			}
		}
		allowedOutputs = filtered
	}

	if len(allowedOutputs) == 0 {
		mgrLog.With("config", domainConfigKey).Warn("No outputs allowed for domain config key after filtering - skipping record write")
		return nil
	}

	mgrLog.With("config", domainConfigKey, "domain", domain, "source", source).Debug("Routing record write: hostname='%s', target='%s', recordType='%s', ttl=%d, proxied=%t, allowedOutputs=%v", hostname, target, recordType, ttl, proxied, allowedOutputs)

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	writtenCount := 0
	var errors []string

	for _, outputProfile := range allowedOutputs {
		if profile, exists := om.profiles[outputProfile]; exists {
			written, errStr := om.writeToProfile(outputProfile, profile, domain, hostname, target, recordType, ttl, source, proxied, overwrite)
			if errStr != "" {
				errors = append(errors, errStr)
			} else if written {
				writtenCount++
				mgrLog.With("source", source).Debug("changedProfiles after WriteRecordWithSourceAndDomainFilter: %v", om.changedProfiles[source])
			}
		} else {
			mgrLog.With("profile", outputProfile, "config", domainConfigKey).Warn("Output profile not found (referenced by domain config key)")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to write to some outputs: %s", strings.Join(errors, "; "))
	}

	if writtenCount > 0 {
		mgrLog.With("config", domainConfigKey).Debug("Successfully wrote to %d output profiles", writtenCount)
	}

	return nil
}

func (om *OutputManager) GetProfile(profileName string) OutputFormat {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	return om.profiles[profileName]
}

func (om *OutputManager) AddProfile(profileName, path string, domains []string, config map[string]interface{}) error {
	om.mutex.Lock()
	defer om.mutex.Unlock()

	if _, exists := om.profiles[profileName]; exists {
		outLog.With("profile", profileName).Debug("Output profile already exists, skipping duplicate registration")
		return nil
	}

	var outputFormat OutputFormat
	var err error

	format, _ := config["format"].(string)
	if format == "" {
		if t, ok := config["type"].(string); ok && t != "" {
			format = t
		}
	}

	if format == "file" || format == "json" || format == "yaml" || format == "hosts" || format == "zone" {
		domainArg := profileName // fallback
		if domainFromConfig, ok := config["domain"].(string); ok && domainFromConfig != "" {
			domainArg = domainFromConfig
		} else {
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
		config["domain"] = domainArg
		outputFormat, err = fileoutput.NewFileOutput(profileName, config)
	} else if format == "dns" {
		providerName, ok := config["provider"].(string)
		if !ok || providerName == "" {
			return fmt.Errorf("dns output requires 'provider' field")
		}
		providerConfig := make(map[string]string)
		for k, v := range config {
			switch t := v.(type) {
			case string:
				providerConfig[k] = t
			case bool:
				providerConfig[k] = strconv.FormatBool(t)
			case int:
				providerConfig[k] = strconv.Itoa(t)
			case float64:
				providerConfig[k] = strconv.Itoa(int(t))
			case map[string]interface{}:
				for nk, nv := range t {
					providerConfig[k+"."+nk] = fmt.Sprintf("%v", nv)
				}
			case []interface{}:
				for i, item := range t {
					providerConfig[fmt.Sprintf("%s.%d", k, i)] = fmt.Sprintf("%v", item)
				}
			default:
				providerConfig[k] = fmt.Sprintf("%v", v)
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
	outLog.With("profile", profileName).Info("Registered output profile (%s)", format)
	return nil
}

func (om *OutputManager) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return om.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

func (om *OutputManager) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	for profileName, outputFormat := range om.profiles {
		err := outputFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
		if err != nil {
			mgrLog.With("domain", domain, "profile", profileName).Error("Failed to write record to profile: %v", err)
			return err
		}

		om.changesMutex.Lock()
		if om.changedProfiles[source] == nil {
			om.changedProfiles[source] = make(map[string]bool)
		}
		om.changedProfiles[source][profileName] = true
		mgrLog.With("source", source).Debug("changedProfiles after WriteRecordWithSource: %v", om.changedProfiles[source])
		om.changesMutex.Unlock()
	}
	return nil
}

func (om *OutputManager) RemoveRecord(domain, hostname, recordType string) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	for profileName, outputFormat := range om.profiles {
		err := outputFormat.RemoveRecord(domain, hostname, recordType)
		if err != nil {
			mgrLog.With("domain", domain, "profile", profileName).Error("Failed to remove record from profile: %v", err)
			return err
		}
	}
	return nil
}

func (om *OutputManager) SyncAll() error {
	om.syncMutex.Lock()
	defer om.syncMutex.Unlock()

	if time.Since(om.lastSync) < om.syncCooldown {
		mgrLog.Debug("Sync throttled - last sync was %v ago (cooldown: %v)", time.Since(om.lastSync), om.syncCooldown)
		return nil
	}

	mgrLog.Debug("SyncAll called. lastSync=%v, syncCooldown=%v", om.lastSync, om.syncCooldown)

	om.mutex.RLock()
	defer om.mutex.RUnlock()

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

	mgrLog.Debug("changedProfiles map at sync: %+v", om.changedProfiles)

	if len(changedProfilesSet) == 0 {
		mgrLog.Debug("No changed profiles to sync (changedProfilesSet empty)")
		return nil
	}

	changedProfiles := make([]string, 0, len(changedProfilesSet))
	for profileName := range changedProfilesSet {
		changedProfiles = append(changedProfiles, profileName)
	}

	mgrLog.Debug("Starting sync for %d changed output profiles: %v", len(changedProfiles), changedProfiles)

	for _, profileName := range changedProfiles {
		if outputFormat, exists := om.profiles[profileName]; exists {
			mgrLog.With("profile", profileName).Debug("Syncing changed profile")
			err := outputFormat.Sync()
			if err != nil {
				mgrLog.With("profile", profileName).Error("Failed to sync profile: %v", err)
				return err
			}
			mgrLog.With("profile", profileName).Debug("Successfully synced profile")
		}
	}

	om.changesMutex.Lock()
	om.changedProfiles = make(map[string]map[string]bool)
	om.changesMutex.Unlock()

	om.lastSync = time.Now()

	mgrLog.Debug("Completed sync for %d changed profiles", len(changedProfiles))
	return nil
}

func (om *OutputManager) SyncAllFromSource(source string) error {
	om.syncMutex.Lock()
	defer om.syncMutex.Unlock()

	if time.Since(om.lastSync) < om.syncCooldown {
		mgrLog.With("source", source).Debug("Sync throttled for source - last sync was %v ago (cooldown: %v)", time.Since(om.lastSync), om.syncCooldown)
		return nil
	}

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	om.changesMutex.RLock()
	sourceChanges, exists := om.changedProfiles[source]
	mgrLog.With("source", source).Trace("changedProfiles at start of SyncAllFromSource: %v", sourceChanges)
	if !exists || len(sourceChanges) == 0 {
		om.changesMutex.RUnlock()
		mgrLog.With("source", source).Trace("No changed profiles to sync for source")
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
		mgrLog.With("source", source).Trace("No changed profiles to sync for source")
		return nil
	}

	mgrLog.With("source", source).Debug("Starting sync for %d changed output profiles: %v", len(changedProfiles), changedProfiles)

	for _, profileName := range changedProfiles {
		if outputFormat, exists := om.profiles[profileName]; exists {
			mgrLog.With("profile", profileName, "source", source).Debug("Syncing changed profile")
			err := outputFormat.Sync()
			if err != nil {
				mgrLog.With("profile", profileName, "source", source).Error("Failed to sync profile: %v", err)
				return err
			}
			mgrLog.With("profile", profileName, "source", source).Debug("Successfully synced profile")
		}
	}

	om.changesMutex.Lock()
	delete(om.changedProfiles, source)
	om.changesMutex.Unlock()

	om.lastSync = time.Now()

	mgrLog.With("source", source).Debug("Completed sync for %d changed profiles", len(changedProfiles))
	return nil
}

func InitializeOutputManagerWithProfiles(outputConfigs map[string]interface{}, enabledProfiles []string) error {
	outputManagerInitCount++
	outLog.Trace("InitializeOutputManagerWithProfiles called %d time(s)", outputManagerInitCount)

	globalOutputManagerMutex.Lock()
	if globalOutputManager != nil {
		globalOutputManagerMutex.Unlock()
		return nil
	}
	globalOutputManagerMutex.Unlock()

	outputManager := NewOutputManager()

	outLog.Trace("Starting output manager initialization with profiles: %v", enabledProfiles)

	if outputConfigs != nil {

		enabledSet := make(map[string]bool)
		for _, profile := range enabledProfiles {
			enabledSet[profile] = true
		}

		for profileName, profileConfig := range outputConfigs {
			outLog.With("profile", profileName).Debug("Processing profile")

			configMap, ok := profileConfig.(map[string]interface{})
			if !ok {
				outLog.With("profile", profileName).Error("Invalid config for profile, skipping")
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
				outLog.With("profile", profileName).Error("Failed to add profile: %v", err)
			}
		}
	} else {
		outLog.Debug("No outputs configuration found")
	}

	SetGlobalOutputManager(outputManager)
	return nil
}
