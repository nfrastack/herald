// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package output

import (
	"slices"

	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output/types/common"
	"github.com/nfrastack/herald/internal/output/types/dns"
	fileoutput "github.com/nfrastack/herald/internal/output/types/file"
	state "github.com/nfrastack/herald/internal/state"

	"fmt"
	"strconv"
	"sync"
	"time"
)

type DomainConfig interface {
	GetOutputs() []string
	GetName() string
	GetZoneID() string
}

type GlobalConfigForOutput interface {
	GetDomains() map[string]DomainConfig
}

var globalConfigGetter func() GlobalConfigForOutput

var dryRun bool
var dryRunMutex sync.RWMutex

func SetDryRun(v bool) {
	dryRunMutex.Lock()
	defer dryRunMutex.Unlock()
	dryRun = v
}

func DryRun() bool {
	dryRunMutex.RLock()
	defer dryRunMutex.RUnlock()
	return dryRun
}

func SetGlobalConfigGetter(getter func() GlobalConfigForOutput) {
	globalConfigGetter = getter
}

func getGlobalConfigForOutput() GlobalConfigForOutput {
	if globalConfigGetter != nil {
		return globalConfigGetter()
	}
	return nil
}

func (om *OutputManager) markChanged(source, profile string) {
	om.changesMutex.Lock()
	defer om.changesMutex.Unlock()
	if om.changedProfiles[source] == nil {
		om.changedProfiles[source] = make(map[string]uint64)
	}
	om.changeClock++
	om.changedProfiles[source][profile] = om.changeClock
}

func (om *OutputManager) writeToProfile(profileName string, profile OutputFormat, domain, hostname, target, recordType string, ttl int, source string, proxied bool, overwrite bool) (bool, string) {
	if DryRun() {
		mgrLog.With("action", "dryrun.skip", "profile", profileName, "domain", domain).Debug("write skipped: %s %s -> %s", hostname, recordType, target)
		return false, ""
	}
	if df, ok := profile.(*dns.DNSOutputFormat); ok {
		if df.Provider == nil {
			return false, fmt.Sprintf("profile '%s': dns provider not initialized", profileName)
		}
		applyProxied := false
		if proxied && df.Provider.SupportsProxied() {
			applyProxied = true
		}
		// Stable first-seen/last-modified comment from presence tracking.
		// Callers Touch state before writing, so FirstSeen is preserved
		// across polls and LastModified only moves when the target
		// changes - the comment is byte-identical while the record is
		// unchanged, letting providers skip the update entirely.
		comment := state.CommentFor(domain, hostname, recordType, source)
		if !df.ShouldWrite(domain, hostname, target, recordType, ttl, applyProxied) {
			return false, ""
		}
		if err := df.Provider.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, applyProxied, comment, source, overwrite); err != nil {
			return false, fmt.Sprintf("profile '%s': %v", profileName, err)
		}
		df.NoteWritten(domain, hostname, target, recordType, ttl, applyProxied)
		mgrLog.With("action", "record.create", "profile", profileName).Debug("record to DNS profile (proxied=%t)", applyProxied)
	} else {
		if err := profile.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source); err != nil {
			return false, fmt.Sprintf("profile '%s': %v", profileName, err)
		}
		mgrLog.With("action", "record.create", "profile", profileName).Debug("record to profile")
	}

	om.markChanged(source, profileName)

	return true, ""
}

var outLog = log.NewScopedLogger("[output]", "")

func init() {
	outLog.With("action", "provider.init").Debug("core output types")

	registerAllCoreFormats()
}

func registerAllCoreFormats() {
	RegisterFormat("file", fileoutput.NewFileOutput)
	RegisterFormat("file/json", fileoutput.NewFileOutput)
	RegisterFormat("file/yaml", fileoutput.NewFileOutput)
	RegisterFormat("file/zone", fileoutput.NewFileOutput)
	RegisterFormat("file/hosts", fileoutput.NewFileOutput)

	outLog.With("action", "provider.init").Debug("core formats: file")
}

var (
	outputFormatRegistry   = make(map[string]func(string, map[string]any) (OutputFormat, error))
	registryMutex          sync.RWMutex
	outputManagerInitCount int // Track how many times output manager is initialized
)

func RegisterFormat(formatName string, createFunc func(string, map[string]any) (OutputFormat, error)) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	if _, exists := outputFormatRegistry[formatName]; exists {
		outLog.With("action", "provider.init", "format", formatName).Debug("already registered, skipping duplicate registration")
		return
	}
	outputFormatRegistry[formatName] = createFunc
	outLog.With("action", "provider.init", "format", formatName).Debug("format creator")
}

func GetOutputManager() *OutputManager {
	return GetGlobalOutputManager()
}

type OutputFormat = common.OutputFormat

type OutputManager struct {
	profiles        map[string]OutputFormat
	mutex           sync.RWMutex
	syncMutex       sync.Mutex                   // Prevent concurrent sync operations
	lastSync        time.Time                    // Track last sync time
	syncCooldown    time.Duration                // Minimum time between syncs
	changedProfiles map[string]map[string]uint64 // Track which profiles have changes per source
	changeClock     uint64                       // Monotonic generation for change marks
	changesMutex    sync.RWMutex                 // Protect changes tracking
}

func NewOutputManager() *OutputManager {
	return &OutputManager{
		profiles:        make(map[string]OutputFormat),
		syncCooldown:    0, // Disable cooldown for debugging
		changedProfiles: make(map[string]map[string]uint64),
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

func (om *OutputManager) GetProfile(profileName string) OutputFormat {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	return om.profiles[profileName]
}

func (om *OutputManager) AddProfile(profileName, path string, domains []string, config map[string]any) error {
	om.mutex.Lock()
	defer om.mutex.Unlock()

	if _, exists := om.profiles[profileName]; exists {
		outLog.With("action", "provider.init", "profile", profileName).Debug("profile already exists, skipping duplicate registration")
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
					if slices.Contains(domainConfig.GetOutputs(), profileName) {
						domainArg = domainConfig.GetName()
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
			case map[string]any:
				for nk, nv := range t {
					providerConfig[k+"."+nk] = fmt.Sprintf("%v", nv)
				}
			case []any:
				for i, item := range t {
					providerConfig[fmt.Sprintf("%s.%d", k, i)] = fmt.Sprintf("%v", item)
				}
			default:
				providerConfig[k] = fmt.Sprintf("%v", v)
			}
		}
		providerConfig["profile_name"] = profileName
		if globalConfig := getGlobalConfigForOutput(); globalConfig != nil {
			for key, domainConfig := range globalConfig.GetDomains() {
				if !slices.Contains(domainConfig.GetOutputs(), profileName) {
					continue
				}
				zoneID := domainConfig.GetZoneID()
				if zoneID == "" {
					continue
				}
				domainName := domainConfig.GetName()
				if domainName == "" {
					domainName = key
				}
				providerConfig["zone_ids."+domainName] = zoneID
			}
		}
		provider, errProvider := dns.GetProvider(providerName, providerConfig)
		if errProvider != nil {
			return fmt.Errorf("failed to instantiate DNS provider '%s': %v", providerName, errProvider)
		}
		outputFormat = &dns.DNSOutputFormat{
			ProfileName: profileName,
			Provider:    provider,
			Config:      config,
		}
		if err := provider.Validate(); err != nil {
			return fmt.Errorf("dns provider '%s' validation failed: %v", providerName, err)
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
	outLog.With("action", "provider.init", "profile", profileName).Info("output profile (%s)", format)
	return nil
}

func (om *OutputManager) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return om.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

func (om *OutputManager) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	if DryRun() {
		mgrLog.With("action", "dryrun.skip", "domain", domain).Debug("write skipped: %s %s -> %s", hostname, recordType, target)
		return nil
	}

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	for profileName, outputFormat := range om.profiles {
		err := outputFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
		if err != nil {
			mgrLog.With("action", "output.write", "domain", domain, "profile", profileName).Error("record to profile: %v", err)
			return err
		}

		om.markChanged(source, profileName)
		om.changesMutex.RLock()
		mgrLog.With("action", "state.save", "source", source).Debug("changed profiles after WriteRecordWithSource: %v", om.changedProfiles[source])
		om.changesMutex.RUnlock()
	}
	return nil
}

func (om *OutputManager) RemoveRecord(domain, hostname, recordType string) error {
	if DryRun() {
		mgrLog.With("action", "dryrun.skip", "domain", domain).Debug("removal skipped: %s %s", hostname, recordType)
		return nil
	}

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	for profileName, outputFormat := range om.profiles {
		err := outputFormat.RemoveRecord(domain, hostname, recordType)
		if err != nil {
			mgrLog.With("action", "output.remove", "domain", domain, "profile", profileName).Error("record from profile: %v", err)
			return err
		}
	}
	return nil
}

func (om *OutputManager) SyncAllFromSource(source string) error {
	if DryRun() {
		mgrLog.With("action", "dryrun.skip", "source", source).Debug("sync skipped")
		return nil
	}

	om.syncMutex.Lock()
	defer om.syncMutex.Unlock()

	if time.Since(om.lastSync) < om.syncCooldown {
		mgrLog.With("action", "sync.skip", "source", source).Debug("throttled for source - last sync was %v ago (cooldown: %v)", time.Since(om.lastSync), om.syncCooldown)
		return nil
	}

	om.mutex.RLock()
	defer om.mutex.RUnlock()

	om.changesMutex.RLock()
	sourceChanges, exists := om.changedProfiles[source]
	mgrLog.With("action", "sync.start", "source", source).Trace("profiles at start of SyncAllFromSource: %v", sourceChanges)
	if !exists || len(sourceChanges) == 0 {
		om.changesMutex.RUnlock()
		mgrLog.With("action", "sync.skip", "source", source).Trace("no changed profiles to sync for source")
		return nil
	}

	changedProfiles := make(map[string]uint64, len(sourceChanges))
	for profileName, gen := range sourceChanges {
		changedProfiles[profileName] = gen
	}
	om.changesMutex.RUnlock()

	if len(changedProfiles) == 0 {
		mgrLog.With("action", "sync.skip", "source", source).Trace("no changed profiles to sync for source")
		return nil
	}

	mgrLog.With("action", "sync.start", "source", source).Debug("sync for %d changed output profiles: %v", len(changedProfiles), changedProfiles)

	for profileName := range changedProfiles {
		if outputFormat, exists := om.profiles[profileName]; exists {
			mgrLog.With("action", "sync.start", "profile", profileName, "source", source).Debug("changed profile")
			err := outputFormat.Sync()
			if err != nil {
				mgrLog.With("action", "sync.fail", "profile", profileName, "source", source).Error("profile: %v", err)
				return err
			}
			mgrLog.With("action", "sync.done", "profile", profileName, "source", source).Debug("profile")
		}
	}

	om.changesMutex.Lock()
	if profiles, ok := om.changedProfiles[source]; ok {
		for profileName, gen := range changedProfiles {
			if profiles[profileName] == gen {
				delete(profiles, profileName)
			}
		}
		if len(profiles) == 0 {
			delete(om.changedProfiles, source)
		}
	}
	om.changesMutex.Unlock()

	om.lastSync = time.Now()

	mgrLog.With("action", "sync.done", "source", source).Debug("sync for %d changed profiles", len(changedProfiles))
	return nil
}

func InitializeOutputManagerWithProfiles(outputConfigs map[string]any, enabledProfiles []string) error {
	outputManagerInitCount++
	outLog.With("action", "provider.init").Trace("called %d time(s)", outputManagerInitCount)

	globalOutputManagerMutex.Lock()
	if globalOutputManager != nil {
		globalOutputManagerMutex.Unlock()
		return nil
	}
	globalOutputManagerMutex.Unlock()

	outputManager := NewOutputManager()

	outLog.With("action", "provider.init").Trace("output manager initialization with profiles: %v", enabledProfiles)

	if outputConfigs != nil {

		enabledSet := make(map[string]bool)
		for _, profile := range enabledProfiles {
			enabledSet[profile] = true
		}

		for profileName, profileConfig := range outputConfigs {
			outLog.With("action", "provider.init", "profile", profileName).Debug("profile")

			configMap, ok := profileConfig.(map[string]any)
			if !ok {
				outLog.With("action", "config.error", "profile", profileName).Error("config for profile invalid, skipping")
				continue
			}
			path, _ := configMap["path"].(string)
			domains := []string{}
			if d, ok := configMap["domains"].([]any); ok {
				for _, v := range d {
					if s, ok := v.(string); ok {
						domains = append(domains, s)
					}
				}
			}
			err := outputManager.AddProfile(profileName, path, domains, configMap)
			if err != nil {
				return fmt.Errorf("failed to add output profile '%s': %w", profileName, err)
			}
		}
	} else {
		outLog.With("action", "config.load").Debug("no outputs configuration found")
	}

	SetGlobalOutputManager(outputManager)
	return nil
}
