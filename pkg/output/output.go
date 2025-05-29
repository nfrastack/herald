// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package output

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/utils"

	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OutputFormat defines the interface that all output formats must implement
type OutputFormat interface {
	GetName() string
	WriteRecord(domain, hostname, target, recordType string, ttl int) error
	WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error
	RemoveRecord(domain, hostname, recordType string) error
	Sync() error
}

// FormatConstructor is a function that creates a new format instance
type FormatConstructor func(domain string, config map[string]interface{}) (OutputFormat, error)

// formatRegistry holds all registered output formats
var formatRegistry = make(map[string]FormatConstructor)

// RegisterFormat registers a new output format
func RegisterFormat(name string, constructor FormatConstructor) {
	formatRegistry[name] = constructor
}

// GetFormat creates a new instance of the specified format
func GetFormat(name, domain string, config map[string]interface{}) (OutputFormat, error) {
	constructor, exists := formatRegistry[name]
	if !exists {
		availableFormats := make([]string, 0, len(formatRegistry))
		for formatName := range formatRegistry {
			availableFormats = append(availableFormats, formatName)
		}
		return nil, fmt.Errorf("unknown output format '%s'. Available formats: %v", name, availableFormats)
	}
	return constructor(domain, config)
}

// GetAvailableFormats returns a list of all registered format names
func GetAvailableFormats() []string {
	formats := make([]string, 0, len(formatRegistry))
	for name := range formatRegistry {
		formats = append(formats, name)
	}
	return formats
}

// BaseFormat provides common functionality for all output formats
type BaseFormat struct {
	filePath           string
	user               string
	group              string
	mode               os.FileMode
	mutex              sync.RWMutex
	logPrefix          string
	permissionsApplied bool // Track if we've applied permissions on startup
}

// BaseConfig holds common configuration for output formats
type BaseConfig struct {
	Path  string `yaml:"path" json:"path"`
	User  string `yaml:"user" json:"user"`
	Group string `yaml:"group" json:"group"`
	Mode  int    `yaml:"mode" json:"mode"`
}

// NewBaseFormat creates a new base format with common configuration
func NewBaseFormat(domain, formatName string, config map[string]interface{}) (*BaseFormat, BaseConfig, error) {
	baseConfig := BaseConfig{
		Mode: 0644, // Default permissions (octal)
	}

	// Parse common configuration
	if path, ok := config["path"].(string); ok {
		baseConfig.Path = path
	}
	if user, ok := config["user"].(string); ok {
		baseConfig.User = user
	}
	if group, ok := config["group"].(string); ok {
		baseConfig.Group = group
	}
	if mode, ok := config["mode"].(int); ok {
		baseConfig.Mode = mode
	}

	if baseConfig.Path == "" {
		return nil, baseConfig, fmt.Errorf("path is required for %s format", formatName)
	}

	profileName := getProfileName(domain, formatName)

	bf := &BaseFormat{
		filePath:  baseConfig.Path,
		user:      baseConfig.User,
		group:     baseConfig.Group,
		mode:      os.FileMode(baseConfig.Mode),
		logPrefix: fmt.Sprintf("[output/%s/%s]", formatName, profileName),
	}

	return bf, baseConfig, nil
}

// getProfileName generates a profile name from domain and format
func getProfileName(domain, formatName string) string {
	// Convert domain to a safe profile name (replace dots with underscores)
	profileName := strings.ReplaceAll(domain, ".", "_") + "_" + formatName
	return profileName
}

// GetFilePath returns the file path
func (bf *BaseFormat) GetFilePath() string {
	return bf.filePath
}

// GetLogPrefix returns the log prefix for this format
func (bf *BaseFormat) GetLogPrefix() string {
	return bf.logPrefix
}

// GetUser returns the configured user
func (bf *BaseFormat) GetUser() string {
	return bf.user
}

// GetGroup returns the configured group
func (bf *BaseFormat) GetGroup() string {
	return bf.group
}

// GetMode returns the configured file mode
func (bf *BaseFormat) GetMode() os.FileMode {
	return bf.mode
}

// Lock acquires a write lock
func (bf *BaseFormat) Lock() {
	bf.mutex.Lock()
}

// Unlock releases a write lock
func (bf *BaseFormat) Unlock() {
	bf.mutex.Unlock()
}

// RLock acquires a read lock
func (bf *BaseFormat) RLock() {
	bf.mutex.RLock()
}

// RUnlock releases a read lock
func (bf *BaseFormat) RUnlock() {
	bf.mutex.RUnlock()
}

// EnsureFileAndSetOwnership creates the file and sets ownership if needed (exported version)
func (bf *BaseFormat) EnsureFileAndSetOwnership() error {
	return bf.ensureFileAndSetOwnership()
}

// EnsureDirectory ensures the directory exists
func (bf *BaseFormat) EnsureDirectory() error {
	dir := filepath.Dir(bf.filePath)
	return os.MkdirAll(dir, 0755)
}

// SetFileOwnership sets the file ownership and permissions (exported version)
func (bf *BaseFormat) SetFileOwnership() error {
	return bf.setFileOwnership()
}

// ensureFileAndSetOwnership creates the file and sets ownership if needed (only called on startup)
func (bf *BaseFormat) ensureFileAndSetOwnership() error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(bf.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Check if file exists before creating
	if _, err := os.Stat(bf.filePath); os.IsNotExist(err) {
		// Create with default permissions
		if err := os.WriteFile(bf.filePath, []byte{}, 0644); err != nil {
			return fmt.Errorf("failed to create file: %v", err)
		}
		log.Trace("%s fsnotify event: Name='%s', Op=CREATE", bf.GetLogPrefix(), bf.filePath)
	}

	// Only set ownership/permissions on startup if explicitly configured
	// (mode != 0644 means it was explicitly set to something other than default)
	if (bf.user != "" || bf.group != "" || bf.mode != 0644) && !bf.permissionsApplied {
		return bf.setFileOwnership()
	}

	return nil
}

// setFileOwnership sets the file ownership and permissions (only called once on startup if configured)
func (bf *BaseFormat) setFileOwnership() error {
	// Skip if we've already applied permissions on startup
	if bf.permissionsApplied {
		return nil
	}

	// Apply ownership if user/group is specified
	if bf.user != "" || bf.group != "" {
		if err := utils.SetFileOwnership(bf.filePath, bf.user, bf.group, bf.mode); err != nil {
			return fmt.Errorf("failed to set file ownership: %v", err)
		}
		log.Trace("%s fsnotify event: Name='%s', Op=CHOWN", bf.GetLogPrefix(), bf.filePath)
	} else if bf.mode != 0644 {
		// Apply permissions only if mode is explicitly specified and different from default
		if err := os.Chmod(bf.filePath, bf.mode); err != nil {
			return fmt.Errorf("failed to set file permissions: %v", err)
		}
		log.Trace("%s fsnotify event: Name='%s', Op=CHMOD", bf.GetLogPrefix(), bf.filePath)
	}

	// Mark that we've applied permissions - never touch them again
	bf.permissionsApplied = true
	return nil
}

// CreateScopedLogger creates a scoped logger for output providers using common logic
func CreateScopedLogger(providerType, profileName string, options map[string]interface{}) *log.ScopedLogger {
	logLevel := ""
	if val, ok := options["log_level"].(string); ok {
		logLevel = val
	}

	logPrefix := fmt.Sprintf("[output/%s/%s]", providerType, profileName)
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		scopedLogger.Info("Output provider log_level set to: '%s'", logLevel)
	}

	return scopedLogger
}

// OutputProfile defines a complete output configuration profile
type OutputProfile struct {
	Name      string
	Format    string
	Path      string
	Domains   []string
	Config    map[string]interface{}
	providers map[string]OutputFormat // domain -> provider
}

// OutputManager manages all output profiles and domain targeting
type OutputManager struct {
	profiles   map[string]*OutputProfile
	domainData map[string]map[string]*DNSRecord // domain -> hostname:type -> record
	mutex      sync.RWMutex
}

// DNSRecord represents a DNS record for output processing
type DNSRecord struct {
	Domain     string
	Hostname   string
	Target     string
	RecordType string
	TTL        int
}

var globalOutputManager *OutputManager

// NewOutputManager creates a new output manager
func NewOutputManager() *OutputManager {
	return &OutputManager{
		profiles:   make(map[string]*OutputProfile),
		domainData: make(map[string]map[string]*DNSRecord),
	}
}

// SetGlobalOutputManager sets the global output manager instance
func SetGlobalOutputManager(mgr *OutputManager) {
	globalOutputManager = mgr
}

// GetOutputManager returns the global output manager instance
func GetOutputManager() *OutputManager {
	return globalOutputManager
}

// AddProfile adds a new output profile
func (om *OutputManager) AddProfile(name string, format string, path string, domains []string, config map[string]interface{}) error {
	om.mutex.Lock()
	defer om.mutex.Unlock()

	// Validate that the format exists before registering the profile
	if _, exists := formatRegistry[format]; !exists {
		availableFormats := GetAvailableFormats()
		return fmt.Errorf("unknown output format '%s' for profile '%s'. Available formats: %v", format, name, availableFormats)
	}

	// Handle domain targeting logic
	if len(domains) == 0 {
		// Default to ALL domains if none specified
		domains = []string{"ALL"}
		log.Info("[output/%s] No domains specified, defaulting to ALL domains", name)
	} else {
		// Normalize domain aliases to "ALL"
		normalizedDomains := make([]string, 0, len(domains))
		for _, domain := range domains {
			switch strings.ToLower(domain) {
			case "all", "any", "*":
				normalizedDomains = append(normalizedDomains, "ALL")
				if domain != "ALL" {
					log.Info("[output/%s] Domain alias '%s' normalized to 'ALL'", name, domain)
				}
			default:
				normalizedDomains = append(normalizedDomains, domain)
			}
		}
		domains = normalizedDomains
	}

	profile := &OutputProfile{
		Name:      name,
		Format:    format,
		Path:      path,
		Domains:   domains,
		Config:    config,
		providers: make(map[string]OutputFormat),
	}

	// Validate zonefile multi-domain constraint
	if format == "zonefile" && (len(domains) > 1 || (len(domains) == 1 && domains[0] == "ALL")) && !strings.Contains(path, "%domain%") {
		return fmt.Errorf("zonefile format with multiple domains requires %%domain%% template in path")
	}
	// Additional validation for zone format
	if format == "zone" && (len(domains) > 1 || (len(domains) == 1 && domains[0] == "ALL")) && !strings.Contains(path, "%domain%") {
		return fmt.Errorf("zone format with multiple domains requires %%domain%% template in path")
	}

	om.profiles[name] = profile
	return nil
}

// WriteRecord writes a record for a domain and updates all matching profiles
func (om *OutputManager) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return om.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "dns-companion")
}

// WriteRecordWithSource writes a record with source information for a domain and updates all matching profiles
func (om *OutputManager) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	om.mutex.Lock()
	defer om.mutex.Unlock()
	if om.domainData[domain] == nil {
		om.domainData[domain] = make(map[string]*DNSRecord)
	}
	key := fmt.Sprintf("%s:%s", hostname, recordType)
	om.domainData[domain][key] = &DNSRecord{
		Domain:     domain,
		Hostname:   hostname,
		Target:     target,
		RecordType: recordType,
		TTL:        ttl,
	}
	for _, profile := range om.profiles {
		if om.shouldIncludeDomain(profile, domain) {
			provider, err := om.getProviderForDomain(profile, domain)
			if err != nil {
				log.Error("[output/%s] Failed to get provider for domain '%s': %v", profile.Name, domain, err)
				continue
			}
			if err := provider.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source); err != nil {
				log.Error("[output/%s] Failed to write record: %v", profile.Name, err)
				continue
			}
		}
	}
	return nil
}

// RemoveRecord removes a record for a domain and updates all matching profiles
func (om *OutputManager) RemoveRecord(domain, hostname, recordType string) error {
	om.mutex.Lock()
	defer om.mutex.Unlock()

	// Don't log at the manager level - let each provider log its own removals

	if om.domainData[domain] != nil {
		key := fmt.Sprintf("%s:%s", hostname, recordType)
		delete(om.domainData[domain], key)
		if len(om.domainData[domain]) == 0 {
			delete(om.domainData, domain)
		}
	}
	for _, profile := range om.profiles {
		if om.shouldIncludeDomain(profile, domain) {
			if provider, exists := profile.providers[domain]; exists {
				if err := provider.RemoveRecord(domain, hostname, recordType); err != nil {
					log.Error("[output/%s] Failed to remove record: %v", profile.Name, err)
					continue
				}
			}
		}
	}
	return nil
}

// SyncAll synchronizes all output profiles
func (om *OutputManager) SyncAll() error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	// Add a small debug trace to track duplicate calls
	log.Trace("[output] SyncAll() called - checking %d profiles", len(om.profiles))

	var errors []string
	syncedPaths := make(map[string]bool) // Track file paths to avoid duplicate syncs

	for name, profile := range om.profiles {
		for domain, provider := range profile.providers {
			// Use the provider's file path as unique identifier
			providerPath := ""
			if baseProvider, ok := provider.(interface{ GetFilePath() string }); ok {
				providerPath = baseProvider.GetFilePath()
			} else {
				// Fallback to old method if GetFilePath not available
				providerPath = fmt.Sprintf("%s:%s:%s", profile.Format, name, domain)
			}

			// Skip if we've already synced this file path
			if syncedPaths[providerPath] {
				log.Trace("[output] Skipping already synced provider: %s", providerPath)
				continue
			}

			if err := provider.Sync(); err != nil {
				errMsg := fmt.Sprintf("profile '%s' domain '%s': %v", name, domain, err)
				errors = append(errors, errMsg)
				log.Error("[output/%s] Sync failed: %v", name, err)
			} else {
				syncedPaths[providerPath] = true
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("sync failed for %d providers: %s", len(errors), strings.Join(errors, "; "))
	}
	return nil
}

// shouldIncludeDomain checks if a domain should be included in a profile
func (om *OutputManager) shouldIncludeDomain(profile *OutputProfile, domain string) bool {
	for _, targetDomain := range profile.Domains {
		if targetDomain == "ALL" || targetDomain == domain {
			return true
		}
	}
	return false
}

// getProviderForDomain gets or creates a provider for the specific domain
func (om *OutputManager) getProviderForDomain(profile *OutputProfile, domain string) (OutputFormat, error) {
	if provider, exists := profile.providers[domain]; exists {
		return provider, nil
	}
	actualPath := om.templatePath(profile.Path, domain, profile.Name)
	providerConfig := make(map[string]interface{})
	for k, v := range profile.Config {
		providerConfig[k] = v
	}
	providerConfig["path"] = actualPath
	providerConfig["profile_name"] = profile.Name // Add profile name for logging
	provider, err := GetFormat(profile.Format, domain, providerConfig)
	if err != nil {
		// Don't log here - let the caller handle it with proper context
		return nil, fmt.Errorf("failed to create provider for domain '%s': %v", domain, err)
	}
	profile.providers[domain] = provider
	return provider, nil
}

// templatePath applies templates to the path
func (om *OutputManager) templatePath(pathTemplate, domain, profileName string) string {
	result := pathTemplate
	safeDomain := strings.ReplaceAll(domain, ".", "_")
	result = strings.ReplaceAll(result, "%domain%", safeDomain)
	result = strings.ReplaceAll(result, "%profile%", profileName)
	now := time.Now()
	result = strings.ReplaceAll(result, "%date%", now.Format("2006-01-02"))
	result = strings.ReplaceAll(result, "%datetime%", now.Format("2006-01-02_15-04-05"))
	result = strings.ReplaceAll(result, "%timestamp%", fmt.Sprintf("%d", now.Unix()))
	envRegex := regexp.MustCompile(`%env:([A-Z_][A-Z0-9_]*)%`)
	result = envRegex.ReplaceAllStringFunc(result, func(match string) string {
		envVar := envRegex.FindStringSubmatch(match)[1]
		if value := os.Getenv(envVar); value != "" {
			return value
		}
		return match
	})
	return result
}

// GetProfiles returns all configured profiles
func (om *OutputManager) GetProfiles() map[string]*OutputProfile {
	om.mutex.RLock()
	defer om.mutex.RUnlock()
	return om.profiles
}

// GetDomains returns all domains that have records
func (om *OutputManager) GetDomains() []string {
	om.mutex.RLock()
	defer om.mutex.RUnlock()
	domains := make([]string, 0, len(om.domainData))
	for domain := range om.domainData {
		domains = append(domains, domain)
	}
	return domains
}

// InitializeOutputManager initializes the output manager with profiles from config
func InitializeOutputManager(outputsConfig map[string]interface{}) error {
	manager := NewOutputManager()

	if outputsConfig == nil {
		log.Debug("[output] No outputs section in configuration")
		SetGlobalOutputManager(manager)
		return nil
	}

	// Treat everything under outputs as profile names directly
	log.Debug("[config/output] Found %d output profiles", len(outputsConfig))
	for profileName, profileConfigRaw := range outputsConfig {
		log.Debug("[config/output] Processing profile: %s", profileName)

		profileConfig, ok := profileConfigRaw.(map[string]interface{})
		if !ok {
			log.Warn("[config/output] Skipping invalid profile config for '%s'", profileName)
			continue
		}

		// Extract required fields
		format, _ := profileConfig["format"].(string)
		path, _ := profileConfig["path"].(string)

		if format == "" {
			log.Warn("[config/output] Skipping profile '%s': format is required", profileName)
			continue
		}
		if path == "" {
			log.Warn("[config/output] Skipping profile '%s': path is required", profileName)
			continue
		}

		// Parse domains
		var domains []string
		if domainsRaw, exists := profileConfig["domains"]; exists {
			switch v := domainsRaw.(type) {
			case string:
				domains = []string{v}
			case []interface{}:
				for _, d := range v {
					if ds, ok := d.(string); ok {
						domains = append(domains, ds)
					}
				}
			case []string:
				domains = v
			default:
				log.Warn("[config/output] Invalid domains format for profile '%s', defaulting to ALL", profileName)
				domains = []string{}
			}
		}

		// Create config map excluding the known top-level keys
		config := make(map[string]interface{})
		for k, v := range profileConfig {
			if k != "format" && k != "path" && k != "domains" {
				config[k] = v
			}
		}

		// Add the profile to the manager
		if err := manager.AddProfile(profileName, format, path, domains, config); err != nil {
			log.Error("[config/output] Failed to register profile '%s': %v", profileName, err)
			return fmt.Errorf("failed to register output profile '%s': %v", profileName, err)
		}

		log.Verbose("[output] Registered output profile '%s' (%s)", profileName, format)
	}

	SetGlobalOutputManager(manager)
	return nil
}
