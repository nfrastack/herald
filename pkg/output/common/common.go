// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"herald/pkg/log"

	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// expandTags replaces template tags in s with values from domain, profile, etc.
func expandTags(s, domain, profile string) string {
	domainUnderscore := strings.ReplaceAll(domain, ".", "_")
	now := time.Now().Format("20060102-150405") // yyyymmdd-hhmmss
	replacer := strings.NewReplacer(
		"%domain%", domain,
		"%domain_underscore%", domainUnderscore,
		"%date%", now,
		"%profile%", profile,
	)
	return replacer.Replace(s)
}

// Like expandTags, but always replaces %domain% with underscores for filenames
func expandTagsWithUnderscore(s, domain, profile string) string {
	domainUnderscore := strings.ReplaceAll(domain, ".", "_")
	now := time.Now().Format("20060102-150405")
	replacer := strings.NewReplacer(
		"%domain%", domainUnderscore, // always use underscores for %domain%
		"%domain_underscore%", domainUnderscore,
		"%date%", now,
		"%profile%", profile,
	)
	return replacer.Replace(s)
}

// setFileOwnership is a common helper function to set file ownership and permissions
func setFileOwnership(filePath string, config map[string]interface{}, logger *log.ScopedLogger) error {
	if userConfig, ok := config["user"].(string); ok && userConfig != "" {
		var uid int
		var gid int = -1 // Keep existing group by default

		// Look up user
		if u, err := user.Lookup(userConfig); err == nil {
			if parsed, err := strconv.Atoi(u.Uid); err == nil {
				uid = parsed
				if parsed, err := strconv.Atoi(u.Gid); err == nil {
					gid = parsed // Use user's primary group as fallback
				}
			}
		} else {
			logger.Warn("Failed to lookup user '%s': %v", userConfig, err)
		}

		// Override group if specified
		if groupConfig, ok := config["group"].(string); ok && groupConfig != "" {
			if g, err := user.LookupGroup(groupConfig); err == nil {
				if parsed, err := strconv.Atoi(g.Gid); err == nil {
					gid = parsed
				}
			} else {
				logger.Warn("Failed to lookup group '%s': %v", groupConfig, err)
			}
		}

		// Apply ownership
		if err := syscall.Chown(filePath, uid, gid); err != nil {
			logger.Warn("Failed to change ownership of %s: %v", filePath, err)
		}
	}

	// Set file mode if specified
	if modeConfig, ok := config["mode"]; ok {
		var mode os.FileMode
		switch v := modeConfig.(type) {
		case int:
			mode = os.FileMode(v)
		case float64:
			mode = os.FileMode(int(v))
		case string:
			if parsed, err := strconv.ParseUint(v, 8, 32); err == nil {
				mode = os.FileMode(parsed)
			}
		}

		if mode != 0 {
			if err := os.Chmod(filePath, mode); err != nil {
				logger.Warn("Failed to change mode of %s: %v", filePath, err)
			}
		}
	}

	return nil
}

// AddScopedLogging adds scoped logging to any output format provider
func AddScopedLogging(provider interface{}, formatType, name string, options map[string]interface{}) *log.ScopedLogger {
	logLevel := ""
	if val, ok := options["log_level"].(string); ok {
		logLevel = val
	}

	// Normalize domain name for consistent logging (replace dots with underscores)
	normalizedName := strings.ReplaceAll(name, ".", "_")
	logPrefix := fmt.Sprintf("[output/%s/%s]", formatType, normalizedName)
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		scopedLogger.Info("Output format log_level set to: '%s'", logLevel)
	}

	return scopedLogger
}

// CommonFormat provides shared functionality for export formats (JSON, YAML)
type CommonFormat struct {
	profileName string
	config      map[string]interface{}
	path        string
	user        string
	group       string
	mode        os.FileMode
	logPrefix   string
	records     map[string]*BaseRecord // key: domain:hostname:type
	domains     map[string]*BaseDomain
	metadata    *BaseMetadata
	formatName  string            // Track the actual format name
	logger      *log.ScopedLogger // provider-specific logger
	mutex       sync.RWMutex      // Add mutex for thread safety
	realDomain  string            // the real DNS domain for file naming/tag expansion
}

// GetConfig returns the config map
func (c *CommonFormat) GetConfig() map[string]interface{} {
	return c.config
}

// SetDomain sets the real domain for this output (for file path/tag expansion)
func (c *CommonFormat) SetDomain(domain string) {
	c.realDomain = domain
}

// GetDomain returns the real domain if set, otherwise the profileName
func (c *CommonFormat) GetDomain() string {
	if c.realDomain != "" {
		return c.realDomain
	}
	return c.profileName
}

// GetProfile returns the profile name (same as domain for file outputs)
func (c *CommonFormat) GetProfile() string {
	return c.profileName
}

// GetFilePath returns the expanded file path for this output
func (c *CommonFormat) GetFilePath() string {
	path := c.path
	if c.config != nil {
		if p, ok := c.config["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTags(path, c.GetDomain(), c.GetProfile())
}

// GetUser returns the user
func (c *CommonFormat) GetUser() string {
	return c.user
}

// GetGroup returns the group
func (c *CommonFormat) GetGroup() string {
	return c.group
}

// GetMode returns the file mode
func (c *CommonFormat) GetMode() os.FileMode {
	return c.mode
}

// GetLogPrefix returns the log prefix
func (c *CommonFormat) GetLogPrefix() string {
	return c.logPrefix
}

// GetLogger returns the scoped logger for this output
func (c *CommonFormat) GetLogger() *log.ScopedLogger {
	return c.logger
}

// Lock acquires the mutex
func (c *CommonFormat) Lock() {
	c.mutex.Lock()
}

// Unlock releases the mutex
func (c *CommonFormat) Unlock() {
	c.mutex.Unlock()
}

// EnsureDirectory ensures the directory exists
func (c *CommonFormat) EnsureDirectory() error {
	dir := filepath.Dir(c.path)
	return os.MkdirAll(dir, 0755)
}

// EnsureFileAndSetOwnership ensures file exists and sets ownership
func (c *CommonFormat) EnsureFileAndSetOwnership() error {
	if err := c.EnsureDirectory(); err != nil {
		return err
	}

	// Create file if it doesn't exist
	if _, err := os.Stat(c.path); os.IsNotExist(err) {
		if err := os.WriteFile(c.path, []byte{}, c.mode); err != nil {
			return err
		}
	}

	return c.SetFileOwnership()
}

// SetFileOwnership sets file ownership
func (c *CommonFormat) SetFileOwnership() error {
	return setFileOwnership(c.path, c.config, c.logger)
}

// BaseRecord represents a DNS record in export formats
type BaseRecord struct {
	Hostname  string    `json:"hostname" yaml:"hostname"`
	Type      string    `json:"type" yaml:"type"`
	Target    string    `json:"target" yaml:"target"`
	TTL       uint32    `json:"ttl" yaml:"ttl"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	Source    string    `json:"source" yaml:"source"`
}

// BaseDomain represents a domain and its records in export formats
type BaseDomain struct {
	Comment string        `json:"comment,omitempty" yaml:"comment,omitempty"`
	Records []*BaseRecord `json:"records" yaml:"records"`
}

// BaseMetadata represents metadata in export formats
type BaseMetadata struct {
	Generator   string    `json:"generator" yaml:"generator"`
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
}

// ExportData represents the complete export structure
type ExportData struct {
	Metadata *BaseMetadata          `json:"metadata" yaml:"metadata"`
	Domains  map[string]*BaseDomain `json:"domains" yaml:"domains"`
}

// NewCommonFormat creates a new common format instance
func NewCommonFormat(domain, formatName string, config map[string]interface{}) (*CommonFormat, error) {
	path, ok := config["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("output format requires 'path' field")
	}

	// Get file ownership and permissions
	user, _ := config["user"].(string)
	group, _ := config["group"].(string)

	mode := os.FileMode(0644) // default
	if modeInt, ok := config["mode"].(int); ok {
		mode = os.FileMode(modeInt)
	}

	// Get provider-specific log level from config
	logLevel := ""
	if level, ok := config["log_level"].(string); ok {
		logLevel = level
	}

	// Create scoped logger
	logPrefix := fmt.Sprintf("[output/%s/%s]", formatName, strings.ReplaceAll(domain, ".", "_"))
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		scopedLogger.Info("Output format log_level set to: '%s'", logLevel)
	}

	// Set realDomain from config if available
	realDomain := domain
	if d, ok := config["domain"].(string); ok && d != "" {
		realDomain = d
	}

	format := &CommonFormat{
		profileName: domain,
		config:      config,
		path:        path,
		user:        user,
		group:       group,
		mode:        mode,
		logPrefix:   logPrefix,
		records:     make(map[string]*BaseRecord),
		domains:     make(map[string]*BaseDomain),
		metadata:    &BaseMetadata{Generator: "herald"},
		formatName:  formatName,
		logger:      scopedLogger,
		realDomain:  realDomain,
	}

	format.logger.Debug("Initialized %s format: %s", formatName, format.path)

	return format, nil
}

// NormalizeHostname normalizes a hostname relative to a domain
func NormalizeHostname(hostname, domain string) string {
	if hostname == "" || hostname == "@" {
		return "@"
	}
	// Remove domain suffix if present
	suffix := "." + domain
	if strings.HasSuffix(hostname, suffix) {
		hostname = strings.TrimSuffix(hostname, suffix)
	}
	if hostname == "" {
		return "@"
	}
	return hostname
}

// RecordKey creates a unique key for a DNS record
func RecordKey(domain, hostname, recordType string) string {
	return fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)
}

// WriteRecord writes or updates a DNS record
func (c *CommonFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return c.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

// WriteRecordWithSource writes or updates a DNS record with source information
func (c *CommonFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	c.Lock()
	defer c.Unlock()

	// Normalize hostname
	hostname = NormalizeHostname(hostname, domain)
	key := RecordKey(domain, hostname, recordType)

	// Create domain if it doesn't exist
	if _, exists := c.domains[domain]; !exists {
		c.domains[domain] = &BaseDomain{
			Comment: fmt.Sprintf("Domain: %s", domain),
			Records: make([]*BaseRecord, 0),
		}
	}

	// Check if record already exists
	existingRecord := c.records[key]
	if existingRecord != nil {
		// Only log if the target actually changed
		if existingRecord.Target != target {
			oldTarget := existingRecord.Target
			existingRecord.Target = target
			existingRecord.TTL = uint32(ttl)
			existingRecord.Source = source
			c.logger.Info("DNS record target updated: %s.%s (%s) %s -> %s (TTL: %d, source: %s)", hostname, domain, recordType, oldTarget, target, ttl, source)
		} else {
			// Check if TTL changed and log that too
			if existingRecord.TTL != uint32(ttl) {
				oldTTL := existingRecord.TTL
				existingRecord.TTL = uint32(ttl)
				existingRecord.Source = source
				c.logger.Verbose("DNS record TTL updated: %s.%s (%s) %d -> %d (target: %s, source: %s)", hostname, domain, recordType, oldTTL, ttl, target, source)
			} else {
				// Just update metadata without logging
				existingRecord.TTL = uint32(ttl)
				existingRecord.Source = source
			}
		}
	} else {
		// Create new record
		record := &BaseRecord{
			Hostname:  hostname,
			Type:      recordType,
			Target:    target,
			TTL:       uint32(ttl),
			CreatedAt: time.Now().UTC(),
			Source:    source,
		}

		c.records[key] = record
		c.domains[domain].Records = append(c.domains[domain].Records, record)
		c.logger.Verbose("Added record: %s.%s (%s) -> %s", hostname, domain, recordType, target)
	}

	// Update metadata
	c.metadata.LastUpdated = time.Now().UTC()

	// --- DEBUG: Log the current state of domains and records ---
	domainRecords := make(map[string]int)
	for d, dom := range c.domains {
		if dom != nil {
			domainRecords[d] = len(dom.Records)
		}
	}
	c.logger.Debug("[DEBUG] After WriteRecordWithSource: domains=%v", domainRecords)
	// --- END DEBUG ---

	return nil
}

// RemoveRecord removes a DNS record
func (c *CommonFormat) RemoveRecord(domain, hostname, recordType string) error {
	c.Lock()
	defer c.Unlock()

	// Normalize hostname
	hostname = NormalizeHostname(hostname, domain)
	key := RecordKey(domain, hostname, recordType)

	// Remove from records map
	if record, exists := c.records[key]; exists {
		delete(c.records, key)

		// Remove from domain records slice
		if domainData, domainExists := c.domains[domain]; domainExists {
			for i, r := range domainData.Records {
				if r == record {
					// Remove from slice
					domainData.Records = append(domainData.Records[:i], domainData.Records[i+1:]...)
					break
				}
			}

			// Remove domain if no records left
			if len(domainData.Records) == 0 {
				delete(c.domains, domain)
			}
		}

		c.logger.Verbose("Removed record: %s.%s (%s)", hostname, domain, recordType)
		c.metadata.LastUpdated = time.Now().UTC()
	}

	return nil
}

// GetExportData returns the export structure for serialization
func (c *CommonFormat) GetExportData() *ExportData {
	// Set generated_at if not already set (new file)
	if c.metadata.GeneratedAt.IsZero() {
		c.metadata.GeneratedAt = time.Now().UTC()
	}

	// Always update the last updated time
	c.metadata.LastUpdated = time.Now().UTC()

	return &ExportData{
		Metadata: c.metadata,
		Domains:  c.domains,
	}
}

// LoadExistingData loads existing export data to preserve metadata
func (c *CommonFormat) LoadExistingData(unmarshalFunc func([]byte, interface{}) error) error {
	if _, err := os.Stat(c.GetFilePath()); os.IsNotExist(err) {
		return nil // File doesn't exist, that's okay
	}

	log.Trace("%s fsnotify event: Name='%s', Op=READ", c.GetLogPrefix(), c.GetFilePath())
	data, err := os.ReadFile(c.GetFilePath())
	if err != nil {
		return err
	}

	var export ExportData
	if err := unmarshalFunc(data, &export); err != nil {
		return err
	}

	// Preserve existing metadata
	if export.Metadata != nil {
		c.metadata = export.Metadata
		c.logger.Trace("Preserved existing metadata from file")
	}

	// Load existing records (but they will be overwritten by current state)
	if export.Domains != nil {
		for domain, domainData := range export.Domains {
			c.domains[domain] = domainData
			for _, record := range domainData.Records {
				key := RecordKey(domain, record.Hostname, record.Type)
				c.records[key] = record
			}
		}
	}

	return nil
}

// SyncWithSerializer writes data using the provided serialization function
func (c *CommonFormat) SyncWithSerializer(serializeFunc func(domain string, export *ExportData) ([]byte, error), fallbackDomain ...string) error {
	c.Lock()
	defer func() {
		c.Unlock()
		log.Debug("%s Released lock", c.GetLogPrefix())
	}()

	log.Debug("%s Starting file sync", c.GetLogPrefix())

	// Create directory if it doesn't exist
	if err := c.EnsureDirectory(); err != nil {
		log.Error("%s Failed to create directory: %v", c.GetLogPrefix(), err)
		return err
	}

	export := c.GetExportData()
	if export.Domains == nil || len(export.Domains) == 0 {
		log.Warn("%s  No domains to export, calling serializer with empty export", c.GetLogPrefix())
		// Use fallbackDomain for tag expansion and serializer domain argument
		var domain string
		if len(fallbackDomain) > 0 && fallbackDomain[0] != "" {
			domain = fallbackDomain[0]
		} else {
			domain = c.GetDomain()
		}
		data, err := serializeFunc(domain, export)
		if err != nil {
			log.Error("%s Failed to serialize empty export: %v", c.GetLogPrefix(), err)
			return fmt.Errorf("failed to serialize empty export: %v", err)
		}
		path := c.path
		if c.config != nil {
			if p, ok := c.config["path"].(string); ok && p != "" {
				path = p
			}
		}
		// PATCH: Use expandTagsWithUnderscore for all file outputs to normalize %domain% in filenames
		filename := path
		if strings.Contains(path, "%domain%") || strings.Contains(path, "%domain_underscore%") {
			filename = expandTagsWithUnderscore(path, domain, c.GetProfile())
		}
		if err := os.WriteFile(filename, data, 0644); err != nil {
			log.Error("%s Failed to write file for empty export: %v", c.GetLogPrefix(), err)
			return fmt.Errorf("failed to write file for empty export: %v", err)
		}
		c.logger.Debug("fsnotify event: Name='%s', Op=WRITE", filename)
		if err := setFileOwnership(filename, c.config, c.logger); err != nil {
			log.Warn("%s Failed to set file ownership for %s: %v", c.GetLogPrefix(), filename, err)
		}
		log.Debug("%s Empty export file written successfully", c.GetLogPrefix())
		return nil
	}

	for domain := range export.Domains {
		// Tag expansion for filename uses domain with underscores ONLY
		path := c.path
		if c.config != nil {
			if p, ok := c.config["path"].(string); ok && p != "" {
				path = p
			}
		}
		// Enforce: replace any %domain% in the path with %domain_underscore%
		path = strings.ReplaceAll(path, "%domain%", "%domain_underscore%")
		filename := expandTags(path, domain, c.GetProfile())

		// Serialize data for this domain only
		perDomainExport := &ExportData{
			Metadata: export.Metadata,
			Domains:  map[string]*BaseDomain{domain: export.Domains[domain]},
		}
		data, err := serializeFunc(domain, perDomainExport)
		if err != nil {
			log.Error("%s Failed to serialize data for domain %s: %v", c.GetLogPrefix(), domain, err)
			return fmt.Errorf("failed to serialize data for domain %s: %v", domain, err)
		}

		// --- PATCH: Log the data being written for debug ---
		c.logger.Debug("[DEBUG] Writing to zone file: %s\n---\n%s\n---", filename, string(data))
		// --- END PATCH ---

		if err := os.WriteFile(filename, data, 0644); err != nil {
			log.Error("%s Failed to write file for domain %s: %v", c.GetLogPrefix(), domain, err)
			return fmt.Errorf("failed to write file for domain %s: %v", domain, err)
		}
		c.logger.Debug("fsnotify event: Name='%s', Op=WRITE", filename)

		if err := setFileOwnership(filename, c.config, c.logger); err != nil {
			log.Warn("%s Failed to set file ownership for %s: %v", c.GetLogPrefix(), filename, err)
		}
	}
	log.Debug("%s All files written successfully", c.GetLogPrefix())
	return nil
}
