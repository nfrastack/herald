// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package outputCommon

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"

	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// setFileOwnership is a common helper function to set file ownership and permissions
func setFileOwnership(filePath string, config map[string]interface{}, logger *log.ScopedLogger) error {
	// Set file ownership if specified
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
	*output.BaseFormat
	records    map[string]*BaseRecord // key: domain:hostname:type
	domains    map[string]*BaseDomain
	metadata   *BaseMetadata
	formatName string            // Track the actual format name
	logger     *log.ScopedLogger // provider-specific logger
}

// NewCommonFormat creates a new common format instance
func NewCommonFormat(domain, formatName string, config map[string]interface{}) (*CommonFormat, error) {
	base, _, err := output.NewBaseFormat(domain, formatName, config)
	if err != nil {
		return nil, err
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
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	format := &CommonFormat{
		BaseFormat: base,
		records:    make(map[string]*BaseRecord),
		domains:    make(map[string]*BaseDomain),
		metadata:   &BaseMetadata{Generator: "dns-companion"},
		formatName: formatName,
		logger:     scopedLogger,
	}

	format.logger.Debug("Initialized %s format: %s", formatName, format.GetFilePath())

	// Only ensure file and set ownership if permissions are explicitly configured (non-default)
	if format.GetUser() != "" || format.GetGroup() != "" || format.GetMode() != 0644 {
		if err := format.EnsureFileAndSetOwnership(); err != nil {
			log.Warn("%s Failed to ensure file and set ownership: %v", format.GetLogPrefix(), err)
		}
	} else {
		// Just ensure directory exists for default permissions - don't create/chmod the file
		if err := format.EnsureDirectory(); err != nil {
			log.Warn("%s Failed to ensure directory: %v", format.GetLogPrefix(), err)
		}
	}

	return format, nil
}

// WriteRecord writes or updates a DNS record
func (c *CommonFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return c.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "dns-companion")
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
func (c *CommonFormat) SyncWithSerializer(serializeFunc func(*ExportData) ([]byte, error)) error {
	c.Lock()
	defer c.Unlock()

	// Create directory if it doesn't exist
	if err := c.EnsureDirectory(); err != nil {
		log.Error("%s Failed to create directory: %v", c.GetLogPrefix(), err)
		return err
	}

	// Get export data
	export := c.GetExportData()

	// Serialize data
	data, err := serializeFunc(export)
	if err != nil {
		log.Error("%s Failed to serialize data: %v", c.GetLogPrefix(), err)
		return fmt.Errorf("failed to serialize data: %v", err)
	}

	// Write to file
	if err := os.WriteFile(c.GetFilePath(), data, 0644); err != nil {
		log.Error("%s Failed to write file: %v", c.GetLogPrefix(), err)
		return fmt.Errorf("failed to write file: %v", err)
	}
	c.logger.Trace("fsnotify event: Name='%s', Op=WRITE", c.GetFilePath())

	// Set file ownership if specified
	if err := c.SetFileOwnership(); err != nil {
		log.Warn("%s Failed to set file ownership: %v", c.GetLogPrefix(), err)
	}

	// Remove old verbose logging - let individual formats handle their own logging
	return nil
}

// GetName returns the format name
func (c *CommonFormat) GetName() string {
	return c.formatName
}

// GetRecordCount returns the number of records currently stored
func (c *CommonFormat) GetRecordCount() int {
	return len(c.records)
}
