// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"github.com/nfrastack/herald/internal/log"

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

func setFileOwnership(filePath string, config map[string]interface{}, logger *log.ScopedLogger) error {
	if userConfig, ok := config["user"].(string); ok && userConfig != "" {
		var uid int
		var gid int = -1 // Keep existing group by default

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

		if groupConfig, ok := config["group"].(string); ok && groupConfig != "" {
			if g, err := user.LookupGroup(groupConfig); err == nil {
				if parsed, err := strconv.Atoi(g.Gid); err == nil {
					gid = parsed
				}
			} else {
				logger.Warn("Failed to lookup group '%s': %v", groupConfig, err)
			}
		}

		if err := syscall.Chown(filePath, uid, gid); err != nil {
			logger.Warn("Failed to change ownership of %s: %v", filePath, err)
		}
	}

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

func AddScopedLogging(provider interface{}, formatType, name string, options map[string]interface{}) *log.ScopedLogger {
	logLevel := ""
	if val, ok := options["log_level"].(string); ok {
		logLevel = val
	}

	normalizedName := strings.ReplaceAll(name, ".", "_")
	logPrefix := fmt.Sprintf("[output/%s/%s]", formatType, normalizedName)
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		scopedLogger.Info("Output format log_level set to: '%s'", logLevel)
	}

	return scopedLogger
}

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

func (c *CommonFormat) GetConfig() map[string]interface{} {
	return c.config
}

func (c *CommonFormat) SetDomain(domain string) {
	c.realDomain = domain
}

func (c *CommonFormat) GetDomain() string {
	if c.realDomain != "" {
		return c.realDomain
	}
	return c.profileName
}

func (c *CommonFormat) GetProfile() string {
	return c.profileName
}

func (c *CommonFormat) GetFilePath() string {
	path := c.path
	if c.config != nil {
		if p, ok := c.config["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTags(path, c.GetDomain(), c.GetProfile())
}

func (c *CommonFormat) GetUser() string {
	return c.user
}

func (c *CommonFormat) GetGroup() string {
	return c.group
}

func (c *CommonFormat) GetMode() os.FileMode {
	return c.mode
}

func (c *CommonFormat) GetLogPrefix() string {
	return c.logPrefix
}

func (c *CommonFormat) GetLogger() *log.ScopedLogger {
	return c.logger
}

func (c *CommonFormat) Lock() {
	c.mutex.Lock()
}

func (c *CommonFormat) Unlock() {
	c.mutex.Unlock()
}

func (c *CommonFormat) EnsureDirectory() error {
	dir := filepath.Dir(c.path)
	return os.MkdirAll(dir, 0755)
}

func (c *CommonFormat) EnsureFileAndSetOwnership() error {
	if err := c.EnsureDirectory(); err != nil {
		return err
	}

	if _, err := os.Stat(c.path); os.IsNotExist(err) {
		if err := os.WriteFile(c.path, []byte{}, c.mode); err != nil {
			return err
		}
	}

	return c.SetFileOwnership()
}

func (c *CommonFormat) SetFileOwnership() error {
	return setFileOwnership(c.path, c.config, c.logger)
}

type BaseRecord struct {
	Hostname  string    `json:"hostname" yaml:"hostname"`
	Type      string    `json:"type" yaml:"type"`
	Target    string    `json:"target" yaml:"target"`
	TTL       uint32    `json:"ttl" yaml:"ttl"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	Source    string    `json:"source" yaml:"source"`
	Comment   string    `json:"comment,omitempty" yaml:"comment,omitempty"`
}

type BaseDomain struct {
	Comment string        `json:"comment,omitempty" yaml:"comment,omitempty"`
	Records []*BaseRecord `json:"records" yaml:"records"`
}

type BaseMetadata struct {
	Generator   string    `json:"generator" yaml:"generator"`
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
}

type ExportData struct {
	Metadata *BaseMetadata          `json:"metadata" yaml:"metadata"`
	Domains  map[string]*BaseDomain `json:"domains" yaml:"domains"`
}

func NewCommonFormat(domain, formatName string, config map[string]interface{}) (*CommonFormat, error) {
	path, ok := config["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("output format requires 'path' field")
	}

	user, _ := config["user"].(string)
	group, _ := config["group"].(string)

	mode := os.FileMode(0644) // default
	if modeInt, ok := config["mode"].(int); ok {
		mode = os.FileMode(modeInt)
	}

	logLevel := ""
	if level, ok := config["log_level"].(string); ok {
		logLevel = level
	}

	logPrefix := fmt.Sprintf("[output/%s/%s]", formatName, strings.ReplaceAll(domain, ".", "_"))
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		scopedLogger.Info("Output format log_level set to: '%s'", logLevel)
	}

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

func NormalizeHostname(hostname, domain string) string {
	if hostname == "" || hostname == "@" {
		return "@"
	}
	suffix := "." + domain
	if strings.HasSuffix(hostname, suffix) {
		hostname = strings.TrimSuffix(hostname, suffix)
	}
	if hostname == "" {
		return "@"
	}
	return hostname
}

func RecordKey(domain, hostname, recordType string) string {
	return fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)
}

func (c *CommonFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return c.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

func (c *CommonFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	c.Lock()
	defer c.Unlock()

	hostname = NormalizeHostname(hostname, domain)
	key := RecordKey(domain, hostname, recordType)

	if _, exists := c.domains[domain]; !exists {
		c.domains[domain] = &BaseDomain{
			Comment: fmt.Sprintf("Domain: %s", domain),
			Records: make([]*BaseRecord, 0),
		}
	}

	existingRecord := c.records[key]
	if existingRecord != nil {
		if existingRecord.Target != target {
			oldTarget := existingRecord.Target
			existingRecord.Target = target
			existingRecord.TTL = uint32(ttl)
			existingRecord.Source = source
			c.logger.Info("DNS record target updated: %s.%s (%s) %s -> %s (TTL: %d, source: %s)", hostname, domain, recordType, oldTarget, target, ttl, source)
		} else {
			if existingRecord.TTL != uint32(ttl) {
				oldTTL := existingRecord.TTL
				existingRecord.TTL = uint32(ttl)
				existingRecord.Source = source
				c.logger.Verbose("DNS record TTL updated: %s.%s (%s) %d -> %d (target: %s, source: %s)", hostname, domain, recordType, oldTTL, ttl, target, source)
			} else {
				existingRecord.TTL = uint32(ttl)
				existingRecord.Source = source
			}
		}
	} else {
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

	c.metadata.LastUpdated = time.Now().UTC()
	return nil
}

func (c *CommonFormat) RemoveRecord(domain, hostname, recordType string) error {
	c.Lock()
	defer c.Unlock()

	hostname = NormalizeHostname(hostname, domain)
	key := RecordKey(domain, hostname, recordType)

	if record, exists := c.records[key]; exists {
		delete(c.records, key)

		if domainData, domainExists := c.domains[domain]; domainExists {
			for i, r := range domainData.Records {
				if r == record {
					domainData.Records = append(domainData.Records[:i], domainData.Records[i+1:]...)
					break
				}
			}

			if len(domainData.Records) == 0 {
				delete(c.domains, domain)
			}
		}

		c.logger.Verbose("Removed record: %s.%s (%s)", hostname, domain, recordType)
		c.metadata.LastUpdated = time.Now().UTC()
	}

	return nil
}

func (c *CommonFormat) GetExportData() *ExportData {
	if c.metadata.GeneratedAt.IsZero() {
		c.metadata.GeneratedAt = time.Now().UTC()
	}

	c.metadata.LastUpdated = time.Now().UTC()

	return &ExportData{
		Metadata: c.metadata,
		Domains:  c.domains,
	}
}

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

	if export.Metadata != nil {
		c.metadata = export.Metadata
		c.logger.Trace("Preserved existing metadata from file")
	}

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

func (c *CommonFormat) SyncWithSerializer(serializeFunc func(domain string, export *ExportData) ([]byte, error), fallbackDomain ...string) error {
	c.Lock()
	defer func() {
		c.Unlock()
		log.Debug("%s Released lock", c.GetLogPrefix())
	}()

	log.Debug("%s Starting file sync", c.GetLogPrefix())

	if err := c.EnsureDirectory(); err != nil {
		log.Error("%s Failed to create directory: %v", c.GetLogPrefix(), err)
		return err
	}

	export := c.GetExportData()
	if export.Domains == nil || len(export.Domains) == 0 {
		log.Warn("%s  No domains to export, calling serializer with empty export", c.GetLogPrefix())
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
		path := c.path
		if c.config != nil {
			if p, ok := c.config["path"].(string); ok && p != "" {
				path = p
			}
		}
		path = strings.ReplaceAll(path, "%domain%", "%domain_underscore%")
		filename := expandTags(path, domain, c.GetProfile())

		perDomainExport := &ExportData{
			Metadata: export.Metadata,
			Domains:  map[string]*BaseDomain{domain: export.Domains[domain]},
		}
		data, err := serializeFunc(domain, perDomainExport)
		if err != nil {
			log.Error("%s Failed to serialize data for domain %s: %v", c.GetLogPrefix(), domain, err)
			return fmt.Errorf("failed to serialize data for domain %s: %v", domain, err)
		}

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
