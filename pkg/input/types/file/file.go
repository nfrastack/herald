// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"herald/pkg/config"
	"herald/pkg/domain"
	"herald/pkg/input/common"
	"herald/pkg/input/types/file/parsers"
	"herald/pkg/log"

	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Provider interface {
	StartPolling() error
	StopPolling() error
	GetName() string
}

type DNSEntry struct {
	Name                   string `json:"name"`
	Hostname               string `json:"hostname"`
	Domain                 string `json:"domain"`
	RecordType             string `json:"type"`
	Target                 string `json:"target"`
	TTL                    int    `json:"ttl"`
	Overwrite              bool   `json:"overwrite"`
	RecordTypeAMultiple    bool   `json:"record_type_a_multiple"`
	RecordTypeAAAAMultiple bool   `json:"record_type_aaaa_multiple"`
	SourceName             string `json:"source_name"`
}

// GetFQDN returns the fully qualified domain name
func (d DNSEntry) GetFQDN() string {
	return d.Name
}

// GetRecordType returns the DNS record type
func (d DNSEntry) GetRecordType() string {
	return d.RecordType
}

type FileProvider struct {
	source             string
	format             string
	interval           time.Duration
	watchMode          bool
	recordRemoveOnStop bool
	processExisting    bool
	options            map[string]string
	filterConfig       common.FilterConfig // Add filter configuration
	lastRecords        map[string]DNSEntry
	mutex              sync.Mutex
	running            bool
	ctx                context.Context
	cancel             context.CancelFunc
	logPrefix          string
	isInitialLoad      bool
	logger             *log.ScopedLogger              // provider-specific logger
	name               string                         // Profile name
	outputWriter       domain.OutputWriter            // Injected dependency
	outputSyncer       domain.OutputSyncer            // Injected dependency
	domainConfigs      map[string]config.DomainConfig // Add domain configs for domain matching
}

func NewProvider(options map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           60 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "file",
	})
	logPrefix := common.BuildLogPrefix("file", parsed.Name)
	source := common.ReadFileValue(options["source"])
	if source == "" {
		log.Error("%s source option (file path) is required", logPrefix)
		return nil, fmt.Errorf("%s source option (file path) is required", logPrefix)
	}

	// Convert string options to structured options for filtering
	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	// Parse filter configuration using structured format
	filterLogPrefix := logPrefix + "/filter"
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions, filterLogger)
	if err != nil {
		log.Debug("%s Error creating filter configuration: %v, using default", logPrefix, err)
		filterConfig = common.DefaultFilterConfig()
	}

	format := common.ReadFileValue(options["format"])
	if format == "" {
		ext := strings.ToLower(filepath.Ext(source))
		if ext == ".yaml" || ext == ".yml" {
			format = "yaml"
		} else if ext == ".json" {
			format = "json"
		} else {
			format = "yaml" // default
		}
	}
	watchMode := true
	finalInterval := parsed.Interval // Use the parsed interval as default

	if v := strings.ToLower(options["interval"]); v != "" {
		switch v {
		case "0", "false", "disabled":
			finalInterval = 0
			watchMode = false
		case "-1", "always", "constant":
			watchMode = true
			finalInterval = -1 * time.Second
		default:
			if d, err := time.ParseDuration(v); err == nil {
				finalInterval = d
				watchMode = false
			} else {
				// Use global logger here since scoped logger doesn't exist yet
				log.Warn("%s Invalid interval '%s', using default: watchMode=true", logPrefix, v)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if watchMode {
		log.Info("%s Initializing file provider: name: %s source=%s, format=%s, watchMode=%v", logPrefix, parsed.Name, source, format, watchMode)
	} else {
		log.Info("%s Initializing file provider: name: %s source=%s, format=%s, interval=%v, watchMode=%v", logPrefix, parsed.Name, source, format, finalInterval, watchMode)
	}
	logLevel := options["log_level"] // Get provider-specific log level

	// Create scoped logger
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	return &FileProvider{
		source:             source,
		format:             format,
		interval:           finalInterval,
		watchMode:          watchMode,
		recordRemoveOnStop: parsed.RecordRemoveOnStop,
		processExisting:    parsed.ProcessExisting,
		options:            options,
		filterConfig:       filterConfig,
		lastRecords:        make(map[string]DNSEntry),
		ctx:                ctx,
		cancel:             cancel,
		logPrefix:          logPrefix,
		isInitialLoad:      true,
		logger:             scopedLogger,
		name:               parsed.Name, // Store the parsed name
		outputWriter:       outputWriter,
		outputSyncer:       outputSyncer,
	}, nil
}

func (p *FileProvider) StartPolling() error {
	if p.running {
		p.logger.Warn("StartPolling called but already running")
		return nil
	}
	p.logger.Debug("Starting polling loop")
	p.running = true
	if p.watchMode {
		go p.watchLoop()
	} else if p.interval == 0 {
		// Run once only
		go func() {
			p.processFile()
			p.running = false
		}()
	} else {
		go p.pollLoop()
	}
	return nil
}

func (p *FileProvider) StopPolling() error {
	p.running = false
	p.cancel()
	return nil
}

func (p *FileProvider) IsRunning() bool {
	return p.running
}

func (p *FileProvider) GetDNSEntries() ([]DNSEntry, error) {
	p.logger.Debug("GetDNSEntries called")
	return p.readFile()
}

func (p *FileProvider) pollLoop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	if p.processExisting {
		p.logger.Trace("Processing existing file on startup")
		p.processFile()
	}
	// Always process once immediately on startup
	if !p.processExisting {
		p.processFile()
	}
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.logger.Trace("Polling file for changes")
			p.processFile()
		}
	}
}

func (p *FileProvider) watchLoop() {
	p.logger.Verbose("Starting file watch mode")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		p.logger.Error("Failed to create file watcher: %v", err)
		return
	}
	defer watcher.Close()
	dir := filepath.Dir(p.source)
	if err := watcher.Add(dir); err != nil {
		p.logger.Error("Failed to add watch on dir %s: %v", dir, err)
		return
	}
	if p.processExisting {
		p.logger.Trace("Processing existing file on startup (watch mode)")
		p.processFile()
	}
	for {
		select {
		case <-p.ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// Check if this event is for our actual source file
			absSource, _ := filepath.Abs(p.source)
			absEvent, _ := filepath.Abs(event.Name)

			// Only log and process events for our actual source file, not other files in directory
			if absEvent == absSource && (event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0) {
				p.logger.Trace("fsnotify event: Name='%s', Op=%v", event.Name, event.Op)
				switch {
				case event.Op&fsnotify.Write != 0:
					p.logger.Verbose("File modified: '%s'", event.Name)
				case event.Op&fsnotify.Create != 0:
					p.logger.Verbose("File created: '%s'", event.Name)
				case event.Op&fsnotify.Rename != 0:
					p.logger.Verbose("File renamed: '%s'", event.Name)
				case event.Op&fsnotify.Remove != 0:
					p.logger.Verbose("File removed: '%s'", event.Name)
				default:
					p.logger.Verbose("File changed: '%s' (op: '%v')", event.Name, event.Op)
				}
				p.processFile()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			p.logger.Error("File watch error: %v", err)
		}
	}
}

func (p *FileProvider) processFile() {
	entries, err := p.readFile()
	if err != nil {
		p.logger.Error("Failed to read file: %v", err)
		return
	}
	p.logger.Debug("Processing %d DNS entries from file", len(entries))
	// p.logger.Trace("%s Available domains in config: %v", p.logPrefix, keys(config.GlobalConfig.Domains)) // Removed direct access

	batchProcessor := domain.NewBatchProcessor(p.logPrefix, p.outputWriter, p.outputSyncer)
	current := make(map[string]DNSEntry)

	for _, e := range entries {
		fqdn := e.GetFQDN()
		recordType := e.GetRecordType()
		key := fqdn + ":" + recordType
		current[key] = e
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		if _, ok := p.lastRecords[key]; !ok {
			if p.isInitialLoad {
				p.logger.Info("Initial record detected: %s (%s)", fqdnNoDot, recordType)
			} else {
				p.logger.Info("New record detected: %s (%s)", fqdnNoDot, recordType)
			}
			p.logger.Trace("New or changed record detected: fqdn='%s', type='%s'", fqdnNoDot, recordType)

			// The domain.EnsureDNSForRouterStateWithProvider will handle domain config lookup
			// and input provider validation.
			// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
			// This is consistent with how other input providers pass the FQDN.
			// The domain.EnsureDNSForRouterStateWithProvider will extract the domain and subdomain from fqdnNoDot.

			// Use helper to get parent domain for correct domain config matching
			realDomain := p.getParentDomainForFQDN(fqdnNoDot)
			p.logger.Trace("Using real domain name '%s' for DNS provider", realDomain)
			state := domain.RouterState{
				SourceType: "file",
				Name:       p.name, // Use the actual provider name
				Service:    e.Target,
				RecordType: recordType, // Set the actual DNS record type
			}
			p.logger.Trace("Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
			if err != nil {
				p.logger.Error("Failed to ensure DNS for '%s': %v", fqdnNoDot, err)
			}
		}
	}
	if p.recordRemoveOnStop {
		for key, old := range p.lastRecords {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				p.logger.Info("Record removed: %s (%s)", fqdnNoDot, recordType) // This log is fine

				// The domain.EnsureDNSRemoveForRouterStateWithProvider will handle domain config lookup
				// and input provider validation.
				// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
				// This is consistent with how other input providers pass the FQDN.
				// The domain.EnsureDNSRemoveForRouterStateWithProvider will extract the domain and subdomain from fqdnNoDot.

				// Use helper to get parent domain for correct domain config matching
				realDomain := p.getParentDomainForFQDN(fqdnNoDot)
				p.logger.Trace("Using real domain name '%s' for DNS provider (removal)", realDomain)
				state := domain.RouterState{
					SourceType: "file",
					Name:       p.name, // Use the actual provider name
					Service:    old.Target,
					RecordType: recordType,
				}
				p.logger.Trace("Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
				err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
				if err != nil {
					p.logger.Error("Failed to remove DNS for '%s': %v", fqdnNoDot, err)
				}
			}
		}
	}
	p.mutex.Lock()
	p.lastRecords = current
	p.isInitialLoad = false // Mark that we've completed the initial load
	p.mutex.Unlock()

	// Finalize the batch - this will sync output files only if there were changes
	batchProcessor.FinalizeBatch()
}

func (p *FileProvider) readFile() ([]DNSEntry, error) {
	p.logger.Trace("Reading file: %s", p.source)
	data, err := os.ReadFile(p.source)
	if err != nil {
		p.logger.Error("Error reading file: %v", err)
		return nil, err
	}
	var records []common.FileRecord
	if p.format == "yaml" {
		p.logger.Trace("Parsing YAML file")
		// Try structured format first, fall back to basic format
		records, err = parsers.ParseStructuredYAML(data)
		if err != nil {
			p.logger.Trace("Structured YAML parse failed, trying basic format: %v", err)
			records, err = common.ParseRecordsYAML(data)
			if err != nil {
				p.logger.Error("YAML unmarshal error: %v", err)
				return nil, err
			}
		}
	} else if p.format == "json" {
		p.logger.Trace("Parsing JSON file")
		// Try structured format first, fall back to basic format
		records, err = parsers.ParseStructuredJSON(data)
		if err != nil {
			p.logger.Trace("Structured JSON parse failed, trying basic format: %v", err)
			records, err = common.ParseRecordsJSON(data)
			if err != nil {
				p.logger.Error("JSON unmarshal error: %v", err)
				return nil, err
			}
		}
	} else if p.format == "hosts" {
		p.logger.Trace("Parsing hosts file")
		records, err = parsers.ParseHostsFile(data)
		if err != nil {
			p.logger.Error("Hosts file parse error: %v", err)
			return nil, err
		}
	} else {
		p.logger.Error("Unsupported file format: %s", p.format)
		return nil, fmt.Errorf("unsupported file format: %s", p.format)
	}
	entries := common.ConvertRecordsToDNSEntries(records, p.name)

	// Convert from common.DNSEntry to local DNSEntry type
	var localEntries []DNSEntry
	for _, entry := range entries {
		localEntries = append(localEntries, DNSEntry{
			Name:                   entry.Name,
			Hostname:               entry.Hostname,
			Domain:                 entry.Domain,
			RecordType:             entry.RecordType,
			Target:                 entry.Target,
			TTL:                    entry.TTL,
			Overwrite:              entry.Overwrite,
			RecordTypeAMultiple:    entry.RecordTypeAMultiple,
			RecordTypeAAAAMultiple: entry.RecordTypeAAAAMultiple,
			SourceName:             entry.SourceName,
		})
	}

	return localEntries, nil
}

// GetName returns the provider name
func (fp *FileProvider) GetName() string {
	return "file"
}

// SetDomainConfigs allows injection of loaded domain configs (like Docker/Caddy)
func (p *FileProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

// Helper to find the best matching domain config by suffix match on the 'name' field
func (p *FileProvider) getParentDomainForFQDN(fqdn string) string {
	p.logger.Trace("getParentDomainForFQDN called with fqdn='%s'", fqdn)
	var bestMatch string
	for _, cfg := range p.domainConfigs {
		p.logger.Trace("Checking if fqdn '%s' has suffix '%s'", fqdn, cfg.Name)
		if strings.HasSuffix(fqdn, cfg.Name) {
			if len(cfg.Name) > len(bestMatch) {
				bestMatch = cfg.Name
				p.logger.Trace("Match: '%s'", bestMatch)
			}
		}
	}
	if bestMatch == "" {
		p.logger.Warn("No domain config matched for FQDN '%s' (configs: %v)", fqdn, p.domainConfigs)
	}
	return bestMatch
}
