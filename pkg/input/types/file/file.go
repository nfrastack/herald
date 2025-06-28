// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
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
	logger             *log.ScopedLogger   // provider-specific logger
	name               string              // Profile name
	outputWriter       domain.OutputWriter // Injected dependency
	outputSyncer       domain.OutputSyncer // Injected dependency
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
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions)
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
	p.logger.Debug("%s GetDNSEntries called", p.logPrefix)
	return p.readFile()
}

func (p *FileProvider) pollLoop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	if p.processExisting {
		p.logger.Trace("%s Processing existing file on startup", p.logPrefix)
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
			p.logger.Trace("%s Polling file for changes", p.logPrefix)
			p.processFile()
		}
	}
}

func (p *FileProvider) watchLoop() {
	p.logger.Verbose("%s Starting file watch mode", p.logPrefix)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		p.logger.Error("%s Failed to create file watcher: %v", p.logPrefix, err)
		return
	}
	defer watcher.Close()
	dir := filepath.Dir(p.source)
	if err := watcher.Add(dir); err != nil {
		p.logger.Error("%s Failed to add watch on dir %s: %v", p.logPrefix, dir, err)
		return
	}
	if p.processExisting {
		p.logger.Trace("%s Processing existing file on startup (watch mode)", p.logPrefix)
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
				p.logger.Trace("%s fsnotify event: Name='%s', Op=%v", p.logPrefix, event.Name, event.Op)
				switch {
				case event.Op&fsnotify.Write != 0:
					p.logger.Verbose("%s File modified: '%s'", p.logPrefix, event.Name)
				case event.Op&fsnotify.Create != 0:
					p.logger.Verbose("%s File created: '%s'", p.logPrefix, event.Name)
				case event.Op&fsnotify.Rename != 0:
					p.logger.Verbose("%s File renamed: '%s'", p.logPrefix, event.Name)
				case event.Op&fsnotify.Remove != 0:
					p.logger.Verbose("%s File removed: '%s'", p.logPrefix, event.Name)
				default:
					p.logger.Verbose("%s File changed: '%s' (op: '%v')", p.logPrefix, event.Name, event.Op)
				}
				p.processFile()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			p.logger.Error("%s File watch error: %v", p.logPrefix, err)
		}
	}
}

func (p *FileProvider) processFile() {
	entries, err := p.readFile()
	if err != nil {
		p.logger.Error("%s Failed to read file: %v", p.logPrefix, err)
		return
	}
	p.logger.Debug("%s Processing %d DNS entries from file", p.logPrefix, len(entries))
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
				p.logger.Info("%s Initial record detected: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			} else {
				p.logger.Info("%s New record detected: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			}
			p.logger.Trace("%s New or changed record detected: fqdn='%s', type='%s'", p.logPrefix, fqdnNoDot, recordType)

			// The domain.EnsureDNSForRouterStateWithProvider will handle domain config lookup
			// and input provider validation.
			// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
			// This is consistent with how other input providers pass the FQDN.
			// The domain.EnsureDNSForRouterStateWithProvider will extract the domain and subdomain from fqdnNoDot.

			// The domain.EnsureDNSForRouterStateWithProvider will handle domain config lookup
			// and input provider validation.
			// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
			realDomain, _ := common.ExtractDomainAndSubdomain(fqdnNoDot) // This is just for logging, actual domain resolution is in domain package

			// The domain.EnsureDNSForRouterStateWithProvider will handle domain config lookup
			// and input provider validation.
			p.logger.Trace("%s Using real domain name '%s' for DNS provider", p.logPrefix, realDomain)
			state := domain.RouterState{
				SourceType: "file",
				Name:       p.name, // Use the actual provider name
				Service:    e.Target,
				RecordType: recordType, // Set the actual DNS record type
			}
			p.logger.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(fqdnNoDot, fqdnNoDot, state) // Pass fqdnNoDot as domain, it will be resolved later
			if err != nil {
				p.logger.Error("%s Failed to ensure DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
			}
		}
	}
	if p.recordRemoveOnStop {
		for key, old := range p.lastRecords {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				p.logger.Info("%s Record removed: %s (%s)", p.logPrefix, fqdnNoDot, recordType) // This log is fine

				// The domain.EnsureDNSRemoveForRouterStateWithProvider will handle domain config lookup
				// and input provider validation.
				// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
				// This is consistent with how other input providers pass the FQDN.
				// The domain.EnsureDNSRemoveForRouterStateWithProvider will extract the domain and subdomain from fqdnNoDot.

				// The domain.EnsureDNSRemoveForRouterStateWithProvider will handle domain config lookup
				// and input provider validation.
				// We pass the fqdnNoDot as the domain for now, and the domain package will resolve it to the correct domain config.
				realDomain, _ := common.ExtractDomainAndSubdomain(fqdnNoDot) // This is just for logging, actual domain resolution is in domain package

				p.logger.Trace("%s Using real domain name '%s' for DNS provider (removal)", p.logPrefix, realDomain)

				state := domain.RouterState{
					SourceType: "file",
					Name:       p.name, // Use the actual provider name
					Service:    old.Target,
					RecordType: recordType,
				}
				p.logger.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
				err := batchProcessor.ProcessRecordRemoval(fqdnNoDot, fqdnNoDot, state) // Pass fqdnNoDot as domain, it will be resolved later
				if err != nil {
					p.logger.Error("%s Failed to remove DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
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
	p.logger.Trace("%s Reading file: %s", p.logPrefix, p.source)
	data, err := os.ReadFile(p.source)
	if err != nil {
		p.logger.Error("%s Error reading file: %v", p.logPrefix, err)
		return nil, err
	}
	var records []common.FileRecord
	if p.format == "yaml" {
		p.logger.Trace("%s Parsing YAML file", p.logPrefix)
		// Try structured format first, fall back to basic format
		records, err = parsers.ParseStructuredYAML(data)
		if err != nil {
			p.logger.Trace("%s Structured YAML parse failed, trying basic format: %v", p.logPrefix, err)
			records, err = common.ParseRecordsYAML(data)
			if err != nil {
				p.logger.Error("%s YAML unmarshal error: %v", p.logPrefix, err)
				return nil, err
			}
		}
	} else if p.format == "json" {
		p.logger.Trace("%s Parsing JSON file", p.logPrefix)
		// Try structured format first, fall back to basic format
		records, err = parsers.ParseStructuredJSON(data)
		if err != nil {
			p.logger.Trace("%s Structured JSON parse failed, trying basic format: %v", p.logPrefix, err)
			records, err = common.ParseRecordsJSON(data)
			if err != nil {
				p.logger.Error("%s JSON unmarshal error: %v", p.logPrefix, err)
				return nil, err
			}
		}
	} else if p.format == "hosts" {
		p.logger.Trace("%s Parsing hosts file", p.logPrefix)
		records, err = parsers.ParseHostsFile(data)
		if err != nil {
			p.logger.Error("%s Hosts file parse error: %v", p.logPrefix, err)
			return nil, err
		}
	} else {
		p.logger.Error("%s Unsupported file format: %s", p.logPrefix, p.format)
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
