// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input/common"
	"github.com/nfrastack/herald/internal/input/types/file/parsers"
	"github.com/nfrastack/herald/internal/log"

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

func (d DNSEntry) GetFQDN() string {
	return d.Name
}

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
		log.NewScopedLogger("", "").With("action", "config.error", "provider", parsed.Name).Error("option (file path) is required")
		return nil, fmt.Errorf("%s source option (file path) is required", logPrefix)
	}

	structuredOptions := make(map[string]interface{})
	for key, value := range options {
		structuredOptions[key] = value
	}

	filterLogPrefix := logPrefix + "/filter"
	filterLogger := log.NewScopedLogger(filterLogPrefix, "")
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions, filterLogger)
	if err != nil {
		log.NewScopedLogger("", "").With("action", "input.filter", "provider", parsed.Name).Debug("creating filter configuration: %v, using default", err)
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
				log.NewScopedLogger("", "").With("action", "config.load", "provider", parsed.Name).Warn("interval '%s', using default: watchMode=true", v)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if watchMode {
		log.NewScopedLogger("", "").With("action", "provider.init", "provider", parsed.Name).Info("file provider: source=%s, format=%s, watchMode=%v", source, format, watchMode)
	} else {
		log.NewScopedLogger("", "").With("action", "provider.init", "provider", parsed.Name).Info("file provider: source=%s, format=%s, interval=%v, watchMode=%v", source, format, finalInterval, watchMode)
	}
	logLevel := options["log_level"] // Get provider-specific log level

	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		scopedLogger.With("action", "provider.init").Info("log_level set to: '%s'", logLevel)
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
		p.logger.With("action", "provider.poll").Warn("already running")
		return nil
	}
	p.logger.With("action", "provider.poll").Debug("polling loop")
	p.running = true
	if p.watchMode {
		go p.watchLoop()
	} else if p.interval == 0 {
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
	p.logger.With("action", "input.load").Debug("DNS entries")
	return p.readFile()
}

func (p *FileProvider) pollLoop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	if p.processExisting {
		p.logger.With("action", "input.load").Trace("existing file on startup")
		p.processFile()
	}
	if !p.processExisting {
		p.processFile()
	}
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.logger.With("action", "provider.poll").Trace("file for changes")
			p.processFile()
		}
	}
}

func (p *FileProvider) watchLoop() {
	p.logger.With("action", "provider.poll").Verbose("file watch mode")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		p.logger.With("action", "sync.fail").Error("file watcher: %v", err)
		return
	}
	defer watcher.Close()
	dir := filepath.Dir(p.source)
	if err := watcher.Add(dir); err != nil {
		p.logger.With("action", "sync.fail").Error("adding watch on dir %s: %v", dir, err)
		return
	}
	if p.processExisting {
		p.logger.With("action", "input.load").Trace("existing file on startup (watch mode)")
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

			absSource, _ := filepath.Abs(p.source)
			absEvent, _ := filepath.Abs(event.Name)

			if absEvent == absSource && (event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0) {
				p.logger.With("action", "provider.event").Trace("event: Name='%s', Op=%v", event.Name, event.Op)
				switch {
				case event.Op&fsnotify.Write != 0:
					p.logger.With("action", "provider.event").Verbose("modified: '%s'", event.Name)
				case event.Op&fsnotify.Create != 0:
					p.logger.With("action", "provider.event").Verbose("created: '%s'", event.Name)
				case event.Op&fsnotify.Rename != 0:
					p.logger.With("action", "provider.event").Verbose("renamed: '%s'", event.Name)
				case event.Op&fsnotify.Remove != 0:
					p.logger.With("action", "provider.event").Verbose("removed: '%s'", event.Name)
				default:
					p.logger.With("action", "provider.event").Verbose("changed: '%s' (op: '%v')", event.Name, event.Op)
				}
				p.processFile()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			p.logger.With("action", "sync.fail").Error("watch error: %v", err)
		}
	}
}

func (p *FileProvider) processFile() {
	entries, err := p.readFile()
	if err != nil {
		p.logger.With("action", "input.load").Error("file: %v", err)
		return
	}
	p.logger.With("action", "input.load").Debug("%d DNS entries from file", len(entries))

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
				p.logger.With("action", "record.create", "fqdn", fqdnNoDot).Info("(%s)", recordType)
			} else {
				p.logger.With("action", "record.create", "fqdn", fqdnNoDot).Info("(%s)", recordType)
			}
			p.logger.With("action", "record.sync", "fqdn", fqdnNoDot).Trace("type='%s'", recordType)

			realDomain := p.getParentDomainForFQDN(fqdnNoDot)
			p.logger.With("action", "domain.match").Trace("real domain name '%s' for DNS provider", realDomain)
			state := domain.RouterState{
				SourceType: "file",
				Name:       p.name, // Use the actual provider name
				Service:    e.Target,
				RecordType: recordType, // Set the actual DNS record type
			}
			p.logger.With("action", "record.create", "domain", realDomain, "fqdn", fqdnNoDot).Trace("ProcessRecord: %+v", state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
			if err != nil {
				p.logger.With("action", "sync.fail", "fqdn", fqdnNoDot).Error("ensuring DNS: %v", err)
			}
		}
	}
	if p.recordRemoveOnStop {
		for key, old := range p.lastRecords {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				p.logger.With("action", "record.delete", "fqdn", fqdnNoDot).Info("removed (%s)", recordType)

				realDomain := p.getParentDomainForFQDN(fqdnNoDot)
				p.logger.With("action", "domain.match").Trace("real domain name '%s' for DNS provider (removal)", realDomain)
				state := domain.RouterState{
					SourceType: "file",
					Name:       p.name, // Use the actual provider name
					Service:    old.Target,
					RecordType: recordType,
				}
				p.logger.With("action", "record.delete", "domain", realDomain, "fqdn", fqdnNoDot).Trace("ProcessRecordRemoval: %+v", state)
				err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
				if err != nil {
					p.logger.With("action", "sync.fail", "fqdn", fqdnNoDot).Error("removing DNS: %v", err)
				}
			}
		}
	}
	p.mutex.Lock()
	p.lastRecords = current
	p.isInitialLoad = false // Mark that we've completed the initial load
	p.mutex.Unlock()

	batchProcessor.FinalizeBatch()
}

func (p *FileProvider) readFile() ([]DNSEntry, error) {
	p.logger.With("action", "input.load").Trace("file: %s", p.source)
	data, err := os.ReadFile(p.source)
	if err != nil {
		p.logger.With("action", "input.load").Error("reading file: %v", err)
		return nil, err
	}
	var records []common.FileRecord
	if p.format == "yaml" {
		p.logger.With("action", "input.load").Trace("YAML file")
		records, err = parsers.ParseStructuredYAML(data)
		if err != nil {
			p.logger.With("action", "input.load").Trace("YAML parse failed, trying basic format: %v", err)
			records, err = common.ParseRecordsYAML(data)
			if err != nil {
				p.logger.With("action", "config.error").Error("unmarshal error: %v", err)
				return nil, err
			}
		}
	} else if p.format == "json" {
		p.logger.With("action", "input.load").Trace("JSON file")
		records, err = parsers.ParseStructuredJSON(data)
		if err != nil {
			p.logger.With("action", "input.load").Trace("JSON parse failed, trying basic format: %v", err)
			records, err = common.ParseRecordsJSON(data)
			if err != nil {
				p.logger.With("action", "config.error").Error("unmarshal error: %v", err)
				return nil, err
			}
		}
	} else if p.format == "hosts" {
		p.logger.With("action", "input.load").Trace("hosts file")
		records, err = parsers.ParseHostsFile(data)
		if err != nil {
			p.logger.With("action", "config.error").Error("parse error: %v", err)
			return nil, err
		}
	} else {
		p.logger.With("action", "config.error").Error("file format: %s", p.format)
		return nil, fmt.Errorf("unsupported file format: %s", p.format)
	}
	entries := common.ConvertRecordsToDNSEntries(records, p.name)

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

func (fp *FileProvider) GetName() string {
	return "file"
}

func (p *FileProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

func (p *FileProvider) getParentDomainForFQDN(fqdn string) string {
	p.logger.With("action", "domain.match").Trace("with fqdn='%s'", fqdn)
	var bestMatch string
	for _, cfg := range p.domainConfigs {
		p.logger.With("action", "domain.match").Trace("if fqdn '%s' has suffix '%s'", fqdn, cfg.Name)
		if strings.HasSuffix(fqdn, cfg.Name) {
			if len(cfg.Name) > len(bestMatch) {
				bestMatch = cfg.Name
				p.logger.With("action", "domain.match").Trace("'%s'", bestMatch)
			}
		}
	}
	if bestMatch == "" {
		p.logger.With("action", "domain.skip").Warn("no domain config matched for FQDN '%s' (configs: %v)", fqdn, p.domainConfigs)
	}
	return bestMatch
}
