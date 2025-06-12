// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type FileProvider struct {
	source             string
	format             string
	interval           time.Duration
	watchMode          bool
	recordRemoveOnStop bool
	processExisting    bool
	options            map[string]string
	filterConfig       pollCommon.FilterConfig // Add filter configuration
	lastRecords        map[string]poll.DNSEntry
	mutex              sync.Mutex
	running            bool
	ctx                context.Context
	cancel             context.CancelFunc
	logPrefix          string
	isInitialLoad      bool
	logger             *log.ScopedLogger // provider-specific logger
}

func NewProvider(options map[string]string) (poll.Provider, error) {
	parsed := pollCommon.ParsePollProviderOptions(options, pollCommon.PollProviderOptions{
		Interval:           60 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "file",
	})
	logPrefix := pollCommon.BuildLogPrefix("file", parsed.Name)
	source := pollCommon.GetOptionOrEnv(options, "source", "FILE_SOURCE", "")
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
	filterConfig, err := pollCommon.NewFilterFromStructuredOptions(structuredOptions)
	if err != nil {
		log.Debug("%s Error creating filter configuration: %v, using default", logPrefix, err)
		filterConfig = pollCommon.DefaultFilterConfig()
	}

	format := pollCommon.GetOptionOrEnv(options, "format", "FILE_FORMAT", "")
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
		lastRecords:        make(map[string]poll.DNSEntry),
		ctx:                ctx,
		cancel:             cancel,
		logPrefix:          logPrefix,
		isInitialLoad:      true,
		logger:             scopedLogger,
	}, nil
}

func (p *FileProvider) StartPolling() error {
	if p.running {
		p.logger.Warn("%s StartPolling called but already running", p.logPrefix)
		return nil
	}
	p.logger.Debug("%s Starting polling loop", p.logPrefix)
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

func (p *FileProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
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
	p.logger.Trace("%s Available domains in config: %v", p.logPrefix, keys(config.GlobalConfig.Domains))

	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(p.logPrefix)
	current := make(map[string]poll.DNSEntry)

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

			// Extract domain and subdomain like Docker/Traefik
			domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
			p.logger.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s'", p.logPrefix, domainKey, subdomain, fqdnNoDot)
			if domainKey == "" {
				p.logger.Error("%s No domain config found for '%s' (tried to match domain from FQDN)", p.logPrefix, fqdnNoDot)
				continue
			}
			domainCfg, ok := config.GlobalConfig.Domains[domainKey]
			if !ok {
				p.logger.Error("%s Domain '%s' not found in config for fqdn='%s'", p.logPrefix, domainKey, fqdnNoDot)
				continue
			}
			realDomain := domainCfg.Name
			p.logger.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s')", p.logPrefix, realDomain, domainKey)
			providerName := p.options["name"]
			if providerName == "" {
				providerName = "file_profile"
			}
			state := domain.RouterState{
				SourceType: "file_profile",
				Name:       providerName,
				Service:    e.Target,
				RecordType: recordType, // Set the actual DNS record type
			}
			p.logger.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
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
				p.logger.Info("%s Record removed: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
				domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
				p.logger.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s' (removal)", p.logPrefix, domainKey, subdomain, fqdnNoDot)
				if domainKey == "" {
					p.logger.Error("%s No domain config found for '%s' (removal, tried to match domain from FQDN)", p.logPrefix, fqdnNoDot)
					continue
				}
				domainCfg, ok := config.GlobalConfig.Domains[domainKey]
				if !ok {
					p.logger.Error("%s Domain '%s' not found in config for fqdn='%s' (removal)", p.logPrefix, domainKey, fqdnNoDot)
					continue
				}
				realDomain := domainCfg.Name
				p.logger.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s') (removal)", p.logPrefix, realDomain, domainKey)
				providerName := p.options["name"]
				if providerName == "" {
					providerName = "file_profile"
				}
				state := domain.RouterState{
					SourceType: "file_profile",
					Name:       providerName,
					Service:    old.Target,
					RecordType: recordType,
				}
				p.logger.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
				err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
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

// keys returns the keys of a map as a slice
func keys(m map[string]config.DomainConfig) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (p *FileProvider) readFile() ([]poll.DNSEntry, error) {
	p.logger.Trace("%s Reading file: %s", p.logPrefix, p.source)
	data, err := os.ReadFile(p.source)
	if err != nil {
		p.logger.Error("%s Error reading file: %v", p.logPrefix, err)
		return nil, err
	}
	var records []pollCommon.FileRecord
	if p.format == "yaml" {
		p.logger.Trace("%s Parsing YAML file", p.logPrefix)
		records, err = pollCommon.ParseRecordsYAML(data)
		if err != nil {
			p.logger.Error("%s YAML unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else if p.format == "json" {
		p.logger.Trace("%s Parsing JSON file", p.logPrefix)
		records, err = pollCommon.ParseRecordsJSON(data)
		if err != nil {
			p.logger.Error("%s JSON unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else if p.format == "hosts" {
		p.logger.Trace("%s Parsing hosts file", p.logPrefix)
		records, err = pollCommon.ParseHostsFile(data)
		if err != nil {
			p.logger.Error("%s Hosts file parse error: %v", p.logPrefix, err)
			return nil, err
		}
	} else {
		p.logger.Error("%s Unsupported file format: %s", p.logPrefix, p.format)
		return nil, fmt.Errorf("unsupported file format: %s", p.format)
	}
	providerName := p.options["name"]
	if providerName == "" {
		providerName = "file_profile"
	}
	entries := pollCommon.ConvertRecordsToDNSEntries(records, providerName)
	return entries, nil
}

func init() {
	poll.RegisterProvider("file", NewProvider)
}
