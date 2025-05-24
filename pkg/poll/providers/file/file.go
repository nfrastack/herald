// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	"dns-companion/pkg/poll/providers/common"

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
	lastRecords        map[string]poll.DNSEntry
	mutex              sync.Mutex
	running            bool
	ctx                context.Context
	cancel             context.CancelFunc
	logPrefix          string
}

func NewProvider(options map[string]string) (poll.Provider, error) {
	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           60 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "file",
	})
	source := options["source"]
	if source == "" {
		log.Error("[poll/file] source option (file path) is required")
		return nil, fmt.Errorf("[poll/file] source option (file path) is required")
	}
	format := options["format"]
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
	interval := -1 * time.Second
	watchMode := true
	if v := strings.ToLower(options["interval"]); v != "" {
		switch v {
		case "0", "false", "disabled":
			interval = 0
			watchMode = false
		case "-1", "always", "constant":
			watchMode = true
			interval = -1
		default:
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
				watchMode = false
			} else {
				log.Warn("[poll/file] Invalid interval '%s', using default: %v", v, interval)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	logPrefix := "[poll/file]"
	if parsed.Name != "" && parsed.Name != "file" {
		logPrefix = "[poll/file/" + parsed.Name + "]"
	}
	if watchMode {
		log.Info("%s Initializing file provider: source=%s, format=%s, watchMode=%v", logPrefix, source, format, watchMode)
	} else {
		log.Info("%s Initializing file provider: source=%s, format=%s, interval=%v, watchMode=%v", logPrefix, source, format, parsed.Interval, watchMode)
	}
	return &FileProvider{
		source:             source,
		format:             format,
		interval:           parsed.Interval,
		watchMode:          watchMode,
		recordRemoveOnStop: parsed.RecordRemoveOnStop,
		processExisting:    parsed.ProcessExisting,
		options:            options,
		lastRecords:        make(map[string]poll.DNSEntry),
		ctx:                ctx,
		cancel:             cancel,
		logPrefix:          logPrefix,
	}, nil
}

func (p *FileProvider) StartPolling() error {
	if p.running {
		log.Warn("%s StartPolling called but already running", p.logPrefix)
		return nil
	}
	log.Info("%s Starting polling loop", p.logPrefix)
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
	log.Debug("%s GetDNSEntries called", p.logPrefix)
	return p.readFile()
}

func (p *FileProvider) pollLoop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	if p.processExisting {
		log.Trace("%s Processing existing file on startup", p.logPrefix)
		p.processFile()
	}
	for {
		select {
		case <-p.ctx.Done():
			log.Info("%s Polling loop stopped", p.logPrefix)
			return
		case <-ticker.C:
			log.Trace("%s Polling file for changes", p.logPrefix)
			p.processFile()
		}
	}
}

func (p *FileProvider) watchLoop() {
	log.Info("%s Starting file watch mode", p.logPrefix)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("%s Failed to create file watcher: %v", p.logPrefix, err)
		return
	}
	defer watcher.Close()
	dir := filepath.Dir(p.source)
	if err := watcher.Add(dir); err != nil {
		log.Error("%s Failed to add watch on dir %s: %v", p.logPrefix, dir, err)
		return
	}
	if p.processExisting {
		log.Trace("%s Processing existing file on startup (watch mode)", p.logPrefix)
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
			log.Trace("%s fsnotify event: Name='%s', Op=%v", p.logPrefix, event.Name, event.Op)
			absSource, _ := filepath.Abs(p.source)
			absEvent, _ := filepath.Abs(event.Name)
			if absEvent == absSource && (event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0) {
				log.Trace("%s File changed: %s (op: %v)", p.logPrefix, event.Name, event.Op)
				p.processFile()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Error("%s File watch error: %v", p.logPrefix, err)
		}
	}
}

func (p *FileProvider) processFile() {
	initialRun := len(p.lastRecords) == 0
	entries, err := p.readFile()
	if err != nil {
		log.Error("%s Failed to read file: %v", p.logPrefix, err)
		return
	}
	log.Debug("%s Processing %d DNS entries from file", p.logPrefix, len(entries))
	log.Trace("%s Available domains in config: %v", p.logPrefix, keys(config.GlobalConfig.Domains))
	current := make(map[string]poll.DNSEntry)
	for _, e := range entries {
		fqdn := e.GetFQDN()
		recordType := e.GetRecordType()
		key := fqdn + ":" + recordType
		current[key] = e
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		if _, ok := p.lastRecords[key]; !ok {
			if initialRun {
				log.Info("%s Initial record detected: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			} else {
				log.Info("%s New record detected: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			}
			log.Trace("%s New or changed record detected: fqdn='%s', type='%s'", p.logPrefix, fqdnNoDot, recordType)

			// Extract domain and subdomain like Docker/Traefik
			domainKey, subdomain := common.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
			log.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s'", p.logPrefix, domainKey, subdomain, fqdnNoDot)
			if domainKey == "" {
				log.Error("%s No domain config found for '%s' (tried to match domain from FQDN)", p.logPrefix, fqdnNoDot)
				continue
			}
			domainCfg, ok := config.GlobalConfig.Domains[domainKey]
			if !ok {
				log.Error("%s Domain '%s' not found in config for fqdn='%s'", p.logPrefix, domainKey, fqdnNoDot)
				continue
			}
			realDomain := domainCfg.Name
			log.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s')", p.logPrefix, realDomain, domainKey)
			providerName := p.options["name"]
			if providerName == "" {
				providerName = "file_profile"
			}
			state := domain.RouterState{SourceType: "file_profile", Name: providerName, Service: e.Target}
			log.Trace("%s Calling EnsureDNSForRouterState(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err := domain.EnsureDNSForRouterState(realDomain, fqdnNoDot, state)
			if err != nil {
				log.Error("%s Failed to ensure DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
			}
		}
	}
	if p.recordRemoveOnStop {
		for key, old := range p.lastRecords {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				log.Info("%s Record removed: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
				log.Trace("%s Record removed from file: fqdn='%s', type='%s'", p.logPrefix, fqdnNoDot, recordType)
				domainKey, subdomain := common.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
				log.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s' (removal)", p.logPrefix, domainKey, subdomain, fqdnNoDot)
				if domainKey == "" {
					log.Error("%s No domain config found for '%s' (removal, tried to match domain from FQDN)", p.logPrefix, fqdnNoDot)
					continue
				}
				domainCfg, ok := config.GlobalConfig.Domains[domainKey]
				if !ok {
					log.Error("%s Domain '%s' not found in config for fqdn='%s' (removal)", p.logPrefix, domainKey, fqdnNoDot)
					continue
				}
				realDomain := domainCfg.Name
				log.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s') (removal)", p.logPrefix, realDomain, domainKey)
				providerName := p.options["name"]
				if providerName == "" {
					providerName = "file_profile"
				}
				state := domain.RouterState{SourceType: "file_profile", Name: providerName, Service: old.Target}
				log.Trace("%s Calling EnsureDNSRemoveForRouterState(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
				err := domain.EnsureDNSRemoveForRouterState(realDomain, fqdnNoDot, state)
				if err != nil {
					log.Error("%s Failed to remove DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
				}
			}
		}
	}
	p.mutex.Lock()
	p.lastRecords = current
	p.mutex.Unlock()
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
	log.Trace("%s Reading file: %s", p.logPrefix, p.source)
	data, err := os.ReadFile(p.source)
	if err != nil {
		log.Error("%s Error reading file: %v", p.logPrefix, err)
		return nil, err
	}
	var records []common.FileRecord
	if p.format == "yaml" {
		log.Trace("%s Parsing YAML file", p.logPrefix)
		records, err = common.ParseRecordsYAML(data)
		if err != nil {
			log.Error("%s YAML unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else if p.format == "json" {
		log.Trace("%s Parsing JSON file", p.logPrefix)
		records, err = common.ParseRecordsJSON(data)
		if err != nil {
			log.Error("%s JSON unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else {
		log.Error("%s Unsupported file format: %s", p.logPrefix, p.format)
		return nil, fmt.Errorf("unsupported file format: %s", p.format)
	}
	providerName := p.options["name"]
	if providerName == "" {
		providerName = "file_profile"
	}
	entries := common.ConvertRecordsToDNSEntries(records, providerName)
	log.Trace("%s Returning %d DNS entries from file", p.logPrefix, len(entries))
	return entries, nil
}

func init() {
	poll.RegisterProvider("file", NewProvider)
}
