// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"herald/pkg/config"
	"herald/pkg/domain"
	"herald/pkg/input/common"
	"herald/pkg/input/types/file/parsers"
	"herald/pkg/log"

	"fmt"
	"strings"
	"time"
)

type Provider interface {
	StartPolling() error
	StopPolling() error
	GetName() string
}

// DNSEntry represents a DNS entry from input providers - local definition
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

type RemoteProvider struct {
	remoteURL     string
	format        string
	interval      time.Duration
	opts          common.PollProviderOptions
	running       bool
	lastRecords   map[string]DNSEntry
	logPrefix     string
	options       map[string]string
	filterConfig  common.FilterConfig
	logger        *log.ScopedLogger
	name          string                         // Profile name
	outputWriter  domain.OutputWriter            // Injected dependency
	outputSyncer  domain.OutputSyncer            // Injected dependency
	domainConfigs map[string]config.DomainConfig // Add domain configs for domain matching
}

func NewProvider(options map[string]string, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (Provider, error) {
	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           60 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "remote",
	})
	remoteURL := common.ReadFileValue(options["url"])
	if remoteURL == "" {
		remoteURL = common.ReadFileValue(options["remote_url"])
	}
	if remoteURL == "" {
		return nil, fmt.Errorf("%s remote_url option (URL) is required", parsed.Name)
	}
	format := common.ReadFileValue(options["format"])
	if format == "" {
		if len(remoteURL) > 5 && remoteURL[len(remoteURL)-5:] == ".json" {
			format = "json"
		} else {
			format = "yaml"
		}
	}
	logPrefix := common.BuildLogPrefix("remote", parsed.Name)
	logLevel := options["log_level"]

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

	// Create scoped logger
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	return &RemoteProvider{
		remoteURL:    remoteURL,
		format:       format,
		interval:     parsed.Interval,
		opts:         parsed,
		logPrefix:    logPrefix,
		options:      options,
		filterConfig: filterConfig,
		logger:       scopedLogger,
		outputWriter: outputWriter,
		outputSyncer: outputSyncer,
	}, nil
}

func (p *RemoteProvider) StartPolling() error {
	if p.running {
		return nil
	}
	if p.lastRecords == nil {
		p.lastRecords = make(map[string]DNSEntry)
	}
	p.running = true
	go p.pollLoop()
	return nil
}

func (p *RemoteProvider) StopPolling() error {
	p.running = false
	return nil
}

func (p *RemoteProvider) IsRunning() bool {
	return p.running
}

func (p *RemoteProvider) GetDNSEntries() ([]DNSEntry, error) {
	return p.readRemote()
}

func (p *RemoteProvider) pollLoop() {
	// Always perform an initial poll immediately on startup
	if p.opts.ProcessExisting {
		p.logger.Trace("Processing existing remote records on startup (process_existing=true)")
		p.processRemote()
	} else {
		p.logger.Trace("Initial poll on startup (process_existing=false), inventory only, no processing")
		entries, err := p.readRemote()
		if err == nil {
			current := make(map[string]DNSEntry)
			for _, e := range entries {
				fqdn := e.GetFQDN()
				recordType := e.GetRecordType()
				key := fqdn + ":" + recordType
				current[key] = e
			}
			p.lastRecords = current
		}
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for p.running {
		<-ticker.C
		p.processRemote()
	}
}

func (p *RemoteProvider) processRemote() {
	isInitialLoad := len(p.lastRecords) == 0
	entries, err := p.readRemote()
	if err != nil {
		p.logger.Error("Failed to read remote: %v", err)
		return
	}
	p.logger.Verbose("Processing %d DNS entries from remote", len(entries))

	// Set the provider name for batch processor
	providerName := p.name
	if providerName == "" {
		providerName = p.options["name"]
		if providerName == "" {
			providerName = "remote_profile"
		}
	}
	batchProcessor := domain.NewBatchProcessorWithProvider(p.logPrefix, providerName, p.outputWriter, p.outputSyncer)
	current := make(map[string]DNSEntry)

	for _, e := range entries {
		fqdn := e.GetFQDN()
		recordType := e.GetRecordType()
		key := fqdn + ":" + recordType
		current[key] = e
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		if _, ok := p.lastRecords[key]; !ok {
			if isInitialLoad {
				p.logger.Info("Initial record detected: %s (%s)", fqdnNoDot, recordType)
			} else {
				p.logger.Info("New record detected: %s (%s)", fqdnNoDot, recordType)
			}

			// Use helper to get parent domain for correct domain config matching
			realDomain := p.getParentDomainForFQDN(fqdnNoDot)
			p.logger.Trace("Using real domain name '%s' for DNS provider", realDomain)

			state := domain.RouterState{
				SourceType: "remote_profile",
				Name:       providerName,
				Service:    e.Target,
				RecordType: recordType,
			}

			p.logger.Trace("Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
			if err != nil {
				p.logger.Error("Failed to ensure DNS for '%s': %v", fqdnNoDot, err)
			}
		}
	}

	if p.opts.RecordRemoveOnStop {
		for key, old := range p.lastRecords {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				p.logger.Info("Record removed: %s (%s)", fqdnNoDot, recordType)

				// Use helper to get parent domain for correct domain config matching
				realDomain := p.getParentDomainForFQDN(fqdnNoDot)
				p.logger.Trace("Using real domain name '%s' for DNS provider (removal)", realDomain)

				state := domain.RouterState{
					SourceType: "remote_profile",
					Name:       providerName,
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

	p.lastRecords = current

	// Finalize the batch - this will sync output files only if there were changes
	batchProcessor.FinalizeBatch()
}

func (p *RemoteProvider) readRemote() ([]DNSEntry, error) {
	p.logger.Debug("Fetching remote source: %s", p.remoteURL)
	httpUser := common.ReadFileValue(p.options["remote_auth_user"])
	httpPass := common.ReadFileValue(p.options["remote_auth_pass"])

	// Parse TLS configuration using common utilities
	tlsConfig := common.ParseTLSConfigFromOptions(p.options)

	// Log TLS configuration details
	if !tlsConfig.Verify {
		p.logger.Debug("TLS certificate verification disabled")
	}
	if tlsConfig.CA != "" {
		p.logger.Debug("Using custom CA certificate: %s", tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		p.logger.Debug("Using client certificate authentication")
	}

	data, err := common.FetchRemoteResourceWithTLSConfig(p.remoteURL, httpUser, httpPass, nil, &tlsConfig, p.logPrefix)
	if err != nil {
		p.logger.Error("%v", err)
		return nil, err
	}
	p.logger.Trace("Fetched %d bytes from %s", len(data), p.remoteURL)

	var records []common.FileRecord
	if p.format == "yaml" {
		p.logger.Trace("Parsing YAML from remote")
		records, err = common.ParseRecordsYAML(data)
		if err != nil {
			p.logger.Error("YAML unmarshal error: %v", err)
			return nil, err
		}
	} else if p.format == "json" {
		p.logger.Trace("Parsing JSON from remote")
		records, err = common.ParseRecordsJSON(data)
		if err != nil {
			p.logger.Error("JSON unmarshal error: %v", err)
			return nil, err
		}
	} else if p.format == "hosts" {
		p.logger.Trace("Parsing hosts file from remote")
		records, err = parsers.ParseHostsFile(data)
		if err != nil {
			p.logger.Error("Hosts file parse error: %v", err)
			return nil, err
		}
	} else {
		p.logger.Error("Unsupported remote file format: %s", p.format)
		return nil, fmt.Errorf("unsupported remote file format: %s", p.format)
	}
	entries := common.ConvertRecordsToDNSEntries(records, p.opts.Name)

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
func (rp *RemoteProvider) GetName() string {
	return "remote"
}

// SetDomainConfigs allows injection of loaded domain configs (like Docker/Caddy/File)
func (p *RemoteProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

// Helper to find the best matching domain config by suffix match on the 'name' field
func (p *RemoteProvider) getParentDomainForFQDN(fqdn string) string {
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
