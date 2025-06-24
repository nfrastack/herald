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
	remoteURL    string
	format       string
	interval     time.Duration
	opts         common.PollProviderOptions
	running      bool
	lastRecords  map[string]DNSEntry
	logPrefix    string
	options      map[string]string
	filterConfig common.FilterConfig
	logger       *log.ScopedLogger
	name         string
}

func NewProvider(options map[string]string) (Provider, error) {
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
	filterConfig, err := common.NewFilterFromStructuredOptions(structuredOptions)
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
		log.Error("%s Failed to read remote: %v", p.logPrefix, err)
		return
	}
	log.Verbose("%s Processing %d DNS entries from remote", p.logPrefix, len(entries))

	// Create batch processor for efficient sync handling
	batchProcessor := domain.NewBatchProcessor(p.logPrefix)
	current := make(map[string]DNSEntry)

	for _, e := range entries {
		fqdn := e.GetFQDN()
		recordType := e.GetRecordType()
		key := fqdn + ":" + recordType
		current[key] = e
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		if _, ok := p.lastRecords[key]; !ok {
			if isInitialLoad {
				log.Info("%s Initial record detected: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			} else {
				log.Info("%s New record detected: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			}

			// Extract domain and subdomain
			providerName := p.opts.Name
			domainKey, subdomain := config.ExtractDomainAndSubdomainForProvider(fqdnNoDot, providerName, p.logPrefix)
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

			providerName = p.options["name"]
			if providerName == "" {
				providerName = "remote_profile"
			}

			state := domain.RouterState{
				SourceType: "remote_profile",
				Name:       providerName,
				Service:    e.Target,
				RecordType: recordType,
			}

			log.Trace("%s Calling ProcessRecord(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
			if err != nil {
				log.Error("%s Failed to ensure DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
			}
		}
	}

	if p.opts.RecordRemoveOnStop {
		for key, old := range p.lastRecords {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				log.Info("%s Record removed: %s (%s)", p.logPrefix, fqdnNoDot, recordType)

				providerName := p.opts.Name
				domainKey, subdomain := config.ExtractDomainAndSubdomainForProvider(fqdnNoDot, providerName, p.logPrefix)
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

				providerName = p.options["name"]
				if providerName == "" {
					providerName = "remote_profile"
				}

				state := domain.RouterState{
					SourceType: "remote_profile",
					Name:       providerName,
					Service:    old.Target,
					RecordType: recordType,
				}

				log.Trace("%s Calling ProcessRecordRemoval(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
				err := batchProcessor.ProcessRecordRemoval(realDomain, fqdnNoDot, state)
				if err != nil {
					log.Error("%s Failed to remove DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
				}
			}
		}
	}

	p.lastRecords = current

	// Finalize the batch - this will sync output files only if there were changes
	batchProcessor.FinalizeBatch()
}

func (p *RemoteProvider) readRemote() ([]DNSEntry, error) {
	log.Debug("%s Fetching remote source: %s", p.logPrefix, p.remoteURL)
	httpUser := common.ReadFileValue(p.options["remote_auth_user"])
	httpPass := common.ReadFileValue(p.options["remote_auth_pass"])

	// Parse TLS configuration using common utilities
	tlsConfig := common.ParseTLSConfigFromOptions(p.options)

	// Log TLS configuration details
	if !tlsConfig.Verify {
		log.Debug("%s TLS certificate verification disabled", p.logPrefix)
	}
	if tlsConfig.CA != "" {
		log.Debug("%s Using custom CA certificate: %s", p.logPrefix, tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		log.Debug("%s Using client certificate authentication", p.logPrefix)
	}

	data, err := common.FetchRemoteResourceWithTLSConfig(p.remoteURL, httpUser, httpPass, nil, &tlsConfig, p.logPrefix)
	if err != nil {
		log.Error("%v", err)
		return nil, err
	}
	log.Trace("%s Fetched %d bytes from %s", p.logPrefix, len(data), p.remoteURL)

	var records []common.FileRecord
	if p.format == "yaml" {
		log.Trace("%s Parsing YAML from remote", p.logPrefix)
		records, err = common.ParseRecordsYAML(data)
		if err != nil {
			log.Error("%s YAML unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else if p.format == "json" {
		log.Trace("%s Parsing JSON from remote", p.logPrefix)
		records, err = common.ParseRecordsJSON(data)
		if err != nil {
			log.Error("%s JSON unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else if p.format == "hosts" {
		log.Trace("%s Parsing hosts file from remote", p.logPrefix)
		records, err = parsers.ParseHostsFile(data)
		if err != nil {
			log.Error("%s Hosts file parse error: %v", p.logPrefix, err)
			return nil, err
		}
	} else {
		log.Error("%s Unsupported remote file format: %s", p.logPrefix, p.format)
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
