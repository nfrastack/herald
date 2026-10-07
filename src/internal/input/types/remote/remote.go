// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input/common"
	"github.com/nfrastack/herald/internal/input/types/file/parsers"
	"github.com/nfrastack/herald/internal/log"

	"fmt"
	"strings"
	"time"
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

	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	if logLevel != "" {
		scopedLogger.With("action", "provider.init").Info("log_level set to: '%s'", logLevel)
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
	if p.opts.ProcessExisting {
		p.logger.With("action", "input.load").Trace("existing remote records on startup (process_existing=true)")
		p.processRemote()
	} else {
		p.logger.With("action", "provider.poll").Trace("on startup (process_existing=false), inventory only, no processing")
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
		p.logger.With("action", "input.load").Error("remote: %v", err)
		return
	}
	p.logger.With("action", "input.load").Verbose("%d DNS entries from remote", len(entries))

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
				p.logger.With("action", "record.create", "fqdn", fqdnNoDot).Info("(%s)", recordType)
			} else {
				p.logger.With("action", "record.create", "fqdn", fqdnNoDot).Info("(%s)", recordType)
			}

			realDomain := p.getParentDomainForFQDN(fqdnNoDot)
			p.logger.With("action", "domain.match").Trace("real domain name '%s' for DNS provider", realDomain)

			state := domain.RouterState{
				SourceType: "remote_profile",
				Name:       providerName,
				Service:    e.Target,
				RecordType: recordType,
			}

			p.logger.With("action", "record.create", "domain", realDomain, "fqdn", fqdnNoDot).Trace("ProcessRecord: %+v", state)
			err := batchProcessor.ProcessRecord(realDomain, fqdnNoDot, state)
			if err != nil {
				p.logger.With("action", "sync.fail", "fqdn", fqdnNoDot).Error("ensuring DNS: %v", err)
			}
		}
	}

	if p.opts.RecordRemoveOnStop {
		for key, old := range p.lastRecords {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				p.logger.With("action", "record.delete", "fqdn", fqdnNoDot).Info("removed (%s)", recordType)

				realDomain := p.getParentDomainForFQDN(fqdnNoDot)
				p.logger.With("action", "domain.match").Trace("real domain name '%s' for DNS provider (removal)", realDomain)

				state := domain.RouterState{
					SourceType: "remote_profile",
					Name:       providerName,
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

	p.lastRecords = current

	batchProcessor.FinalizeBatch()
}

func (p *RemoteProvider) readRemote() ([]DNSEntry, error) {
	p.logger.With("action", "input.load").Debug("remote source: %s", p.remoteURL)
	httpUser := common.ReadFileValue(p.options["remote_auth_user"])
	httpPass := common.ReadFileValue(p.options["remote_auth_pass"])

	tlsConfig := common.ParseTLSConfigFromOptions(p.options)

	if !tlsConfig.Verify {
		p.logger.With("action", "tls.skip").Debug("certificate verification disabled")
	}
	if tlsConfig.CA != "" {
		p.logger.With("action", "tls.load").Debug("custom CA certificate: %s", tlsConfig.CA)
	}
	if tlsConfig.Cert != "" && tlsConfig.Key != "" {
		p.logger.With("action", "tls.load").Debug("client certificate authentication")
	}

	data, err := common.FetchRemoteResourceWithTLSConfig(p.remoteURL, httpUser, httpPass, nil, &tlsConfig, p.logPrefix)
	if err != nil {
		p.logger.With("action", "sync.fail").Error("%v", err)
		return nil, err
	}
	p.logger.With("action", "input.load").Trace("%d bytes from %s", len(data), p.remoteURL)

	var records []common.FileRecord
	if p.format == "yaml" {
		p.logger.With("action", "input.load").Trace("YAML from remote")
		records, err = common.ParseRecordsYAML(data)
		if err != nil {
			p.logger.With("action", "config.error").Error("unmarshal error: %v", err)
			return nil, err
		}
	} else if p.format == "json" {
		p.logger.With("action", "input.load").Trace("JSON from remote")
		records, err = common.ParseRecordsJSON(data)
		if err != nil {
			p.logger.With("action", "config.error").Error("unmarshal error: %v", err)
			return nil, err
		}
	} else if p.format == "hosts" {
		p.logger.With("action", "input.load").Trace("hosts file from remote")
		records, err = parsers.ParseHostsFile(data)
		if err != nil {
			p.logger.With("action", "config.error").Error("parse error: %v", err)
			return nil, err
		}
	} else {
		p.logger.With("action", "config.error").Error("remote file format: %s", p.format)
		return nil, fmt.Errorf("unsupported remote file format: %s", p.format)
	}
	entries := common.ConvertRecordsToDNSEntries(records, p.opts.Name)

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

func (rp *RemoteProvider) GetName() string {
	return "remote"
}

func (p *RemoteProvider) SetDomainConfigs(domainConfigs map[string]config.DomainConfig) {
	p.domainConfigs = domainConfigs
}

func (p *RemoteProvider) getParentDomainForFQDN(fqdn string) string {
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
