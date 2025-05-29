package remote

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"fmt"
	"strings"
	"time"
)

type RemoteProvider struct {
	remoteURL   string
	format      string
	interval    time.Duration
	opts        pollCommon.PollProviderOptions
	running     bool
	lastRecords map[string]poll.DNSEntry
	logPrefix   string
	options     map[string]string
	logger      *log.ScopedLogger // provider-specific logger
}

func NewProvider(options map[string]string) (poll.Provider, error) {
	parsed := pollCommon.ParsePollProviderOptions(options, pollCommon.PollProviderOptions{
		Interval:           60 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "remote",
	})
	remoteURL := pollCommon.GetOptionOrEnv(options, "remote_url", "REMOTE_URL", "")
	if remoteURL == "" {
		return nil, fmt.Errorf("%s remote_url option (URL) is required", parsed.Name)
	}
	format := pollCommon.GetOptionOrEnv(options, "format", "REMOTE_FORMAT", "")
	if format == "" {
		if len(remoteURL) > 5 && remoteURL[len(remoteURL)-5:] == ".json" {
			format = "json"
		} else {
			format = "yaml"
		}
	}
	logPrefix := pollCommon.BuildLogPrefix("remote", parsed.Name)
	logLevel := options["log_level"] // Get provider-specific log level

	// Create scoped logger
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	// Only log override message if there's actually a log level override
	if logLevel != "" {
		log.Info("%s Provider log_level set to: '%s'", logPrefix, logLevel)
	}

	return &RemoteProvider{
		remoteURL: remoteURL,
		format:    format,
		interval:  parsed.Interval,
		opts:      parsed,
		logPrefix: logPrefix,
		options:   options,
		logger:    scopedLogger,
	}, nil
}

func (p *RemoteProvider) StartPolling() error {
	if p.running {
		return nil
	}
	if p.lastRecords == nil {
		p.lastRecords = make(map[string]poll.DNSEntry)
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

func (p *RemoteProvider) GetDNSEntries() ([]poll.DNSEntry, error) {
	return p.readRemote()
}

func (p *RemoteProvider) pollLoop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	if p.opts.ProcessExisting {
		log.Trace("%s Processing existing remote file on startup", p.logPrefix)
		p.processRemote()
	}
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
	current := make(map[string]poll.DNSEntry)

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
			domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
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

				domainKey, subdomain := pollCommon.ExtractDomainAndSubdomain(fqdnNoDot, p.logPrefix)
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

func (p *RemoteProvider) readRemote() ([]poll.DNSEntry, error) {
	log.Debug("%s Fetching remote source: %s", p.logPrefix, p.remoteURL)
	httpUser := pollCommon.GetOptionOrEnv(p.options, "remote_auth_user", "REMOTE_AUTH_USER", "")
	httpPass := pollCommon.GetOptionOrEnv(p.options, "remote_auth_pass", "REMOTE_AUTH_PASS", "")
	tlsVerifyStr := pollCommon.GetOptionOrEnv(p.options, "tls_verify", "REMOTE_TLS_VERIFY", "true")
	tlsVerify := strings.ToLower(tlsVerifyStr) != "false" && tlsVerifyStr != "0"

	if !tlsVerify {
		log.Debug("%s TLS certificate verification disabled", p.logPrefix)
	}

	data, err := pollCommon.FetchRemoteResourceWithTLS(p.remoteURL, httpUser, httpPass, nil, p.logPrefix, tlsVerify)
	if err != nil {
		log.Error("%v", err)
		return nil, err
	}
	log.Trace("%s Fetched %d bytes from %s", p.logPrefix, len(data), p.remoteURL)

	var records []pollCommon.FileRecord
	if p.format == "yaml" {
		log.Trace("%s Parsing YAML from remote", p.logPrefix)
		records, err = pollCommon.ParseRecordsYAML(data)
		if err != nil {
			log.Error("%s YAML unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else if p.format == "json" {
		log.Trace("%s Parsing JSON from remote", p.logPrefix)
		records, err = pollCommon.ParseRecordsJSON(data)
		if err != nil {
			log.Error("%s JSON unmarshal error: %v", p.logPrefix, err)
			return nil, err
		}
	} else if p.format == "hosts" {
		log.Trace("%s Parsing hosts file from remote", p.logPrefix)
		records, err = pollCommon.ParseHostsFile(data)
		if err != nil {
			log.Error("%s Hosts file parse error: %v", p.logPrefix, err)
			return nil, err
		}
	} else {
		log.Error("%s Unsupported remote file format: %s", p.logPrefix, p.format)
		return nil, fmt.Errorf("unsupported remote file format: %s", p.format)
	}
	entries := pollCommon.ConvertRecordsToDNSEntries(records, p.opts.Name)
	return entries, nil
}

func init() {
	poll.RegisterProvider("remote", NewProvider)
}
