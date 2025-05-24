package remote

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	pollCommon "dns-companion/pkg/poll/providers/pollCommon"

	"fmt"
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
	return &RemoteProvider{
		remoteURL: remoteURL,
		format:    format,
		interval:  parsed.Interval,
		opts:      parsed,
		logPrefix: logPrefix,
		options:   options,
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
	pollCommon.ProcessEntries(
		p.readRemote,
		&p.lastRecords,
		p.opts.Name,
		p.logPrefix,
		p.opts.RecordRemoveOnStop,
	)
}

func (p *RemoteProvider) readRemote() ([]poll.DNSEntry, error) {
	log.Debug("%s Fetching remote source: %s", p.logPrefix, p.remoteURL)
	httpUser := pollCommon.GetOptionOrEnv(p.options, "remote_auth_user", "REMOTE_AUTH_USER", "")
	httpPass := pollCommon.GetOptionOrEnv(p.options, "remote_auth_pass", "REMOTE_AUTH_PASS", "")
	data, err := pollCommon.FetchRemoteResource(p.remoteURL, httpUser, httpPass, p.logPrefix)
	if err != nil {
		log.Error("%v", err)
		return nil, err
	}
	log.Trace("%s Fetched %d bytes from %s", p.logPrefix, len(data), p.remoteURL)
	if p.format == "yaml" {
		log.Debug("%s Parsing as YAML", p.logPrefix)
	} else {
		log.Debug("%s Parsing as JSON", p.logPrefix)
	}
	var records []pollCommon.FileRecord
	if p.format == "yaml" {
		records, err = pollCommon.ParseRecordsYAML(data)
	} else {
		records, err = pollCommon.ParseRecordsJSON(data)
	}
	if err != nil {
		log.Error("%s Failed to parse %s as %s: %v", p.logPrefix, p.remoteURL, p.format, err)
		return nil, err
	}
	log.Debug("%s Parsed %d DNS records from remote source", p.logPrefix, len(records))
	entries := pollCommon.ConvertRecordsToDNSEntries(records, p.opts.Name)
	log.Trace("%s Returning %d DNS entries from remote", p.logPrefix, len(entries))
	return entries, nil
}

func init() {
	poll.RegisterProvider("remote", NewProvider)
}
