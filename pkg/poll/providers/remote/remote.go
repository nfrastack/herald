package remote

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	"dns-companion/pkg/poll/providers/common"

	"fmt"
	"io"
	"net/http"
	"time"
)

type RemoteProvider struct {
	remoteURL   string
	format      string
	interval    time.Duration
	opts        common.PollProviderOptions
	running     bool
	lastRecords map[string]poll.DNSEntry
	logPrefix   string
	options     map[string]string
}

func NewProvider(options map[string]string) (poll.Provider, error) {
	parsed := common.ParsePollProviderOptions(options, common.PollProviderOptions{
		Interval:           60 * time.Second,
		ProcessExisting:    false,
		RecordRemoveOnStop: false,
		Name:               "remote",
	})
	remoteURL := options["remote_url"]
	if remoteURL == "" {
		return nil, fmt.Errorf("[poll/remote] remote_url option (URL) is required")
	}
	format := options["format"]
	if format == "" {
		if len(remoteURL) > 5 && remoteURL[len(remoteURL)-5:] == ".json" {
			format = "json"
		} else {
			format = "yaml"
		}
	}
	logPrefix := "[poll/remote/" + parsed.Name + "]"
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
	common.ProcessEntries(
		p.readRemote,
		&p.lastRecords,
		p.opts.Name,
		p.logPrefix,
		p.opts.RecordRemoveOnStop,
	)
}

func (p *RemoteProvider) readRemote() ([]poll.DNSEntry, error) {
	log.Debug("%s Fetching remote source: %s", p.logPrefix, p.remoteURL)
	client := &http.Client{}
	req, err := http.NewRequest("GET", p.remoteURL, nil)
	if err != nil {
		log.Error("%s HTTP request creation error for %s: %v", p.logPrefix, p.remoteURL, err)
		return nil, err
	}
	httpUser := p.options["remote_auth_user"]
	httpPass := p.options["remote_auth_pass"]
	if httpUser != "" {
		req.SetBasicAuth(httpUser, httpPass)
		log.Trace("%s Using HTTP Basic Auth for remote source", p.logPrefix)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("%s HTTP GET error for %s: %v", p.logPrefix, p.remoteURL, err)
		return nil, err
	}
	log.Debug("%s HTTP response code: %d for %s", p.logPrefix, resp.StatusCode, p.remoteURL)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 401 {
			log.Error("%s HTTP 401 Unauthorized: authentication required for %s", p.logPrefix, p.remoteURL)
		} else {
			log.Error("%s HTTP error: response code %d for %s", p.logPrefix, resp.StatusCode, p.remoteURL)
		}
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("%s Error reading response body: %v", p.logPrefix, err)
		return nil, err
	}
	log.Trace("%s Fetched %d bytes from %s", p.logPrefix, len(data), p.remoteURL)
	if p.format == "yaml" {
		log.Debug("%s Parsing as YAML", p.logPrefix)
	} else {
		log.Debug("%s Parsing as JSON", p.logPrefix)
	}
	var records []common.FileRecord
	if p.format == "yaml" {
		records, err = common.ParseRecordsYAML(data)
	} else {
		records, err = common.ParseRecordsJSON(data)
	}
	if err != nil {
		log.Error("%s Failed to parse %s as %s: %v", p.logPrefix, p.remoteURL, p.format, err)
		return nil, err
	}
	log.Debug("%s Parsed %d DNS records from remote source", p.logPrefix, len(records))
	entries := common.ConvertRecordsToDNSEntries(records, p.opts.Name)
	log.Trace("%s Returning %d DNS entries from remote", p.logPrefix, len(entries))
	return entries, nil
}

func init() {
	poll.RegisterProvider("remote", NewProvider)
}
