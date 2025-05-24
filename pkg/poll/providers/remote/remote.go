package remote

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"
	"dns-companion/pkg/poll/providers/common"

	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type RemoteProvider struct {
	remoteURL   string
	format      string
	interval    time.Duration
	options     map[string]string
	running     bool
	lastRecords map[string]poll.DNSEntry
	logPrefix   string
}

func NewProvider(options map[string]string) (poll.Provider, error) {
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
	interval := 60 * time.Second
	if v := options["interval"]; v != "" {
		intervalStr := v
		if _, err := time.ParseDuration(intervalStr); err != nil {
			// If no unit, assume seconds
			if _, err2 := time.ParseDuration(intervalStr + "s"); err2 == nil {
				intervalStr = intervalStr + "s"
			}
		}
		if d, err := time.ParseDuration(intervalStr); err == nil {
			interval = d
		}
	}
	providerName := options["name"]
	if providerName == "" {
		providerName = "remote"
	}
	logPrefix := "[poll/remote/" + providerName + "]"
	return &RemoteProvider{
		remoteURL: remoteURL,
		format:    format,
		interval:  interval,
		options:   options,
		logPrefix: logPrefix,
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
	if p.options["process_existing"] == "true" {
		log.Trace("%s Processing existing remote file on startup", p.logPrefix)
		p.processRemote()
	}
	for p.running {
		<-ticker.C
		p.processRemote()
	}
}

func (p *RemoteProvider) processRemote() {
	entries, err := p.readRemote()
	if err != nil {
		log.Error("%s Failed to read remote: %v", p.logPrefix, err)
		return
	}
	log.Debug("%s Processing %d DNS entries from remote", p.logPrefix, len(entries))
	current := make(map[string]poll.DNSEntry)
	for _, e := range entries {
		fqdn := e.GetFQDN()
		recordType := e.GetRecordType()
		key := fqdn + ":" + recordType
		current[key] = e
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		if _, ok := p.lastRecords[key]; !ok {
			log.Info("%s New record detected: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			// Call domain logic to add/update DNS
			domainKey, subdomain := extractDomainAndSubdomain(fqdnNoDot)
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
				providerName = "remote"
			}
			state := domain.RouterState{SourceType: "remote", Name: providerName, Service: e.Target}
			log.Trace("%s Calling EnsureDNSForRouterState(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err := domain.EnsureDNSForRouterState(realDomain, fqdnNoDot, state)
			if err != nil {
				log.Error("%s Failed to ensure DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
			}
		}
	}
	for key, old := range p.lastRecords {
		if _, ok := current[key]; !ok {
			fqdn := old.GetFQDN()
			fqdnNoDot := strings.TrimSuffix(fqdn, ".")
			recordType := old.GetRecordType()
			log.Info("%s Record removed: %s (%s)", p.logPrefix, fqdnNoDot, recordType)
			domainKey, subdomain := extractDomainAndSubdomain(fqdnNoDot)
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
				providerName = "remote"
			}
			state := domain.RouterState{SourceType: "remote", Name: providerName, Service: old.Target}
			log.Trace("%s Calling EnsureDNSRemoveForRouterState(domain='%s', fqdn='%s', state=%+v)", p.logPrefix, realDomain, fqdnNoDot, state)
			err := domain.EnsureDNSRemoveForRouterState(realDomain, fqdnNoDot, state)
			if err != nil {
				log.Error("%s Failed to remove DNS for '%s': %v", p.logPrefix, fqdnNoDot, err)
			}
		}
	}
	p.lastRecords = current
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
	providerName := p.options["name"]
	if providerName == "" {
		providerName = "remote"
	}
	entries := common.ConvertRecordsToDNSEntries(records, providerName)
	log.Trace("%s Returning %d DNS entries from remote", p.logPrefix, len(entries))
	return entries, nil
}

func extractDomainAndSubdomain(fqdn string) (string, string) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	labels := strings.Split(fqdn, ".")
	for i := 0; i < len(labels); i++ {
		domainCandidate := strings.Join(labels[i:], ".")
		normalizedCandidate := strings.ReplaceAll(domainCandidate, ".", "_")
		for configKey := range config.GlobalConfig.Domains {
			if normalizedCandidate == configKey {
				subdomain := strings.Join(labels[:i], ".")
				if subdomain == "" {
					subdomain = "@"
				}
				return configKey, subdomain
			}
		}
	}
	return "", ""
}

func init() {
	poll.RegisterProvider("remote", NewProvider)
}
