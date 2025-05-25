// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/domain"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"

	"strings"
)

// ProcessEntries is a shared processing loop for poll providers (file, remote, etc.)
func ProcessEntries(
	fetchEntries func() ([]poll.DNSEntry, error),
	lastRecordsPtr *map[string]poll.DNSEntry,
	sourceType string,
	profileName string,
	recordRemoveOnStop bool,
) {
	entries, err := fetchEntries()
	if err != nil {
		log.Error("%s Failed to fetch entries: %v", profileName, err)
		return
	}
	log.Debug("%s Processing %d DNS entries", profileName, len(entries))
	current := make(map[string]poll.DNSEntry)
	for _, e := range entries {
		fqdn := e.GetFQDN()
		recordType := e.GetRecordType()
		key := fqdn + ":" + recordType
		current[key] = e
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		if _, ok := (*lastRecordsPtr)[key]; !ok {
			log.Info("%s New record detected: %s (%s)", profileName, fqdnNoDot, recordType)
			domainKey, subdomain := ExtractDomainAndSubdomain(fqdnNoDot, profileName)
			log.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s'", profileName, domainKey, subdomain, fqdnNoDot)
			if domainKey == "" {
				log.Error("%s No domain config found for '%s' (tried to match domain from FQDN)", profileName, fqdnNoDot)
				continue
			}
			domainCfg, ok := config.GlobalConfig.Domains[domainKey]
			if !ok {
				log.Error("%s Domain '%s' not found in config for fqdn='%s'", profileName, domainKey, fqdnNoDot)
				continue
			}
			realDomain := domainCfg.Name
			log.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s')", profileName, realDomain, domainKey)
			state := domain.RouterState{SourceType: sourceType, Name: profileName, Service: e.Target}
			log.Trace("%s Calling EnsureDNSForRouterState(domain='%s', fqdn='%s', state=%+v)", profileName, realDomain, fqdnNoDot, state)
			err := domain.EnsureDNSForRouterState(realDomain, fqdnNoDot, state)
			if err != nil {
				log.Error("%s Failed to ensure DNS for '%s': %v", profileName, fqdnNoDot, err)
			}
		}
	}
	if recordRemoveOnStop {
		for key, old := range *lastRecordsPtr {
			if _, ok := current[key]; !ok {
				fqdn := old.GetFQDN()
				fqdnNoDot := strings.TrimSuffix(fqdn, ".")
				recordType := old.GetRecordType()
				log.Info("%s Record removed: %s (%s)", profileName, fqdnNoDot, recordType)
				domainKey, subdomain := ExtractDomainAndSubdomain(fqdnNoDot, profileName)
				log.Trace("%s Extracted domainKey='%s', subdomain='%s' from fqdn='%s' (removal)", profileName, domainKey, subdomain, fqdnNoDot)
				if domainKey == "" {
					log.Error("%s No domain config found for '%s' (removal, tried to match domain from FQDN)", profileName, fqdnNoDot)
					continue
				}
				domainCfg, ok := config.GlobalConfig.Domains[domainKey]
				if !ok {
					log.Error("%s Domain '%s' not found in config for fqdn='%s' (removal)", profileName, domainKey, fqdnNoDot)
					continue
				}
				realDomain := domainCfg.Name
				log.Trace("%s Using real domain name '%s' for DNS provider (configKey='%s') (removal)", profileName, realDomain, domainKey)
				state := domain.RouterState{SourceType: sourceType, Name: profileName, Service: old.Target}
				log.Trace("%s Calling EnsureDNSRemoveForRouterState(domain='%s', fqdn='%s', state=%+v)", profileName, realDomain, fqdnNoDot, state)
				err := domain.EnsureDNSRemoveForRouterState(realDomain, fqdnNoDot, state)
				if err != nil {
					log.Error("%s Failed to remove DNS for '%s': %v", profileName, fqdnNoDot, err)
				}
			}
		}
	}
	*lastRecordsPtr = current
}
