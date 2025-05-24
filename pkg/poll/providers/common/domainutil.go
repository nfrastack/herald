package common

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/log"

	"strings"
)

// ExtractDomainAndSubdomain tries to find the best matching domain from config and returns (domain, subdomain)
func ExtractDomainAndSubdomain(fqdn string, logPrefix string) (string, string) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	labels := strings.Split(fqdn, ".")
	log.Trace("%s extractDomainAndSubdomain: FQDN='%s', labels=%v", logPrefix, fqdn, labels)
	for i := 0; i < len(labels); i++ {
		domainCandidate := strings.Join(labels[i:], ".")
		normalizedCandidate := NormalizeDomainKey(domainCandidate)
		for configKey := range config.GlobalConfig.Domains {
			if normalizedCandidate == configKey {
				subdomain := strings.Join(labels[:i], ".")
				if subdomain == "" {
					subdomain = "@"
				}
				log.Trace("%s extractDomainAndSubdomain: matched domain configKey='%s' for candidate='%s' (normalized='%s')", logPrefix, configKey, domainCandidate, normalizedCandidate)
				return configKey, subdomain
			}
		}
	}
	log.Trace("%s extractDomainAndSubdomain: no match for FQDN='%s'", logPrefix, fqdn)
	return "", ""
}

// NormalizeDomainKey replaces dots with underscores for config key matching
func NormalizeDomainKey(domain string) string {
	return strings.ReplaceAll(domain, ".", "_")
}
