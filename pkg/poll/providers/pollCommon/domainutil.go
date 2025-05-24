// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/log"

	"regexp"
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

// ExtractHostsFromRule extracts all hostnames from a rule string (used by Docker, Traefik, etc.)
func ExtractHostsFromRule(rule string) []string {
	var hostnames []string
	// Regex to match Host(`...`), Host('...'), or Host("...")
	re := regexp.MustCompile(`Host\(\s*['"` + "`" + `](.*?)['"` + "`" + `]\s*\)`)
	matches := re.FindAllStringSubmatch(rule, -1)
	for _, match := range matches {
		if len(match) > 1 {
			hosts := strings.Split(match[1], ",")
			for _, h := range hosts {
				h = strings.TrimSpace(h)
				h = strings.Trim(h, "'\"` ")
				if h != "" {
					hostnames = append(hostnames, h)
				}
			}
		}
	}
	return hostnames
}
