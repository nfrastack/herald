// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"encoding/json"
	"fmt"
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/util"
	"strings"
)

func BuildLogPrefix(providerType, profileName string) string {
	if profileName == "" {
		return fmt.Sprintf("[input/%s]", providerType)
	}
	return fmt.Sprintf("[input/%s/%s]", providerType, profileName)
}

func ReadFileValue(value string) string {
	return util.ReadSecretValue(value)
}

func ParseDomainList(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}

	if strings.HasPrefix(trimmed, "[") {
		var arr []string
		if err := json.Unmarshal([]byte(trimmed), &arr); err == nil {
			return dedupeDomains(arr)
		}
		trimmed = strings.TrimPrefix(strings.TrimSuffix(trimmed, "]"), "[")
	}

	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	return dedupeDomains(parts)
}

func dedupeDomains(domains []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, d := range domains {
		d = strings.TrimSpace(strings.Trim(d, `"'`))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func ExtractDomainAndSubdomain(hostname string) (domainKey, subdomain string) {
	if hostname == "" {
		return "", ""
	}

	hostname = strings.TrimSuffix(hostname, ".")

	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname, ""
	}

	for i := 0; i < len(parts)-1; i++ {
		potentialDomain := strings.Join(parts[i:], ".")
		potentialSubdomain := ""
		if i > 0 {
			potentialSubdomain = strings.Join(parts[:i], ".")
		}

		if configKey := findDomainConfigKey(potentialDomain); configKey != "" {
			return configKey, potentialSubdomain
		}
	}

	return hostname, ""
}

func findDomainConfigKey(domainName string) string {
	if config.GlobalConfig.Domains == nil {
		return ""
	}

	for configKey, domainConfig := range config.GlobalConfig.Domains {
		if domainConfig.Name == domainName {
			return configKey
		}
	}

	return ""
}
