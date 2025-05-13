package domain

import (
	"fmt"
	"regexp"
	"strings"

	"container-dns-companion/pkg/config"
)

// Domain represents a domain configuration
type Domain struct {
	DomainKey              string
	Name                   string
	Provider               string
	TTL                    int
	TargetDomain           string
	ExcludedSubDomains     []string
	UpdateExisting         bool
	RecordTypeAMultiple    bool
	RecordTypeAAAAMultiple bool
	ProviderOptions        map[string]string
}

// DomainConfig represents global domain configuration settings
type DomainConfig struct {
	TTL            int
	CreateMissing  bool
	UpdateExisting bool
	DeleteOrphaned bool
}

// LoadDomainsFromEnv loads domain configurations from environment variables
func LoadDomainsFromEnv() ([]Domain, error) {
	var domains []Domain

	// Find all environment variables that match DOMAINX, DOMAIN1, DOMAIN2, etc.
	domainPattern := regexp.MustCompile(`^DOMAIN(\d+)$`)

	for envKey, envValue := range config.EnvCache {
		matches := domainPattern.FindStringSubmatch(envKey)
		if len(matches) != 2 {
			continue
		}

		domainKey := envKey
		domainNumber := matches[1]

		// Parse domain configuration
		domain := Domain{
			DomainKey:              domainKey,
			Name:                   envValue,
			Provider:               config.GetEnvVar(fmt.Sprintf("DOMAIN%s_PROVIDER", domainNumber), config.GetEnvVar("PROVIDER", "cloudflare")),
			TTL:                    config.EnvToInt(fmt.Sprintf("DOMAIN%s_TTL", domainNumber), 120),
			TargetDomain:           config.GetEnvVar(fmt.Sprintf("DOMAIN%s_TARGET_DOMAIN", domainNumber), ""),
			UpdateExisting:         config.EnvToBool(fmt.Sprintf("DOMAIN%s_UPDATE_EXISTING", domainNumber), true),
			RecordTypeAMultiple:    config.EnvToBool(fmt.Sprintf("DOMAIN%s_RECORD_TYPE_A_MULTIPLE", domainNumber), false),
			RecordTypeAAAAMultiple: config.EnvToBool(fmt.Sprintf("DOMAIN%s_RECORD_TYPE_AAAA_MULTIPLE", domainNumber), false),
			ProviderOptions:        make(map[string]string),
		}

		// Check if target domain is set
		if domain.TargetDomain == "" {
			return nil, fmt.Errorf("DOMAIN%s_TARGET_DOMAIN is required", domainNumber)
		}

		// Load excluded subdomains
		excludedSubDomains := config.GetEnvVar(fmt.Sprintf("DOMAIN%s_EXCLUDED_SUBDOMAINS", domainNumber), "")
		if excludedSubDomains != "" {
			domain.ExcludedSubDomains = strings.Split(excludedSubDomains, ",")
			for i, subdomain := range domain.ExcludedSubDomains {
				domain.ExcludedSubDomains[i] = strings.TrimSpace(subdomain)
			}
		}

		// Load provider options
		providerOptionPrefix := fmt.Sprintf("DOMAIN%s_PROVIDER_", domainNumber)
		for k, v := range config.EnvCache {
			if strings.HasPrefix(k, providerOptionPrefix) {
				optionKey := strings.ToLower(strings.TrimPrefix(k, providerOptionPrefix))
				domain.ProviderOptions[optionKey] = v
			}
		}

		// Ensure domain name is present
		if domain.ProviderOptions["domain"] == "" {
			domain.ProviderOptions["domain"] = domain.Name
		}

		domains = append(domains, domain)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains configured")
	}

	return domains, nil
}

// IsDomainExcluded checks if a hostname should be excluded
func IsDomainExcluded(hostname string, domain Domain) bool {
	for _, excludedSubDomain := range domain.ExcludedSubDomains {
		if strings.HasPrefix(hostname, excludedSubDomain+".") {
			return true
		}
	}
	return false
}

// GetDomainConfig returns the configuration for domain updates
func GetDomainConfig() DomainConfig {
	return DomainConfig{
		TTL:            config.EnvToInt("DOMAIN_TTL", 300),
		CreateMissing:  config.EnvToBool("DOMAIN_CREATE_MISSING", true),
		UpdateExisting: config.EnvToBool("DOMAIN_UPDATE_EXISTING", true),
		DeleteOrphaned: config.EnvToBool("DOMAIN_DELETE_ORPHANED", false),
	}
}
