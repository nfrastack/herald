package domain

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/dns"
	"dns-companion/pkg/log"
	"dns-companion/pkg/utils"

	"fmt"
	"net"
	"strconv"
	"strings"
)

type RouterState struct {
	Name        string
	Rule        string
	EntryPoints []string
	Service     string
	SourceType  string // e.g. "container", "router", etc.
}

// EnsureDNSForRouterState merges config, validates, and performs DNS add/update for a router event
func EnsureDNSForRouterState(domain, fqdn string, state RouterState) error {
	logPrefix := fmt.Sprintf("[domain/%s]", domain)

	// Print all provider keys and their options at this point
	if len(config.GlobalConfig.Providers) == 0 {
		log.Warn("%s Providers map is EMPTY at EnsureDNSForRouterState", logPrefix)
	} else {
		for k, v := range config.GlobalConfig.Providers {
			log.Trace("%s Provider key: %s, Options: %+v", logPrefix, k, v.Options)
		}
	}

	domainConfig := config.GetDomainConfig(domain)
	if domainConfig == nil {
		log.Error("%s No domain config found for '%s'", logPrefix, fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}
	log.Trace("%s domainConfig: %+v", logPrefix, domainConfig)
	providerKey := domainConfig["provider"]
	if providerKey == "" {
		log.Error("%s No provider specified for domain '%s' (hostname: %s)", logPrefix, domain, fqdn)
		return fmt.Errorf("no provider for domain %s", domain)
	}
	log.Trace("%s Looking up provider config for key: '%s'", logPrefix, providerKey)
	providerCfg, ok := config.GlobalConfig.Providers[providerKey]
	if !ok {
		log.Error("%s No provider config found for key '%s' (domain: %s)", logPrefix, providerKey, domain)
		// Get keys from map[string]config.DNSProviderConfig
		providerKeys := make([]string, 0, len(config.GlobalConfig.Providers))
		for k := range config.GlobalConfig.Providers {
			providerKeys = append(providerKeys, k)
		}
		log.Trace("%s Available provider keys: %v", logPrefix, providerKeys)
		return fmt.Errorf("no provider config for %s", providerKey)
	}
	log.Trace("%s providerCfg.Options: %+v", logPrefix, providerCfg.Options)
	// Merge provider options and domain config
	providerOptions := providerCfg.GetOptions()
	for k, v := range domainConfig {
		providerOptions[k] = v
	}
	// Mask sensitive values before logging
	maskedProviderOptions := utils.MaskSensitiveOptions(providerOptions)
	log.Trace("%s Merged providerOptions: %v", logPrefix, maskedProviderOptions)

	// Check for required secrets
	missingSecrets := []string{}
	for _, key := range []string{"api_token", "api_key", "api_email"} {
		if v, ok := providerOptions[key]; !ok || v == "" {
			missingSecrets = append(missingSecrets, key)
		}
	}

	recordType := providerOptions["type"]
	target := providerOptions["target"]
	if state.Service != "" {
		target = state.Service
	}
	// Smart record type detection if not explicitly set
	if recordType == "" {
		if ip := net.ParseIP(target); ip != nil {
			if ip.To4() != nil {
				recordType = "A"
			} else {
				recordType = "AAAA"
			}
		} else {
			recordType = "CNAME"
		}
	}
	ttl := 60
	if v, ok := providerOptions["ttl"]; ok && v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			ttl = parsed
		}
	}
	overwrite := true
	if v, ok := providerOptions["update_existing"]; ok && v != "" {
		overwrite = v == "true" || v == "1"
	}
	// Use the subdomain part for the hostname
	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}
	log.Debug("%s DNS params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d, update=%v, container=%s", logPrefix, domain, recordType, hostname, target, ttl, overwrite, state.Name)

	dnsProvider, err := dns.LoadProviderFromConfig(providerKey, providerOptions)
	if err != nil {
		log.Error("%s Failed to load DNS provider '%s': %v", logPrefix, providerKey, err)
		return err
	}
	if cfProvider, ok := dnsProvider.(interface {
		CreateOrUpdateRecordWithSource(string, string, string, string, int, bool, string, string) error
	}); ok {
		err = cfProvider.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, overwrite, state.Name, state.SourceType)
		// If no error, assume created/updated (provider logs the real action)
	} else {
		err = dnsProvider.CreateOrUpdateRecord(domain, recordType, hostname, target, ttl, overwrite)
	}
	if err != nil {
		return err
	}
	label := state.SourceType
	if label == "" {
		label = "container"
	}
	return nil
}

// EnsureDNSRemoveForRouterState removes DNS records for a router event
func EnsureDNSRemoveForRouterState(domain, fqdn string, state RouterState) error {
	logPrefix := fmt.Sprintf("[domain/%s]", domain)
	log.Debug("%s Removing DNS for FQDN: %s | RouterState: %+v", logPrefix, fqdn, state)

	domainConfig := config.GetDomainConfig(domain)
	if domainConfig == nil {
		log.Error("%s No domain config found for '%s'", logPrefix, fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}
	providerKey := domainConfig["provider"]
	if providerKey == "" {
		log.Error("%s No provider specified for domain '%s' (hostname: %s)", logPrefix, domain, fqdn)
		return fmt.Errorf("no provider for domain %s", domain)
	}
	providerCfg, ok := config.GlobalConfig.Providers[providerKey]
	if !ok {
		log.Error("%s No provider config found for key '%s' (domain: %s)", logPrefix, providerKey, domain)
		return fmt.Errorf("no provider config for %s", providerKey)
	}
	providerOptions := providerCfg.GetOptions()
	for k, v := range domainConfig {
		providerOptions[k] = v
	}
	// Mask sensitive values before logging
	maskedProviderOptions := utils.MaskSensitiveOptions(providerOptions)
	log.Debug("%s Merged providerOptions for removal: %v", logPrefix, maskedProviderOptions)

	recordType := providerOptions["type"]
	target := providerOptions["target"]
	if state.Service != "" {
		target = state.Service
	}
	if recordType == "" {
		if ip := net.ParseIP(target); ip != nil {
			if ip.To4() != nil {
				recordType = "A"
			} else {
				recordType = "AAAA"
			}
		} else {
			recordType = "CNAME"
		}
	}

	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}
	log.Debug("%s Final DNS removal params: domain=%s, recordType=%s, hostname=%s", logPrefix, domain, recordType, hostname)

	dnsProvider, err := dns.LoadProviderFromConfig(providerKey, providerOptions)
	if err != nil {
		log.Error("%s Failed to load DNS provider '%s': %v", logPrefix, providerKey, err)
		return err
	}
	if cfProvider, ok := dnsProvider.(interface {
		DeleteRecordWithSource(string, string, string, string, string) error
	}); ok {
		err = cfProvider.DeleteRecordWithSource(domain, recordType, hostname, state.Name, state.SourceType)
	} else {
		err = dnsProvider.DeleteRecord(domain, recordType, hostname)
	}
	if err != nil {
		log.Error("%s Failed to delete DNS record for '%s': %v", logPrefix, fqdn, err)
		return err
	}
	label := state.SourceType
	if label == "" {
		label = "container"
	}
	return nil
}
