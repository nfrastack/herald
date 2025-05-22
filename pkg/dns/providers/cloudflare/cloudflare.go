// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// Package cloudflare provides a Cloudflare DNS provider implementation
package cloudflare

import (
	"container-dns-companion/pkg/config"
	"container-dns-companion/pkg/dns"
	"container-dns-companion/pkg/log"
	"container-dns-companion/pkg/utils"

	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"golang.org/x/exp/maps"
)

// Register this provider with the DNS registry
func Register() {
	dns.RegisterProvider("cloudflare", NewProvider)
}

// Provider implements the DNS provider interface for Cloudflare
type Provider struct {
	api        *cloudflare.API
	config     map[string]string
	zoneID     string
	defaultTTL int
	DryRun     bool // Add DryRun field
}

// NewProvider creates a new Cloudflare DNS provider
func NewProvider(config map[string]string) (dns.Provider, error) {
	p := &Provider{
		config: config,
		zoneID: config["zone_id"],
	}

	// Set DryRun if present in config
	if v, ok := config["dry_run"]; ok && (v == "true" || v == "1") {
		p.DryRun = true
	}

	// Log available configuration keys for debugging
	log.Trace("[provider/cloudflare] Cloudflare provider config keys: %v", maps.Keys(config))

	// Log values received (excluding sensitive ones)
	for k, v := range config {
		if !strings.Contains(k, "token") && !strings.Contains(k, "key") && !strings.Contains(k, "secret") && !strings.Contains(k, "password") {
			log.Trace("[provider/cloudflare] Cloudflare config: %s = %s", k, v)
		} else {
			log.Trace("[provider/cloudflare] Cloudflare config: %s = ****", k)
		}
	}

	// Initialize default TTL
	ttl, err := strconv.Atoi(config["default_ttl"])
	if err != nil || ttl <= 0 {
		ttl = 60 // Default TTL if not specified or invalid
	}
	p.defaultTTL = ttl

	// Don't try to initialize API immediately - only when needed
	return p, nil
}

// lazyInitAPI initializes the Cloudflare API client if not already initialized
func (p *Provider) lazyInitAPI() error {
	// If API is already initialized, return immediately
	if p.api != nil {
		return nil
	}

	// Debug configuration
	log.Debug("[provider/cloudflare] Cloudflare provider configuration:")
	log.Debug("[provider/cloudflare]  - API Token present: %v", config.GetConfig(p.config, "api_token") != "")
	log.Debug("[provider/cloudflare]  - Zone ID present: %v", config.GetConfig(p.config, "zone_id") != "")
	log.Debug("[provider/cloudflare]  - All config keys: %v", p.config)

	var api *cloudflare.API
	var err error

	// Check if we have an API token
	apiToken := config.GetConfig(p.config, "api_token")
	if apiToken != "" {
		// Use the token-based authentication method
		log.Debug("[provider/cloudflare] Initializing Cloudflare API with token authentication")
		log.Debug("[provider/cloudflare] API Token (partial): %s", utils.MaskSensitiveValue(apiToken))
		api, err = cloudflare.NewWithAPIToken(apiToken)
		if err != nil {
			return fmt.Errorf("[provider/cloudflare] failed to initialize API with token: %w", err)
		}
	} else {
		// Check for email and API key (legacy auth)
		email := config.GetConfig(p.config, "api_email")
		apiKey := config.GetConfig(p.config, "api_key")

		if email == "" || apiKey == "" {
			return fmt.Errorf("[provider/cloudflare] missing required credentials (either api_token or both api_key and api_email)")
		}

		// Use the key-based authentication method
		log.Debug("[provider/cloudflare] Initializing Cloudflare API with key-based authentication")
		api, err = cloudflare.New(apiKey, email)
		if err != nil {
			return fmt.Errorf("[provider/cloudflare] failed to initialize API with key: %w", err)
		}
	}

	p.api = api
	return nil
}


// getZoneID retrieves the zone ID for a domain
func (p *Provider) getZoneID(domain string) (string, error) {
	// Initialize API if needed
	if err := p.lazyInitAPI(); err != nil {
		return "", err
	}

	if domain == "" {
		return "", fmt.Errorf("[provider/cloudflare] domain name is required to get zone ID")
	}

	// Get zone ID using the API
	zoneID, err := p.api.ZoneIDByName(domain)
	if err != nil {
		return "", fmt.Errorf("[provider/cloudflare] failed to get zone ID for domain %s: %w", domain, err)
	}
	return zoneID, nil
}

// CreateOrUpdateRecord creates or updates a DNS record
func (p *Provider) CreateOrUpdateRecord(domain string, recordType string, hostname string, target string, ttl int, overwrite bool) error {
	if p.DryRun {
		log.Info("[provider/cloudflare] [dry-run] Would create or update DNS record: %s.%s (%s) -> %s (TTL: %d, Overwrite: %v)", hostname, domain, recordType, target, ttl, overwrite)
		return nil
	}

	// Initialize API if needed
	if err := p.lazyInitAPI(); err != nil {
		return err
	}

	// Get zone ID for the domain
	zoneID, err := p.getZoneID(domain)
	if err != nil {
		return err
	}

	// Format the full hostname
	fullHostname := dns.JoinHostWithDomain(hostname, domain)

	// Create context for API calls
	ctx := context.Background()

	// Create resource container with zone ID
	rc := cloudflare.ZoneIdentifier(zoneID)

	// Check if record exists
	recordID, err := p.GetRecordID(domain, recordType, hostname)

	// If we found a record and overwrite is true
	if err == nil && recordID != "" {
		if overwrite {
			log.Debug("[provider/cloudflare] Record %s (%s) exists and overwrite=true, updating it", fullHostname, recordType)
			// Record exists, update it
			proxied := false
			updateParams := cloudflare.UpdateDNSRecordParams{
				ID:      recordID,
				Type:    recordType,
				Name:    fullHostname,
				Content: target,
				TTL:     ttl,
				Proxied: &proxied,
			}

			// Call the UpdateDNSRecord API
			_, err = p.api.UpdateDNSRecord(ctx, rc, updateParams)
			if err != nil {
				return fmt.Errorf("[provider/cloudflare] failed to update DNS record: %w", err)
			}

			log.Info("[provider/cloudflare] Updated DNS record %s (%s) -> %s", fullHostname, recordType, target)
			return nil
		} else {
			// Record exists but overwrite is false
			log.Debug("[provider/cloudflare] Record %s (%s) exists but overwrite=false, skipping", fullHostname, recordType)
			return fmt.Errorf("[provider/cloudflare] record %s (%s) already exists and overwrite is not enabled", fullHostname, recordType)
		}
	}

	// Check if another record type exists with the same hostname
	// This is specifically to handle the CNAME conflict error we're seeing
	listParams := cloudflare.ListDNSRecordsParams{
		Name: fullHostname,
	}

	records, _, err := p.api.ListDNSRecords(ctx, rc, listParams)
	if err != nil {
		log.Debug("[provider/cloudflare] Error checking for conflicting records: %v", err)
	} else if len(records) > 0 {
		// Found records with the same name but different type
		for _, record := range records {
			if record.Type != recordType {
				if overwrite {
					// Delete the conflicting record if overwrite is enabled
					log.Debug("[provider/cloudflare] Found conflicting record type %s for %s, deleting it", record.Type, fullHostname)
					err = p.api.DeleteDNSRecord(ctx, rc, record.ID)
					if err != nil {
						return fmt.Errorf("[provider/cloudflare] failed to delete conflicting DNS record: %w", err)
					}
					log.Info("[provider/cloudflare] Deleted conflicting DNS record %s (%s)", fullHostname, record.Type)
				} else {
					// Report the conflict if overwrite is disabled
					return fmt.Errorf("[provider/cloudflare] conflicting record type %s exists for %s and overwrite is not enabled",
						record.Type, fullHostname)
				}
			}
		}
	}

	// Record doesn't exist or conflicts have been resolved, create it
	proxied := false
	createParams := cloudflare.CreateDNSRecordParams{
		Type:    recordType,
		Name:    fullHostname,
		Content: target,
		TTL:     ttl,
		Proxied: &proxied,
	}

	// Call the CreateDNSRecord API
	_, err = p.api.CreateDNSRecord(ctx, rc, createParams)
	if err != nil {
		return fmt.Errorf("[provider/cloudflare] failed to create DNS record: %w", err)
	}

	log.Info("[provider/cloudflare] Created DNS record %s (%s) -> %s", fullHostname, recordType, target)
	return nil
}

// GetRecordID gets a DNS record ID for a specific record
func (p *Provider) GetRecordID(domain string, recordType string, hostname string) (string, error) {
	// Initialize API if needed
	if err := p.lazyInitAPI(); err != nil {
		return "", err
	}

	// Get zone ID for the domain
	zoneID, err := p.getZoneID(domain)
	if err != nil {
		return "", err
	}

	// Format the full hostname
	fullHostname := dns.JoinHostWithDomain(hostname, domain)

	// Create context for API calls
	ctx := context.Background()

	// Create resource container with zone ID
	rc := cloudflare.ZoneIdentifier(zoneID)

	// List records to find the one we need
	params := cloudflare.ListDNSRecordsParams{
		Type: recordType,
		Name: fullHostname,
	}

	records, _, err := p.api.ListDNSRecords(ctx, rc, params)
	if err != nil {
		return "", fmt.Errorf("[provider/cloudflare] failed to find DNS record: %w", err)
	}

	if len(records) == 0 {
		return "", nil // No error, but no record found
	}

	return records[0].ID, nil
}

// DeleteRecord deletes a DNS record
func (p *Provider) DeleteRecord(domain string, recordType string, hostname string) error {
	if p.DryRun {
		log.Info("[provider/cloudflare] [dry-run] Would delete DNS record: %s.%s (%s)", hostname, domain, recordType)
		return nil
	}

	// Initialize API if needed
	if err := p.lazyInitAPI(); err != nil {
		return err
	}

	// Get zone ID for the domain
	zoneID, err := p.getZoneID(domain)
	if err != nil {
		return err
	}

	// Format the full hostname
	fullHostname := dns.JoinHostWithDomain(hostname, domain)

	// Create context for API calls
	ctx := context.Background()

	// Create resource container with zone ID
	rc := cloudflare.ZoneIdentifier(zoneID)

	// Get record ID
	recordID, err := p.GetRecordID(domain, recordType, hostname)
	if err != nil {
		return err
	}

	if recordID == "" {
		return fmt.Errorf("[provider/cloudflare] record %s not found", fullHostname)
	}

	// Delete the record
	err = p.api.DeleteDNSRecord(ctx, rc, recordID)
	if err != nil {
		return fmt.Errorf("[provider/cloudflare] failed to delete DNS record: %w", err)
	}

	log.Info("[provider/cloudflare] deleted DNS record %s (%s)", fullHostname, recordType)
	return nil
}

// GetRecordValue retrieves the value of a DNS record
func (p *Provider) GetRecordValue(domain, recordType, hostname string) (*dns.Record, error) {
	if err := p.lazyInitAPI(); err != nil {
		return nil, err
	}
	zoneID, err := p.getZoneID(domain)
	if err != nil {
		return nil, err
	}
	fullHostname := dns.JoinHostWithDomain(hostname, domain)
	ctx := context.Background()
	rc := cloudflare.ZoneIdentifier(zoneID)
	params := cloudflare.ListDNSRecordsParams{
		Type: recordType,
		Name: fullHostname,
	}
	records, _, err := p.api.ListDNSRecords(ctx, rc, params)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("record not found")
	}
	cfRec := records[0]
	return &dns.Record{
		Name:    cfRec.Name,
		Type:    cfRec.Type,
		Value:   cfRec.Content,
		TTL:     cfRec.TTL,
		ZoneID:  zoneID,
		Proxied: cfRec.Proxied != nil && *cfRec.Proxied,
	}, nil
}

// GetRecords retrieves all DNS records of a specific type for a hostname
func (p *Provider) GetRecords(domain, recordType, hostname string) ([]*dns.Record, error) {
	if err := p.lazyInitAPI(); err != nil {
		return nil, err
	}
	zoneID, err := p.getZoneID(domain)
	if err != nil {
		return nil, err
	}
	fullHostname := dns.JoinHostWithDomain(hostname, domain)
	ctx := context.Background()
	rc := cloudflare.ZoneIdentifier(zoneID)
	params := cloudflare.ListDNSRecordsParams{
		Type: recordType,
		Name: fullHostname,
	}
	records, _, err := p.api.ListDNSRecords(ctx, rc, params)
	if err != nil {
		return nil, err
	}
	var result []*dns.Record
	for _, cfRec := range records {
		rec := &dns.Record{
			Name:    cfRec.Name,
			Type:    cfRec.Type,
			Value:   cfRec.Content,
			TTL:     cfRec.TTL,
			ZoneID:  zoneID,
			Proxied: cfRec.Proxied != nil && *cfRec.Proxied,
		}
		result = append(result, rec)
	}
	return result, nil
}
