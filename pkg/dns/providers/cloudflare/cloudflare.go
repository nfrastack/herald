// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// Package cloudflare provides a Cloudflare DNS provider implementation
package cloudflare

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/dns"
	"dns-companion/pkg/log"
	"dns-companion/pkg/utils"

	"context"
	"fmt"
	"strconv"

	"github.com/cloudflare/cloudflare-go"
	"golang.org/x/exp/maps"
)

// Register this provider with the DNS registry
func Register() {
	dns.RegisterProvider("cloudflare", NewProvider)
}

// Provider implements the DNS provider interface for Cloudflare
type Provider struct {
	api         *cloudflare.API
	config      map[string]string
	zoneID      string
	defaultTTL  int
	DryRun      bool   // Add DryRun field
	profileName string // Store profile name for logs
	logPrefix   string // Store log prefix for consistent logging
}

// NewProvider creates a new Cloudflare DNS provider
func NewProvider(config map[string]string) (dns.Provider, error) {
	// Always use utils.GetProfileNameFromOptions for profile name resolution
	profileName := utils.GetProfileNameFromOptions(config, "default")
	logPrefix := fmt.Sprintf("[provider/cloudflare/%s]", profileName)

	log.Trace("%s Resolved profile name: %s", logPrefix, profileName)

	p := &Provider{
		config:      config,
		zoneID:      config["zone_id"],
		profileName: profileName,
		logPrefix:   logPrefix,
	}

	// Set DryRun if present in config
	if v, ok := config["dry_run"]; ok && (v == "true" || v == "1") {
		p.DryRun = true
	}

	// Log available configuration keys for debugging
	log.Trace("%s Cloudflare provider config keys: %v", logPrefix, maps.Keys(config))
	log.Trace("%s Cloudflare provider config map: %v", logPrefix, utils.MaskSensitiveOptions(config))

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

	var api *cloudflare.API
	var err error

	// Check if we have an API token
	apiToken := config.GetConfig(p.config, "api_token")
	if apiToken != "" {
		// Use the token-based authentication method
		api, err = cloudflare.NewWithAPIToken(apiToken)
		if err != nil {
			return fmt.Errorf("%s failed to initialize API with token: %w", p.logPrefix, err)
		}
	} else {
		// Check for email and API key (legacy auth)
		email := config.GetConfig(p.config, "api_email")
		apiKey := config.GetConfig(p.config, "api_key")

		if email == "" || apiKey == "" {
			return fmt.Errorf("%s missing required credentials (either api_token or both api_key and api_email)", p.logPrefix)
		}

		// Use the key-based authentication method
		log.Debug("%s Initializing Cloudflare API with key-based authentication", p.logPrefix)
		api, err = cloudflare.New(apiKey, email)
		if err != nil {
			return fmt.Errorf("%s failed to initialize API with key: %w", p.logPrefix, err)
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
		return "", fmt.Errorf("%s domain name is required to get zone ID", p.logPrefix)
	}

	// Get zone ID using the API
	zoneID, err := p.api.ZoneIDByName(domain)
	if err != nil {
		return "", fmt.Errorf("%s failed to get zone ID for domain %s: %w", p.logPrefix, domain, err)
	}
	return zoneID, nil
}

// CreateOrUpdateRecord creates or updates a DNS record (Cloudflare-specific)
func (p *Provider) CreateOrUpdateRecord(domain string, recordType string, hostname string, target string, ttl int, overwrite bool) error {
	return p.createOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, overwrite, "", "")
}

// CreateOrUpdateRecordWithSource allows logging the source/container name and type
func (p *Provider) CreateOrUpdateRecordWithSource(domain string, recordType string, hostname string, target string, ttl int, overwrite bool, sourceName string, sourceType string) error {
	return p.createOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, overwrite, sourceName, sourceType)
}

// createOrUpdateRecordWithSource is the internal implementation that supports logging the source/container name and type
func (p *Provider) createOrUpdateRecordWithSource(domain string, recordType string, hostname string, target string, ttl int, overwrite bool, sourceName string, sourceType string) error {
	if target == "" {
		return fmt.Errorf("%s target must be explicitly set in domain config or default_target; refusing to guess for %s.%s (%s)", p.logPrefix, hostname, domain, recordType)
	}
	if p.DryRun {
		log.Info("%s [dry-run] Would create or update DNS record: %s.%s (%s) -> %s (TTL: %d, Overwrite: %v) (%s: %s)", p.logPrefix, hostname, domain, recordType, target, ttl, overwrite, sourceType, sourceName)
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
			// Fetch current record value and compare all relevant fields
			current, err := p.GetRecordValue(domain, recordType, hostname)
			if err == nil && current != nil {
				proxied := false // Default, adjust if you support proxied
				if current.Type == recordType && current.Value == target && current.TTL == ttl && current.Proxied == proxied {
					label := sourceType
					if label == "" {
						label = "unknown"
					}
					name := sourceName
					if name == "" {
						name = "unknown"
					}
					log.Debug("%s Record %s (%s) already up to date, skipping update (%s: %s)", p.logPrefix, fullHostname, recordType, label, name)
					return nil
				}
			}
			log.Debug("%s Record %s (%s) exists and update_existing=true, updating it", p.logPrefix, fullHostname, recordType)
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
				return fmt.Errorf("%s failed to update DNS record: %w", p.logPrefix, err)
			}
			label := sourceType
			if label == "" {
				label = "unknown"
			}
			name := sourceName
			if name == "" {
				name = "unknown"
			}
			log.Info("%s Updated DNS record %s (%s) -> %s (%s: %s)", p.logPrefix, fullHostname, recordType, target, label, name)
			return nil
		} else {
			// Record exists but overwrite is false
			log.Debug("%s Record %s (%s) exists but update_existing=false, skipping", p.logPrefix, fullHostname, recordType)
			return fmt.Errorf("%s record %s (%s) already exists and update_existing_records=false", p.logPrefix, fullHostname, recordType)
		}
	}

	// Check if another record type exists with the same hostname
	listParams := cloudflare.ListDNSRecordsParams{
		Name: fullHostname,
	}

	records, _, err := p.api.ListDNSRecords(ctx, rc, listParams)
	if err != nil {
		log.Debug("%s Error checking for conflicting records: %v", p.logPrefix, err)
	} else if len(records) > 0 {
		// Found records with the same name but different type
		for _, record := range records {
			if record.Type != recordType {
				if overwrite {
					// Delete the conflicting record if overwrite is enabled
					log.Debug("%s Found conflicting record type %s for %s, deleting it", p.logPrefix, record.Type, fullHostname)
					err = p.api.DeleteDNSRecord(ctx, rc, record.ID)
					if err != nil {
						return fmt.Errorf("%s failed to delete conflicting DNS record: %w", p.logPrefix, err)
					}
					log.Info("%s Deleted conflicting DNS record %s (%s)", p.logPrefix, fullHostname, record.Type)
				} else {
					// Report the conflict if overwrite is disabled
					return fmt.Errorf("%s conflicting record type %s exists for %s and overwrite is not enabled",
						p.logPrefix, record.Type, fullHostname)
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
		return fmt.Errorf("%s failed to create DNS record: %w", p.logPrefix, err)
	}
	label := sourceType
	if label == "" {
		label = "unknown"
	}
	name := sourceName
	if name == "" {
		name = "unknown"
	}
	log.Info("%s Created DNS record %s (%s) -> %s (%s: %s)", p.logPrefix, fullHostname, recordType, target, label, name)
	return nil
}

// DeleteRecord deletes a DNS record (Cloudflare-specific)
func (p *Provider) DeleteRecord(domain string, recordType string, hostname string) error {
	return p.deleteRecordWithSource(domain, recordType, hostname, "", "")
}

// DeleteRecordWithSource deletes a DNS record and logs the source/container name and type
func (p *Provider) DeleteRecordWithSource(domain string, recordType string, hostname string, sourceName string, sourceType string) error {
	return p.deleteRecordWithSource(domain, recordType, hostname, sourceName, sourceType)
}

// deleteRecordWithSource is the internal implementation that supports logging the source/container name and type
func (p *Provider) deleteRecordWithSource(domain string, recordType string, hostname string, sourceName string, sourceType string) error {
	if p.DryRun {
		log.Info("%s [dry-run] Would delete DNS record: %s.%s (%s) (%s: %s)", p.logPrefix, hostname, domain, recordType, sourceType, sourceName)
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
		return fmt.Errorf("%s record %s not found", p.logPrefix, fullHostname)
	}

	// Delete the record
	err = p.api.DeleteDNSRecord(ctx, rc, recordID)
	if err != nil {
		return fmt.Errorf("%s failed to delete DNS record: %w", p.logPrefix, err)
	}

	log.Info("%s Deleted DNS record %s (%s) (%s: %s)", p.logPrefix, fullHostname, recordType, sourceType, sourceName)
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
		return "", fmt.Errorf("%s failed to find DNS record: %w", p.logPrefix, err)
	}

	if len(records) == 0 {
		return "", nil // No error, but no record found
	}

	return records[0].ID, nil
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
