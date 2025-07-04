// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"herald/pkg/log"
	"herald/pkg/util"

	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

// CloudflareProvider implements the DNS provider interface for Cloudflare
// Add ProfileName for log prefix
type CloudflareProvider struct {
	client      *cloudflare.API
	config      map[string]string
	logger      *log.ScopedLogger
	retries     int
	timeout     time.Duration
	profileName string // NEW: store profile name
}

// NewCloudflareProviderWithProfile creates a new Cloudflare DNS provider
// Accepts profileName for log prefix
func NewCloudflareProviderWithProfile(profileName string, config map[string]string) (interface{}, error) {
	token, ok := config["token"]
	if !ok || token == "" {
		// Try legacy fields as fallbacks
		if apiToken, exists := config["api_token"]; exists {
			token = apiToken
		} else {
			return nil, fmt.Errorf("cloudflare provider requires 'token' or 'api_token' parameter")
		}
	}

	// Support file:// and env:// references for the token
	resolvedToken := util.ReadSecretValue(token)
	if resolvedToken == "" {
		return nil, fmt.Errorf("cloudflare provider token is empty after resolution")
	}

	// Create Cloudflare client
	api, err := cloudflare.NewWithAPIToken(resolvedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudflare client: %v", err)
	}

	// Parse optional configuration
	retries := 3
	if retriesStr, ok := config["retries"]; ok && retriesStr != "" {
		if r, err := strconv.Atoi(retriesStr); err == nil {
			retries = r
		}
	}

	timeout := 30 * time.Second
	if timeoutStr, ok := config["timeout"]; ok && timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil {
			timeout = time.Duration(t) * time.Second
		}
	}

	logLevel := config["log_level"]
	logPrefix := fmt.Sprintf("[output/dns/cloudflare/%s]", profileName)
	logger := log.NewScopedLogger(logPrefix, logLevel)

	provider := &CloudflareProvider{
		client:      api,
		config:      config,
		logger:      logger,
		retries:     retries,
		timeout:     timeout,
		profileName: profileName, // store for reference
	}

	logger.Debug("Cloudflare DNS provider initialized (retries: %d, timeout: %v)", retries, timeout)
	return provider, nil
}

func NewCloudflareProvider(config map[string]string) (interface{}, error) {
	return NewCloudflareProviderWithProfile("default", config)
}

func init() {
	RegisterProvider("cloudflare", NewCloudflareProvider)
}

// CreateOrUpdateRecord creates or updates a DNS record
func (c *CloudflareProvider) CreateOrUpdateRecord(domain, recordType, name, target string, ttl int, proxied bool) error {
	return c.CreateOrUpdateRecordWithSource(domain, recordType, name, target, ttl, proxied, "", "herald")
}

// CreateOrUpdateRecordWithSource creates or updates a DNS record with source information
func (c *CloudflareProvider) CreateOrUpdateRecordWithSource(domain, recordType, name, target string, ttl int, proxied bool, comment, source string) error {
	logPrefix := getDomainLogPrefix(c.profileName, domain)
	c.logger.Debug("%s Creating/updating record: %s.%s %s -> %s (TTL: %d, Proxied: %t)", logPrefix, name, domain, recordType, target, ttl, proxied)

	ctx := context.Background()

	// Get zone ID
	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		c.logger.Error("%s Failed to get zone ID for domain %s: %v", logPrefix, domain, err)
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}

	// Format the full hostname
	fullName := name
	if name != "@" && name != "" && !strings.HasSuffix(name, "."+domain) {
		fullName = name + "." + domain
	} else if name == "@" {
		fullName = domain
	}

	// --- Robust replace logic: check for conflicting records ---
	conflictingTypes := []string{"A", "AAAA", "CNAME"}
	for _, t := range conflictingTypes {
		if t == recordType {
			continue // skip the type we're about to create
		}
		params := cloudflare.ListDNSRecordsParams{
			Name: fullName,
			Type: t,
		}
		records, _, err := c.client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), params)
		if err != nil {
			c.logger.Error("%s Error searching for conflicting record: %v", logPrefix, err)
			return fmt.Errorf("failed to search for conflicting DNS records: %v", err)
		}
		for _, rec := range records {
			c.logger.Warn("%s Conflicting record exists and will be deleted: [type=%s] [name=%s] [content=%s] [id=%s]", logPrefix, rec.Type, rec.Name, rec.Content, rec.ID)
			// Always log full record at trace level (Trace() will only output if enabled)
			c.logger.Trace("%s Full conflicting record: %+v", logPrefix, rec)
			err := c.client.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), rec.ID)
			if err != nil {
				c.logger.Error("%s Failed to delete conflicting record [type=%s] [name=%s] [id=%s]: %v", logPrefix, rec.Type, rec.Name, rec.ID, err)
				return fmt.Errorf("failed to delete conflicting DNS record: %v", err)
			}
			c.logger.Info("%s Deleted conflicting record [type=%s] [name=%s] [id=%s] before creating new record", logPrefix, rec.Type, rec.Name, rec.ID)
			// Verify deletion
			verifyParams := cloudflare.ListDNSRecordsParams{Name: rec.Name, Type: rec.Type}
			verifyRecords, _, verr := c.client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), verifyParams)
			if verr != nil {
				c.logger.Warn("%s Could not verify deletion of record [type=%s] [name=%s]: %v", logPrefix, rec.Type, rec.Name, verr)
			} else if len(verifyRecords) == 0 {
				c.logger.Debug("%s Verified deletion of record [type=%s] [name=%s]", logPrefix, rec.Type, rec.Name)
			} else {
				c.logger.Warn("%s Record [type=%s] [name=%s] still exists after deletion attempt!", logPrefix, rec.Type, rec.Name)
				c.logger.Trace("%s Remaining record(s): %+v", logPrefix, verifyRecords)
			}

			// Wait for Cloudflare to propagate deletion (retry up to 5 times, 200ms each)
			for i := 0; i < 5; i++ {
				time.Sleep(200 * time.Millisecond)
				verifyRecords, _, verr := c.client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), verifyParams)
				if verr != nil {
					c.logger.Warn("%s Could not verify deletion of record [type=%s] [name=%s] (retry %d): %v", logPrefix, rec.Type, rec.Name, i+1, verr)
					break
				}
				if len(verifyRecords) == 0 {
					c.logger.Debug("%s Verified deletion of record [type=%s] [name=%s] after %d retries", logPrefix, rec.Type, rec.Name, i+1)
					break
				}
				if i == 4 {
					c.logger.Warn("%s Record [type=%s] [name=%s] still exists after %d retries!", logPrefix, rec.Type, rec.Name, i+1)
					c.logger.Trace("%s Remaining record(s): %+v", logPrefix, verifyRecords)
				}
			}
		}
	}
	// --- End robust replace logic ---

	// Look for existing record of the same type
	existingRecord, err := c.findExistingRecord(ctx, zoneID, fullName, recordType)
	if err != nil {
		c.logger.Error("%s Failed to search for existing record: %v", logPrefix, err)
		return fmt.Errorf("failed to search for existing record: %v", err)
	}

	if existingRecord == nil {
		c.logger.Trace("%s No existing record found for update: %s %s %s", logPrefix, fullName, recordType, target)
	}

	// Prepare record data
	recordParams := cloudflare.CreateDNSRecordParams{
		Type:    recordType,
		Name:    fullName,
		Content: target,
		TTL:     ttl,
		Proxied: &proxied,
	}

	// Create resource container for the zone
	rc := cloudflare.ZoneIdentifier(zoneID)

	// Update or create record
	if existingRecord != nil {
		c.logger.Debug("%s Updating existing record %s", logPrefix, existingRecord.ID)

		updateParams := cloudflare.UpdateDNSRecordParams{
			Type:    recordType,
			Name:    fullName,
			Content: target,
			TTL:     ttl,
			Proxied: &proxied,
		}

		if comment != "" {
			updateParams.Comment = &comment
		}
		updateParams.ID = existingRecord.ID
		_, err = c.client.UpdateDNSRecord(ctx, rc, updateParams)
		if err != nil {
			return fmt.Errorf("failed to update DNS record: %v", err)
		}

		c.logger.Info("%s Updated DNS record: %s %s -> %s", logPrefix, fullName, recordType, target)
	} else {
		c.logger.Debug("%s Creating new record", logPrefix)

		_, err = c.client.CreateDNSRecord(ctx, rc, recordParams)
		if err != nil {
			return fmt.Errorf("failed to create DNS record: %v", err)
		}

		c.logger.Info("%s Created DNS record: %s %s -> %s", logPrefix, fullName, recordType, target)
	}

	return nil
}

// DeleteRecord deletes a DNS record
func (c *CloudflareProvider) DeleteRecord(domain, recordType, name string) error {
	logPrefix := getDomainLogPrefix(c.profileName, domain)
	c.logger.Debug("%s Deleting record: %s.%s %s", logPrefix, name, domain, recordType)

	ctx := context.Background()

	// Get zone ID
	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}

	// Format the full hostname
	fullName := name
	if name != "@" && name != "" && !strings.HasSuffix(name, "."+domain) {
		fullName = name + "." + domain
	} else if name == "@" {
		fullName = domain
	}

	// Find the record to delete
	existingRecord, err := c.findExistingRecord(ctx, zoneID, fullName, recordType)
	if err != nil {
		return fmt.Errorf("failed to search for existing record: %v", err)
	}

	if existingRecord == nil {
		c.logger.Warn("%s Record not found for deletion: %s %s", logPrefix, fullName, recordType)
		return nil // Not an error - record doesn't exist
	}

	// Create resource container for the zone
	rc := cloudflare.ZoneIdentifier(zoneID)

	// Delete the record
	err = c.client.DeleteDNSRecord(ctx, rc, existingRecord.ID)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %v", err)
	}

	c.logger.Info("%s Deleted DNS record: %s %s", logPrefix, fullName, recordType)
	return nil
}

// getZoneID retrieves the zone ID for a domain
func (c *CloudflareProvider) getZoneID(ctx context.Context, domain string) (string, error) {
	// Try to find the zone
	zones, err := c.client.ListZones(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("failed to list zones: %v", err)
	}

	if len(zones) == 0 {
		return "", fmt.Errorf("no zone found for domain: %s", domain)
	}

	// Return the first matching zone
	return zones[0].ID, nil
}

// findExistingRecord searches for an existing DNS record
func (c *CloudflareProvider) findExistingRecord(ctx context.Context, zoneID, name, recordType string) (*cloudflare.DNSRecord, error) {
	logPrefix := getDomainLogPrefix(c.profileName, name)
	// Create resource container for the zone
	rc := cloudflare.ZoneIdentifier(zoneID)

	// Search for records with matching name and type
	params := cloudflare.ListDNSRecordsParams{
		Name: name,
		Type: recordType,
	}

	c.logger.Trace("%s Searching for existing record: zoneID=%s, name=%s, type=%s", logPrefix, zoneID, name, recordType)

	records, _, err := c.client.ListDNSRecords(ctx, rc, params)
	if err != nil {
		c.logger.Error("%s Error searching DNS records: %v", logPrefix, err)
		return nil, fmt.Errorf("failed to search DNS records: %v", err)
	}

	c.logger.Trace("%s Found %d records for name=%s, type=%s", logPrefix, len(records), name, recordType)

	if len(records) == 0 {
		return nil, nil // No existing record found
	}

	// Return the first matching record
	return &records[0], nil
}

// GetName returns the provider name
func (c *CloudflareProvider) GetName() string {
	return "cloudflare"
}

// Validate validates the provider configuration
func (c *CloudflareProvider) Validate() error {
	if c.client == nil {
		return fmt.Errorf("cloudflare client not initialized")
	}

	ctx := context.Background()

	// Test the connection by listing zones (limited to 1 for efficiency)
	_, err := c.client.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate Cloudflare connection: %v", err)
	}

	c.logger.Debug("Cloudflare provider validation successful")
	return nil
}

// New: always include domain config key in log prefix if available
func getDomainLogPrefix(domainConfigKey, domain string) string {
	if domainConfigKey != "" {
		return fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
	}
	return fmt.Sprintf("[domain/%s]", strings.ReplaceAll(domain, ".", "_"))
}
