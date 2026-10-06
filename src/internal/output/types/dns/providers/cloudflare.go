// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

type CloudflareProvider struct {
	*BaseProvider
	client *cloudflare.API
}

func NewCloudflareProviderWithProfile(profileName string, config map[string]string) (interface{}, error) {
	base := NewBaseProvider("cloudflare", profileName, config)

	token := base.Secret("token", "api_token")
	if token == "" {
		return nil, fmt.Errorf("cloudflare provider requires 'token' or 'api_token' parameter")
	}

	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudflare client: %v", err)
	}

	provider := &CloudflareProvider{
		BaseProvider: base,
		client:       api,
	}

	base.Logger.Debug("Cloudflare DNS provider initialized (retries: %d, timeout: %v)", base.Retries, base.Timeout)
	return provider, nil
}

func NewCloudflareProvider(config map[string]string) (interface{}, error) {
	return NewCloudflareProviderWithProfile("default", config)
}

func init() {
	dns.RegisterProvider("cloudflare", NewCloudflareProvider)
}

func (c *CloudflareProvider) SupportsProxied() bool {
	return true
}

func (c *CloudflareProvider) CreateOrUpdateRecord(domain, recordType, name, target string, ttl int, proxied bool, overwrite bool) error {
	return c.CreateOrUpdateRecordWithSource(domain, recordType, name, target, ttl, proxied, "", "herald", overwrite)
}

func (c *CloudflareProvider) CreateOrUpdateRecordWithSource(domain, recordType, name, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	logPrefix := getDomainLogPrefix(c.ProfileName, domain)
	c.Logger.Debug("%s Creating/updating record: %s.%s %s -> %s (TTL: %d, Proxied: %t, Overwrite: %t)", logPrefix, name, domain, recordType, target, ttl, proxied, overwrite)

	ctx := context.Background()

	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		c.Logger.Error("%s Failed to get zone ID for domain %s: %v", logPrefix, domain, err)
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}

	fullName := BuildFQDN(name, domain)

	c.Logger.Trace("%s Starting record lookup for existing record", logPrefix)
	existingRecord, err := c.checkExistingRecord(ctx, zoneID, fullName, recordType)
	if err != nil {
		c.Logger.Error("%s Record lookup failed: %v", logPrefix, err)
		return fmt.Errorf("record lookup failed: %v", err)
	}

	if existingRecord != nil {
		c.Logger.Info("%s Found existing record, updating: id=%s", logPrefix, existingRecord.ID)
		c.Logger.Trace("%s Existing record details: id=%s type=%s name=%s content=%s ttl=%d proxied=%v", logPrefix, existingRecord.ID, existingRecord.Type, existingRecord.Name, existingRecord.Content, existingRecord.TTL, existingRecord.Proxied)
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
		_, uerr := c.client.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), updateParams)
		if uerr != nil {
			return fmt.Errorf("failed to update DNS record: %v", uerr)
		}
		c.Logger.Info("%s Updated DNS record: %s %s -> %s", logPrefix, fullName, recordType, target)
		return nil
	}

	c.Logger.Info("%s No existing record found, proceeding with create", logPrefix)

	recordParams := cloudflare.CreateDNSRecordParams{Type: recordType, Name: fullName, Content: target, TTL: ttl, Proxied: &proxied}
	rc := cloudflare.ZoneIdentifier(zoneID)

	attempts := 3
	for i := 1; i <= attempts; i++ {
		_, cerr := c.client.CreateDNSRecord(ctx, rc, recordParams)
		if cerr == nil {
			c.Logger.Info("%s Created DNS record: %s %s -> %s", logPrefix, fullName, recordType, target)
			return nil
		}

		cerrStr := cerr.Error()
		if strings.Contains(cerrStr, "81058") || strings.Contains(strings.ToLower(cerrStr), "identical record") {
			c.Logger.Info("%s CreateDNSRecord reported an identical record already exists; treating as success: %v", logPrefix, cerr)
			return nil
		}

		c.Logger.Error("%s Failed to create DNS record (attempt %d/%d): %v", logPrefix, i, attempts, cerr)
		if i < attempts {
			c.Sleep(i, 500*time.Millisecond)
		}
	}

	return fmt.Errorf("failed to create DNS record after %d attempts: %s", attempts, fullName)
}

func (c *CloudflareProvider) checkExistingRecord(ctx context.Context, zoneID, name, recordType string) (*cloudflare.DNSRecord, error) {
	logPrefix := getDomainLogPrefix(c.ProfileName, name)
	maxAttempts := 5
	baseDelay := 200 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c.Logger.Trace("%s Record lookup attempt %d/%d: querying for name=%s, type=%s", logPrefix, attempt, maxAttempts, name, recordType)

		rc := cloudflare.ZoneIdentifier(zoneID)
		params := cloudflare.ListDNSRecordsParams{Name: name, Type: recordType}
		recs, _, err := c.client.ListDNSRecords(ctx, rc, params)

		if err != nil {
			c.Logger.Trace("%s Record lookup attempt %d failed with error: %v", logPrefix, attempt, err)
			if attempt < maxAttempts {
				c.Sleep(attempt, baseDelay)
				continue
			}
			return nil, fmt.Errorf("record lookup failed after %d attempts: %v", maxAttempts, err)
		}

		c.Logger.Trace("%s Record lookup attempt %d returned %d records", logPrefix, attempt, len(recs))
		for i, r := range recs {
			c.Logger.Trace("%s Record lookup result %d: id=%s type=%s name=%s content=%s ttl=%d proxied=%v", logPrefix, i+1, r.ID, r.Type, r.Name, r.Content, r.TTL, r.Proxied)
		}

		if len(recs) > 0 {
			for _, r := range recs {
				if r.Type == recordType && r.Name == name {
					c.Logger.Trace("%s Record lookup found exact match on attempt %d: id=%s", logPrefix, attempt, r.ID)
					return &r, nil
				}
			}
			c.Logger.Trace("%s Record lookup found records but no exact match on attempt %d, returning first", logPrefix, attempt)
			return &recs[0], nil
		}

		c.Logger.Trace("%s Record lookup attempt %d found no records", logPrefix, attempt)
		if attempt < maxAttempts {
			c.Logger.Trace("%s Record lookup sleeping %v before retry", logPrefix, baseDelay*time.Duration(attempt))
			c.Sleep(attempt, baseDelay)
		}
	}

	c.Logger.Trace("%s Record lookup completed %d attempts, no records found", logPrefix, maxAttempts)
	return nil, nil
}

func (c *CloudflareProvider) fetchRecordsClientOnly(ctx context.Context, zoneID, name, recordType string) []cloudflare.DNSRecord {
	rc := cloudflare.ZoneIdentifier(zoneID)
	var merged []cloudflare.DNSRecord

	candidates := []string{name}
	nameNoDot := strings.TrimSuffix(name, ".")
	if nameNoDot != name {
		candidates = append(candidates, nameNoDot)
	} else {
		candidates = append(candidates, name+".")
	}
	lower := strings.ToLower(name)
	if lower != name {
		candidates = append(candidates, lower)
	}
	if strings.Contains(nameNoDot, ".") {
		hostOnly := strings.SplitN(nameNoDot, ".", 2)[0]
		if hostOnly != "" && hostOnly != nameNoDot {
			candidates = append(candidates, hostOnly)
			candidates = append(candidates, hostOnly+".")
		}
	}

	if recordType != "" {
		for _, cName := range candidates {
			params := cloudflare.ListDNSRecordsParams{Name: cName, Type: recordType}
			recs, _, err := c.client.ListDNSRecords(ctx, rc, params)
			if err == nil && len(recs) > 0 {
				merged = append(merged, recs...)
			}
		}
		if len(merged) > 0 {
			return merged
		}
	}

	for _, cName := range candidates {
		params := cloudflare.ListDNSRecordsParams{Name: cName}
		recs, _, err := c.client.ListDNSRecords(ctx, rc, params)
		if err == nil && len(recs) > 0 {
			merged = append(merged, recs...)
		}
	}

	unique := make(map[string]cloudflare.DNSRecord)
	for _, r := range merged {
		unique[r.ID] = r
	}
	out := make([]cloudflare.DNSRecord, 0, len(unique))
	for _, r := range unique {
		out = append(out, r)
	}
	return out
}

func (c *CloudflareProvider) DeleteRecord(domain, recordType, name string) error {
	logPrefix := getDomainLogPrefix(c.ProfileName, domain)
	c.Logger.Debug("%s Deleting record: %s.%s %s", logPrefix, name, domain, recordType)

	ctx := context.Background()

	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}

	fullName := BuildFQDN(name, domain)

	existingRecord, err := c.checkExistingRecord(ctx, zoneID, fullName, recordType)
	if err != nil {
		return fmt.Errorf("failed to search for existing record: %v", err)
	}

	if existingRecord == nil {
		c.Logger.Warn("%s Record not found for deletion: %s %s", logPrefix, fullName, recordType)
		return nil
	}

	rc := cloudflare.ZoneIdentifier(zoneID)

	err = c.client.DeleteDNSRecord(ctx, rc, existingRecord.ID)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %v", err)
	}

	c.Logger.Info("%s Deleted DNS record: %s %s", logPrefix, fullName, recordType)
	return nil
}

func (c *CloudflareProvider) getZoneID(ctx context.Context, domain string) (string, error) {
	zones, err := c.client.ListZones(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("failed to list zones: %v", err)
	}

	if len(zones) == 0 {
		return "", fmt.Errorf("no zone found for domain: %s", domain)
	}

	return zones[0].ID, nil
}

func (c *CloudflareProvider) GetName() string {
	return "cloudflare"
}

func (c *CloudflareProvider) Validate() error {
	if c.client == nil {
		return fmt.Errorf("cloudflare client not initialized")
	}

	ctx := context.Background()

	_, err := c.client.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate Cloudflare connection: %v", err)
	}

	c.Logger.Debug("Cloudflare provider validation successful")
	return nil
}

func getDomainLogPrefix(domainConfigKey, domain string) string {
	if domainConfigKey != "" {
		return fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
	}
	return fmt.Sprintf("[domain/%s]", strings.ReplaceAll(domain, ".", "_"))
}
