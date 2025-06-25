// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"context"
	"strconv"
	"time"

	"herald/pkg/log"
	"herald/pkg/util"

	"github.com/cloudflare/cloudflare-go"
)

// Provider defines the interface that all DNS providers must implement
type Provider interface {
	// CreateOrUpdateRecord creates or updates a DNS record
	CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool) error

	// CreateOrUpdateRecordWithSource creates or updates a DNS record with source information
	CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string) error

	// DeleteRecord deletes a DNS record
	DeleteRecord(domain, recordType, hostname string) error

	// GetName returns the provider name
	GetName() string

	// Validate validates the provider configuration
	Validate() error
}

// ProviderConstructor is a function that creates a new DNS provider instance
type ProviderConstructor func(config map[string]string) (Provider, error)

// providerRegistry holds all registered DNS providers
var providerRegistry = make(map[string]ProviderConstructor)
var registryMutex sync.RWMutex

// RegisterProvider registers a new DNS provider
func RegisterProvider(name string, constructor func(map[string]string) (interface{}, error)) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	providerRegistry[name] = func(config map[string]string) (Provider, error) {
		prov, err := constructor(config)
		if err != nil {
			return nil, err
		}
		provider, ok := prov.(Provider)
		if !ok {
			return nil, fmt.Errorf("provider '%s' does not implement Provider interface", name)
		}
		return provider, nil
	}
}

// GetProvider creates a new instance of the specified DNS provider
func GetProvider(name string, config map[string]string) (Provider, error) {
	registryMutex.RLock()
	constructor, exists := providerRegistry[name]
	registryMutex.RUnlock()

	if !exists {
		availableProviders := GetAvailableProviders()
		return nil, fmt.Errorf("unknown DNS provider '%s'. Available providers: %v", name, availableProviders)
	}

	// Process configuration values to support file:// and env:// references
	processedConfig := ProcessConfigValues(config)

	return constructor(processedConfig)
}

// GetAvailableProviders returns a list of all registered DNS provider names
func GetAvailableProviders() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	providers := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		providers = append(providers, name)
	}
	return providers
}

// ValidateProviderExists checks if a DNS provider is registered
func ValidateProviderExists(providerName string) error {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	if _, exists := providerRegistry[providerName]; !exists {
		availableProviders := GetAvailableProviders()
		return fmt.Errorf("unknown DNS provider '%s'. Available providers: %v", providerName, availableProviders)
	}
	return nil
}

// ProcessConfigValues processes DNS provider configuration values to support file:// and env:// references
func ProcessConfigValues(config map[string]string) map[string]string {
	processed := make(map[string]string)
	for key, value := range config {
		processed[key] = processConfigValue(value)
	}
	return processed
}

// processConfigValue processes a single configuration value for file:// and env:// support
func processConfigValue(value string) string {
	// Check if the value is a file reference and resolve it
	if strings.HasPrefix(value, "file://") {
		filePath := value[7:] // Remove "file://" prefix

		// Read the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			// Log error but return original value
			return value
		}

		// Trim whitespace and return content
		return strings.TrimSpace(string(content))
	}

	// Check if the value is an environment variable reference and resolve it
	if strings.HasPrefix(value, "env://") {
		envName := value[6:] // Remove "env://" prefix

		// Read the environment variable
		envValue := os.Getenv(envName)
		if envValue == "" {
			// Return original value if env var not set
			return value
		}

		// Return environment variable value
		return envValue
	}

	return value
}

// DNSOutputFormat wraps a DNS Provider as an OutputFormat for the output manager
// This allows the output manager to treat DNS providers as output profiles

type DNSOutputFormat struct {
	ProfileName string
	Provider    Provider
	Config      map[string]interface{}
}

func (d *DNSOutputFormat) GetName() string {
	return fmt.Sprintf("dns/%s", d.Provider.GetName())
}

func (d *DNSOutputFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return d.Provider.CreateOrUpdateRecord(domain, recordType, hostname, target, ttl, false)
}

func (d *DNSOutputFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	return d.Provider.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, false, "", source)
}

func (d *DNSOutputFormat) RemoveRecord(domain, hostname, recordType string) error {
	return d.Provider.DeleteRecord(domain, recordType, hostname)
}

func (d *DNSOutputFormat) Sync() error {
	// No-op for most DNS providers, but could be extended
	return nil
}

// CloudflareProvider implements the DNS provider interface for Cloudflare
// Add ProfileName for log prefix
type CloudflareProvider struct {
	client      *cloudflare.API
	config      map[string]string
	logger      *log.ScopedLogger
	retries     int
	timeout     time.Duration
	profileName string // store profile name
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
		profileName: profileName,
	}
	logger.Debug("Cloudflare DNS provider initialized (retries: %d, timeout: %v)", retries, timeout)
	return provider, nil
}

// Register the Cloudflare provider
func init() {
	RegisterProvider("cloudflare", func(config map[string]string) (interface{}, error) {
		profileName := config["profile_name"]
		return NewCloudflareProviderWithProfile(profileName, config)
	})
}

// Implement the Provider interface for CloudflareProvider
func (c *CloudflareProvider) CreateOrUpdateRecord(domain, recordType, name, target string, ttl int, proxied bool) error {
	return c.CreateOrUpdateRecordWithSource(domain, recordType, name, target, ttl, proxied, "", "herald")
}

func (c *CloudflareProvider) CreateOrUpdateRecordWithSource(domain, recordType, name, target string, ttl int, proxied bool, comment, source string) error {
	c.logger.Debug("Creating/updating record: %s.%s %s -> %s (TTL: %d, Proxied: %t)", name, domain, recordType, target, ttl, proxied)
	ctx := context.Background()
	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		c.logger.Error("Failed to get zone ID for domain %s: %v", domain, err)
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}
	fullName := name
	if name != "@" && name != "" && !strings.HasSuffix(name, "."+domain) {
		fullName = name + "." + domain
	} else if name == "@" {
		fullName = domain
	}
	existingRecord, err := c.findExistingRecord(ctx, zoneID, fullName, recordType)
	if err != nil {
		c.logger.Error("Failed to search for existing record: %v", err)
		return fmt.Errorf("failed to search for existing record: %v", err)
	}
	if existingRecord == nil {
		c.logger.Trace("No existing record found for update: %s %s %s", fullName, recordType, target)
	}
	recordParams := cloudflare.CreateDNSRecordParams{
		Type:    recordType,
		Name:    fullName,
		Content: target,
		TTL:     ttl,
		Proxied: &proxied,
	}
	rc := cloudflare.ZoneIdentifier(zoneID)
	if existingRecord != nil {
		c.logger.Debug("Updating existing record %s", existingRecord.ID)
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
		c.logger.Info("Updated DNS record: %s %s -> %s", fullName, recordType, target)
	} else {
		c.logger.Debug("Creating new record")
		_, err = c.client.CreateDNSRecord(ctx, rc, recordParams)
		if err != nil {
			return fmt.Errorf("failed to create DNS record: %v", err)
		}
		c.logger.Info("Created DNS record: %s %s -> %s", fullName, recordType, target)
	}
	return nil
}

func (c *CloudflareProvider) DeleteRecord(domain, recordType, name string) error {
	c.logger.Debug("Deleting record: %s.%s %s", name, domain, recordType)
	ctx := context.Background()
	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}
	fullName := name
	if name != "@" && name != "" && !strings.HasSuffix(name, "."+domain) {
		fullName = name + "." + domain
	} else if name == "@" {
		fullName = domain
	}
	existingRecord, err := c.findExistingRecord(ctx, zoneID, fullName, recordType)
	if err != nil {
		return fmt.Errorf("failed to search for existing record: %v", err)
	}
	if existingRecord == nil {
		c.logger.Warn("Record not found for deletion: %s %s", fullName, recordType)
		return nil
	}
	rc := cloudflare.ZoneIdentifier(zoneID)
	err = c.client.DeleteDNSRecord(ctx, rc, existingRecord.ID)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %v", err)
	}
	c.logger.Info("Deleted DNS record: %s %s", fullName, recordType)
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

func (c *CloudflareProvider) findExistingRecord(ctx context.Context, zoneID, name, recordType string) (*cloudflare.DNSRecord, error) {
	rc := cloudflare.ZoneIdentifier(zoneID)
	params := cloudflare.ListDNSRecordsParams{
		Name: name,
		Type: recordType,
	}
	c.logger.Trace("Searching for existing record: zoneID=%s, name=%s, type=%s", zoneID, name, recordType)
	records, _, err := c.client.ListDNSRecords(ctx, rc, params)
	if err != nil {
		c.logger.Error("Error searching DNS records: %v", err)
		return nil, fmt.Errorf("failed to search DNS records: %v", err)
	}
	c.logger.Trace("Found %d records for name=%s, type=%s", len(records), name, recordType)
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
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
	c.logger.Debug("Cloudflare provider validation successful")
	return nil
}
