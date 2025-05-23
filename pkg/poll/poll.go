// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// Package poll provides polling mechanisms for DNS updates
package poll

import (
	"container-dns-companion/pkg/config"
	"container-dns-companion/pkg/dns"
	"container-dns-companion/pkg/log"

	"fmt"
	"strings"
	"sync"
	"time"
)

// Provider defines the interface for all poll providers
type Provider interface {
	// StartPolling starts polling for DNS changes
	StartPolling() error

	// StopPolling stops polling for DNS changes
	StopPolling() error

	// IsRunning returns whether the provider is running
	IsRunning() bool

	// GetDNSEntries returns all DNS entries from the provider
	GetDNSEntries() ([]DNSEntry, error)
}

// ProviderWithDomainConfigs allows setting domain configs on a poll provider
// (for providers that need domain config awareness, e.g., Docker)
type ProviderWithDomainConfigs interface {
	Provider
	SetDomainConfigs(map[string]config.DomainConfig)
}

// ContainerInfo represents information about a container
type ContainerInfo interface {
	// GetID returns the container ID
	GetID() string

	// GetHostname returns the hostname for the container
	GetHostname() string

	// GetTarget returns the target for the DNS record (IP address or hostname)
	GetTarget() string
}

// ProviderWithContainer extends Provider with methods for containers
type ProviderWithContainer interface {
	Provider

	// GetContainersForDomain returns all containers for a specific domain
	GetContainersForDomain(domain string) ([]ContainerInfo, error)

	// SetDNSProvider assigns a DNS provider for direct updates
	SetDNSProvider(provider dns.Provider)
}

// ContainerProvider interface for container-based poll providers
type ContainerProvider interface {
	GetDNSEntries() ([]DNSEntry, error)
}

// ProviderFactory is a function that creates a new poll provider
type ProviderFactory func(options map[string]string) (Provider, error)

var (
	providersMu sync.RWMutex
	providers   = make(map[string]ProviderFactory)
)

// RegisterProvider registers a new poll provider
func RegisterProvider(name string, factory ProviderFactory) {
	providersMu.Lock()
	defer providersMu.Unlock()
	if factory == nil {
		panic("[poll] RegisterProvider factory is nil")
	}
	if _, dup := providers[name]; dup {
		panic("[poll] RegisterProvider called twice for provider " + name)
	}
	providers[name] = factory
}

// GetProvider returns a provider by name
func GetProvider(name string, options map[string]string) (Provider, error) {
	providersMu.RLock()
	factory, ok := providers[name]
	providersMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("[poll] unknown poll provider: %s", name)
	}
	return factory(options)
}

// NewPollProvider creates a new poll provider with environment-specific settings
func NewPollProvider(name string, options map[string]string) (Provider, error) {
	return GetProvider(name, options)
}

// GetPoller returns a poller for a specific provider (for backward compatibility)
func GetPoller(name string, options map[string]string) (*Poller, error) {
	provider, err := GetProvider(name, options)
	if err != nil {
		return nil, err
	}

	containerProvider, ok := provider.(ContainerProvider)
	if !ok {
		return nil, fmt.Errorf("[poll] provider %s is not a container provider", name)
	}

	// Create a poller with the container provider (no DNS provider yet)
	return NewPoller(containerProvider, nil, "", nil, 60), nil
}

// DNSEntry represents a DNS entry to be created/updated
type DNSEntry struct {
	Hostname               string
	Domain                 string
	RecordType             string
	Target                 string
	TTL                    int
	Overwrite              bool
	RecordTypeAMultiple    bool
	RecordTypeAAAAMultiple bool
	SourceName             string // Source name for logging (container, router, etc)
}

// GetFQDN returns the fully qualified domain name
func (e DNSEntry) GetFQDN() string {
	if e.Hostname == "" || e.Hostname == "@" {
		return e.Domain
	}
	return e.Hostname + "." + e.Domain
}

// GetRecordType returns the record type
func (e DNSEntry) GetRecordType() string {
	if e.RecordType == "" {
		return "A"
	}
	return e.RecordType
}

// GetTarget returns the target
func (e DNSEntry) GetTarget() string {
	return e.Target
}

// GetTTL returns the TTL
func (e DNSEntry) GetTTL() int {
	if e.TTL <= 0 {
		return 60
	}
	return e.TTL
}

// ShouldOverwrite returns whether the record should be overwritten
func (e DNSEntry) ShouldOverwrite() bool {
	return e.Overwrite
}

// Poller polls the container provider for DNS entries and updates DNS
type Poller struct {
	containerProvider ContainerProvider
	dnsProvider       dns.Provider
	dnsProviderName   string
	dnsProviderParams map[string]string
	pollInterval      int
	lastPoll          time.Time
	defaultZoneID     string // Default zone ID to use if not specified in entry
}

// NewPoller creates a new Poller
func NewPoller(containerProvider ContainerProvider, dnsProvider dns.Provider, dnsProviderName string, dnsProviderParams map[string]string, pollInterval int) *Poller {
	return &Poller{
		containerProvider: containerProvider,
		dnsProvider:       dnsProvider,
		dnsProviderName:   dnsProviderName,
		dnsProviderParams: dnsProviderParams,
		pollInterval:      pollInterval,
	}
}

// SetDefaultZoneID sets the default zone ID to use when one is not specified
func (p *Poller) SetDefaultZoneID(zoneID string) {
	p.defaultZoneID = zoneID
}

// Poll polls the container provider for DNS entries and updates DNS
func (p *Poller) Poll() error {
	log.Debug("[poll] Starting poll cycle...")

	// Get DNS entries from container provider
	log.Debug("[poll] Calling containerProvider.GetDNSEntries()")
	entries, err := p.containerProvider.GetDNSEntries()
	if err != nil {
		return fmt.Errorf("[poll] failed to get DNS entries: %w", err)
	}

	log.Debug("[poll] Found %d DNS entries to process", len(entries))
	if len(entries) == 0 {
		log.Debug("[poll] No DNS entries found, skipping update")
		p.lastPoll = time.Now()
		return nil
	}

	// Process DNS entries
	if err := p.processDNSEntries(entries); err != nil {
		log.Error("[poll] Failed to process DNS entries: %v", err)
	}

	p.lastPoll = time.Now()
	log.Debug("[poll] Poll cycle completed at %s", p.lastPoll.Format(time.RFC3339))
	return nil
}

// processDNSEntries processes the DNS entries from containers
func (p *Poller) processDNSEntries(entries []DNSEntry) error {
	// Convert container DNSEntries to dns.Record objects
	dnsRecords := make([]dns.Record, 0, len(entries))

	for _, entry := range entries {
		// Skip empty entries
		if entry.Hostname == "" || entry.RecordType == "" || entry.Target == "" {
			continue
		}

		log.Debug("[poll] Processing DNS entry: %s (%s) -> %s", entry.Hostname, entry.RecordType, entry.Target)

		// Set TTL to default if not provided
		ttl := entry.TTL
		if ttl <= 0 {
			ttl = 300 // Default TTL of 5 minutes
		}

		// Set ZoneID or use default if not provided
		zoneID := p.defaultZoneID

		// Create a Record object
		record := dns.Record{
			Name:    entry.Hostname,
			Type:    entry.RecordType,
			Value:   entry.Target,
			TTL:     ttl,
			ZoneID:  zoneID,
			Proxied: false, // Default to not proxied
		}

		dnsRecords = append(dnsRecords, record)
	}

	// Now process each DNS record
	for _, record := range dnsRecords {
		// Extract domain config from record
		domain := dns.DomainConfig{
			Name:   extractDomainFromFQDN(record.Name),
			ZoneID: record.ZoneID,
		}

		// Extract hostname from record
		hostname := extractSubdomainFromFQDN(record.Name, domain.Name)

		// Check if record exists
		exists := false
		recordID, err := p.dnsProvider.GetRecordID(domain.Name, record.Type, hostname)
		if err != nil {
			log.Error("[poll] Error checking if record exists: %v", err)
			continue
		}

		exists = recordID != ""

		// Use overwrite=true by default (for backward compatibility)
		overwrite := true

		// Update or create record
		if exists {
			log.Debug("Record %s (%s) exists, updating", record.Name, record.Type)
			err = p.dnsProvider.CreateOrUpdateRecord(domain.Name, record.Type, hostname, record.Value, record.TTL, overwrite)
			if err != nil {
				log.Error("[poll] Error updating record: %v", err)
				continue
			}
		} else {
			log.Debug("Record %s (%s) does not exist, creating", record.Name, record.Type)
			err = p.dnsProvider.CreateOrUpdateRecord(domain.Name, record.Type, hostname, record.Value, record.TTL, overwrite)
			if err != nil {
				log.Error("[poll] Error creating record: %v", err)
				continue
			}
		}
	}

	return nil
}

// StartPolling starts polling for DNS entries
func (p *Poller) StartPolling() error {
	log.Info("[poll] Starting DNS poll cycle...")

	// Do an initial poll immediately
	if err := p.Poll(); err != nil {
		log.Error("[poll] Error during initial poll: %v", err)
	}

	// Create ticker for regular polling
	ticker := time.NewTicker(time.Duration(p.pollInterval) * time.Second)

	// Start polling in a goroutine
	go func() {
		for range ticker.C {
			log.Info("Polling for DNS entries (interval: %d seconds)...", p.pollInterval)
			if err := p.Poll(); err != nil {
				log.Error("[poll] Error polling for DNS entries: %v", err)
			}
		}
	}()

	return nil
}

// StopPolling stops polling for DNS entries
func (p *Poller) StopPolling() error {
	// Not implemented yet - would need a way to stop the ticker
	return nil
}

// Helper functions for domain name handling

// extractDomainFromFQDN extracts the domain part from a fully qualified domain name
func extractDomainFromFQDN(fqdn string) string {
	// Simple implementation - this might need to be enhanced based on your needs
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return fqdn // Not enough parts to extract a domain
	}

	// Take the last two parts as the domain (e.g., example.com)
	return strings.Join(parts[len(parts)-2:], ".")
}

// extractSubdomainFromFQDN extracts the subdomain part from a fully qualified domain name
func extractSubdomainFromFQDN(fqdn, domain string) string {
	// If FQDN equals domain, return @ (root)
	if fqdn == domain {
		return "@"
	}

	// If FQDN ends with domain, extract the subdomain
	if strings.HasSuffix(fqdn, domain) {
		subdomain := strings.TrimSuffix(fqdn, "."+domain)
		if subdomain != "" {
			return subdomain
		}
	}

	// If we couldn't extract a proper subdomain, return the original FQDN
	return fqdn
}

