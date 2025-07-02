// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package types

// Provider interface defines the methods that all input providers must implement
type Provider interface {
	StartPolling() error
	StopPolling() error
	GetName() string
	GetDNSEntries() ([]DNSEntry, error)
}

// ProviderWithContainer interface for providers that support container operations
type ProviderWithContainer interface {
	Provider
	GetContainerState(containerID string) (map[string]interface{}, error)
}

// DNSEntry represents a DNS entry from input providers
type DNSEntry struct {
	Name                   string `json:"name"`
	Hostname               string `json:"hostname"`
	Domain                 string `json:"domain"`
	RecordType             string `json:"type"`
	Target                 string `json:"target"`
	TTL                    int    `json:"ttl"`
	Overwrite              bool   `json:"overwrite"`
	RecordTypeAMultiple    bool   `json:"record_type_a_multiple"`
	RecordTypeAAAAMultiple bool   `json:"record_type_aaaa_multiple"`
	SourceName             string `json:"source_name"`
}

func (d DNSEntry) GetFQDN() string {
	return d.Name
}

func (d DNSEntry) GetRecordType() string {
	return d.RecordType
}
