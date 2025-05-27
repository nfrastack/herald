// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package outputCommon

import (
	"fmt"
	"strings"
	"time"
)

// BaseMetadata contains common metadata fields
type BaseMetadata struct {
	Generator   string    `json:"generator" yaml:"generator"`
	Hostname    string    `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
	Comment     string    `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// BaseRecord represents a DNS record in formats
type BaseRecord struct {
	Hostname  string    `json:"hostname" yaml:"hostname"`
	Type      string    `json:"type" yaml:"type"`
	Target    string    `json:"target" yaml:"target"`
	TTL       uint32    `json:"ttl" yaml:"ttl"`
	Comment   string    `json:"comment,omitempty" yaml:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	Source    string    `json:"source,omitempty" yaml:"source,omitempty"`
}

// BaseDomain represents a domain in formats
type BaseDomain struct {
	Comment  string        `json:"comment,omitempty" yaml:"comment,omitempty"`
	ZoneID   string        `json:"zone_id,omitempty" yaml:"zone_id,omitempty"`
	Provider string        `json:"provider,omitempty" yaml:"provider,omitempty"`
	Records  []*BaseRecord `json:"records" yaml:"records"`
}

// ExportData represents the common export structure
type ExportData struct {
	Metadata *BaseMetadata          `json:"metadata" yaml:"metadata"`
	Domains  map[string]*BaseDomain `json:"domains" yaml:"domains"`
}

// Utility functions

// NormalizeHostname normalizes hostname for consistent processing
func NormalizeHostname(hostname, domain string) string {
	if hostname == "@" || hostname == domain {
		return "@"
	}
	if strings.HasSuffix(hostname, "."+domain) {
		return strings.TrimSuffix(hostname, "."+domain)
	}
	return hostname
}

// RecordKey generates a unique key for a DNS record
func RecordKey(domain, hostname, recordType string) string {
	return fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)
}
