// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"herald/pkg/log"
	"herald/pkg/output/types/common"

	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// RemoteFormat implements OutputFormat for remote API endpoints
type RemoteFormat struct {
	url      string
	clientID string
	token    string
	records  map[string]*RemoteRecord
	removals map[string]*RemoteRecord
	logger   *log.ScopedLogger
}

// RemoteRecord represents a DNS record for remote API
type RemoteRecord struct {
	Domain     string `json:"domain"`
	Hostname   string `json:"hostname"`
	Target     string `json:"target"`
	RecordType string `json:"type"`
	TTL        int    `json:"ttl"`
	Source     string `json:"source"`
}

// NewRemoteFormat creates a new remote format instance
func NewRemoteFormat(profileName string, config map[string]interface{}) (common.OutputFormat, error) {
	url, ok := config["url"].(string)
	if !ok || url == "" {
		return nil, fmt.Errorf("remote output requires 'url' field")
	}

	clientID, ok := config["client_id"].(string)
	if !ok || clientID == "" {
		return nil, fmt.Errorf("remote output requires 'client_id' field")
	}

	token, ok := config["token"].(string)
	if !ok || token == "" {
		return nil, fmt.Errorf("remote output requires 'token' field")
	}

	// Create scoped logger
	logLevel := ""
	if level, ok := config["log_level"].(string); ok {
		logLevel = level
	}
	logPrefix := fmt.Sprintf("[output/remote/%s]", profileName)
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	return &RemoteFormat{
		url:      url,
		clientID: clientID,
		token:    token,
		records:  make(map[string]*RemoteRecord),
		removals: make(map[string]*RemoteRecord),
		logger:   scopedLogger,
	}, nil
}

// GetName returns the format name
func (r *RemoteFormat) GetName() string {
	return "remote"
}

// WriteRecord writes a DNS record to the remote endpoint
func (r *RemoteFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return r.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

// WriteRecordWithSource writes a DNS record with source information to the remote endpoint
func (r *RemoteFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	key := fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)

	record := &RemoteRecord{
		Domain:     domain,
		Hostname:   hostname,
		Target:     target,
		RecordType: recordType,
		TTL:        ttl,
		Source:     source,
	}

	r.records[key] = record
	r.logger.Debug("Queued record: %s.%s (%s) -> %s", hostname, domain, recordType, target)
	r.logger.Debug("WriteRecordWithSource called: domain=%s, hostname=%s, recordType=%s, target=%s, ttl=%d, source=%s", domain, hostname, recordType, target, ttl, source)
	return nil
}

// RemoveRecord removes a DNS record from the remote endpoint
func (r *RemoteFormat) RemoveRecord(domain, hostname, recordType string) error {
	key := fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)
	if rec, exists := r.records[key]; exists {
		delete(r.records, key)
		r.removals[key] = rec
		r.logger.Debug("Removed record: %s.%s (%s) [queued for API removal]", hostname, domain, recordType)
	} else {
		r.removals[key] = &RemoteRecord{
			Domain:     domain,
			Hostname:   hostname,
			RecordType: recordType,
		}
		r.logger.Debug("Queued removal for missing record: %s.%s (%s)", hostname, domain, recordType)
	}
	return nil
}

// Sync sends all records to the remote endpoint
func (r *RemoteFormat) Sync() error {
	// Always perform sync, even if there are no records or removals
	// This ensures zone files and remote endpoints are updated for SOA/NS/serial, etc.

	// Group additions by domain
	additionsByDomain := make(map[string][]*RemoteRecord)
	for _, record := range r.records {
		additionsByDomain[record.Domain] = append(additionsByDomain[record.Domain], record)
	}

	// Group removals by domain
	removalsByDomain := make(map[string][]*RemoteRecord)
	for _, record := range r.removals {
		removalsByDomain[record.Domain] = append(removalsByDomain[record.Domain], record)
	}

	// Collect all domains that have either additions or removals
	allDomains := make(map[string]struct{})
	for domain := range additionsByDomain {
		allDomains[domain] = struct{}{}
	}
	for domain := range removalsByDomain {
		allDomains[domain] = struct{}{}
	}

	generator := "herald"
	metadata := map[string]interface{}{
		"generator":    generator,
		"generated_at": time.Now().Format(time.RFC3339),
		"last_updated": time.Now().Format(time.RFC3339),
	}

	// Build domains map for payload, always include all domains
	domains := make(map[string]map[string]interface{})
	for domain := range allDomains {
		records := additionsByDomain[domain]
		if records == nil {
			records = []*RemoteRecord{} // ensure empty slice, not nil
		}
		domains[domain] = map[string]interface{}{
			"records": records,
		}
	}

	payload := map[string]interface{}{
		"client_id": r.clientID,
		"metadata":  metadata,
		"domains":   domains,
		"removals":  removalsByDomain, // still send removals for delta sync
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	r.logger.Trace("Sync payload: %s", string(jsonData))

	// Create HTTP request
	req, err := http.NewRequest("POST", r.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("X-Client-ID", r.clientID)
	req.Header.Set("User-Agent", generator)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote API returned status %d", resp.StatusCode)
	}

	r.logger.Info("Successfully synced %d records and %d removals to remote endpoint", len(r.records), len(r.removals))
	// Clear records and removals after successful sync
	r.records = make(map[string]*RemoteRecord)
	r.removals = make(map[string]*RemoteRecord)
	return nil
}

var _ common.OutputFormat = (*RemoteFormat)(nil)
