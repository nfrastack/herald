// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package output

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/util"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type providerDNSRecord struct {
	Domain     string
	Hostname   string
	Target     string
	RecordType string
	TTL        int
	Source     string
	ID         string // Provider-specific record ID (if supported)
}

type providerFormat struct {
	profileName string
	config      map[string]interface{}

	apiToken string // For token-based auth (like Cloudflare)

	records map[string]*providerDNSRecord
	mutex   sync.RWMutex
}

func (p *providerFormat) GetName() string {
	return "PROVIDER" // Replace with your provider name
}

func (p *providerFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return p.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

func (p *providerFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	key := fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)
	p.records[key] = &providerDNSRecord{
		Domain:     domain,
		Hostname:   hostname,
		Target:     target,
		RecordType: recordType,
		TTL:        ttl,
		Source:     source,
		ID:         "", // Will be set after API call
	}

	log.Debug("[output/PROVIDER/%s] Added record: %s %s -> %s (TTL: %d)",
		strings.ReplaceAll(domain, ".", "_"), hostname, recordType, target, ttl)
	return nil
}

func (p *providerFormat) RemoveRecord(domain, hostname, recordType string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	key := fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)
	delete(p.records, key)
	return nil
}

func (p *providerFormat) Sync() error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if len(p.records) == 0 {
		log.Debug("[output/PROVIDER] No records to sync")
		return nil
	}

	log.Info("[output/PROVIDER] Syncing %d records to PROVIDER DNS", len(p.records))

	for key, record := range p.records {
		err := p.syncSingleRecord(record)
		if err != nil {
			log.Error("[output/PROVIDER] Failed to sync record %s: %v", key, err)
			return err
		}
	}

	log.Info("[output/PROVIDER] Successfully synced %d records to PROVIDER", len(p.records))
	return nil
}

func (p *providerFormat) syncSingleRecord(record *providerDNSRecord) error {

	/*
		zoneID, err := p.getZoneID(record.Domain)
		if err != nil {
			return fmt.Errorf("failed to get zone ID for domain %s: %v", record.Domain, err)
		}

		existingRecordID, err := p.findExistingRecord(zoneID, record)
		if err != nil {
			return fmt.Errorf("failed to check existing record: %v", err)
		}

		if existingRecordID != "" {
			return p.updateRecord(zoneID, existingRecordID, record)
		} else {
			return p.createRecord(zoneID, record)
		}
	*/

	log.Info("[output/PROVIDER] Would sync record: %s.%s %s -> %s",
		record.Hostname, record.Domain, record.RecordType, record.Target)
	return nil
}

func (p *providerFormat) getZoneID(domain string) (string, error) {

	url := "https://api.PROVIDER.com/v1/domains/" + domain // Replace with actual API endpoint

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiToken) // Token auth

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("provider API error %d: %s", resp.StatusCode, string(body))
	}

	var response struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	return response.ID, nil
}

func (p *providerFormat) findExistingRecord(zoneID string, record *providerDNSRecord) (string, error) {

	recordName := record.Hostname + "." + record.Domain
	if record.Hostname == "@" || record.Hostname == "" {
		recordName = record.Domain
	}

	url := fmt.Sprintf("https://api.PROVIDER.com/v1/domains/%s/records?name=%s&type=%s",
		zoneID, recordName, record.RecordType)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return "", nil // No existing record
		}
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("provider API error %d: %s", resp.StatusCode, string(body))
	}

	var response struct {
		Records []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
		} `json:"records"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	if len(response.Records) > 0 {
		return response.Records[0].ID, nil
	}

	return "", nil // No existing record found
}

func (p *providerFormat) createRecord(zoneID string, record *providerDNSRecord) error {

	recordName := record.Hostname + "." + record.Domain
	if record.Hostname == "@" || record.Hostname == "" {
		recordName = record.Domain
	}

	payload := map[string]interface{}{
		"type":    record.RecordType,
		"name":    recordName,
		"content": record.Target,
		"ttl":     record.TTL,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.PROVIDER.com/v1/domains/%s/records", zoneID)

	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonBytes)))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create record: %d %s", resp.StatusCode, string(body))
	}

	log.Info("[output/PROVIDER] Created DNS record: %s %s -> %s", recordName, record.RecordType, record.Target)
	return nil
}

func (p *providerFormat) updateRecord(zoneID, recordID string, record *providerDNSRecord) error {

	recordName := record.Hostname + "." + record.Domain
	if record.Hostname == "@" || record.Hostname == "" {
		recordName = record.Domain
	}

	payload := map[string]interface{}{
		"type":    record.RecordType,
		"name":    recordName,
		"content": record.Target,
		"ttl":     record.TTL,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.PROVIDER.com/v1/domains/%s/records/%s", zoneID, recordID)

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(jsonBytes)))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update record: %d %s", resp.StatusCode, string(body))
	}

	log.Info("[output/PROVIDER] Updated DNS record: %s %s -> %s", recordName, record.RecordType, record.Target)
	return nil
}

func createPROVIDEROutputDirect(profileName string, config map[string]interface{}) (OutputFormat, error) {
	apiTokenRaw, ok := config["api_token"]
	if !ok || apiTokenRaw == nil {
		return nil, fmt.Errorf("PROVIDER DNS requires 'api_token' field")
	}

	apiToken := apiTokenRaw.(string)
	apiToken = util.ReadSecretValue(apiToken) // Handles file:// and env:// references

	if apiToken == "" {
		return nil, fmt.Errorf("PROVIDER DNS api_token cannot be empty after processing")
	}

	return &providerFormat{
		profileName: profileName,
		config:      config,
		apiToken:    apiToken,
		records:     make(map[string]*providerDNSRecord),
	}, nil
}

/*
CONFIGURATION EXAMPLE:

Add this to your herald.yml config file:

outputs:
  my_provider_dns:
    type: dns
    provider: PROVIDER
    api_token: "file:///path/to/token.txt"  # or env://PROVIDER_API_TOKEN
    # Add other provider-specific config as needed:
    # endpoint: "https://api.PROVIDER.com"
    # region: "us-east-1"

domains:
  example.com:
    profiles:
      inputs: [docker_input]
      outputs: [my_provider_dns]

USAGE NOTES:

1. Replace all instances of "PROVIDER" with your actual provider name
2. Update API endpoints to match your provider's documentation
3. Adjust authentication method (token, API key, username/password, etc.)
4. Modify request/response structures to match your provider's API
5. Add any provider-specific fields or configuration options
6. Test thoroughly with your provider's API documentation
7. Add appropriate error handling for your provider's specific error responses
8. Consider rate limiting if your provider has API limits

TESTING:

1. Create a test configuration with your provider credentials
2. Test with different record types (A, AAAA, CNAME, MX, etc.)
3. Test create, update, and delete operations
4. Test error conditions (invalid domains, auth failures, etc.)
5. Test with different TTL values
6. Verify records are created correctly in your provider's dashboard

DOCUMENTATION:

Document the following for users:
1. Required configuration fields
2. Optional configuration fields
3. Authentication setup instructions
4. Any provider-specific limitations
5. Supported record types
6. Rate limiting considerations
*/
