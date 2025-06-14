// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// DNS Provider Template
// This file serves as a template for implementing new DNS providers for Herald.
// Replace "PROVIDER" with your actual provider name (e.g., "route53", "digitalocean", etc.)

package output

import (
	"herald/pkg/log"
	"herald/pkg/util"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// STEP 1: Define your DNS record structure
// This should match what your DNS provider's API expects
type providerDNSRecord struct {
	Domain     string
	Hostname   string
	Target     string
	RecordType string
	TTL        int
	Source     string
	ID         string // Provider-specific record ID (if supported)
	// Add any provider-specific fields here
	// Example:
	// Priority int    `json:"priority,omitempty"` // For MX records
	// Weight   int    `json:"weight,omitempty"`   // For SRV records
}

// STEP 2: Define your provider format structure
// This holds the configuration and state for your DNS provider
type providerFormat struct {
	profileName string
	config      map[string]interface{}

	// REQUIRED: Authentication credentials
	// Choose the appropriate authentication method for your provider:
	apiToken string // For token-based auth (like Cloudflare)
	// apiKey      string // For API key-based auth
	// username    string // For username/password auth
	// password    string // For username/password auth
	// secretKey   string // For AWS-style auth
	// accessKey   string // For AWS-style auth

	// OPTIONAL: Provider-specific configuration
	// endpoint    string // For custom API endpoints
	// region      string // For region-specific providers
	// namespace   string // For namespaced providers

	records map[string]*providerDNSRecord
	mutex   sync.RWMutex
}

// STEP 3: Implement the OutputFormat interface
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

// STEP 4: Implement the main sync logic
func (p *providerFormat) syncSingleRecord(record *providerDNSRecord) error {
	// IMPLEMENTATION PATTERN:
	// 1. Get domain/zone information (if needed)
	// 2. Check if record already exists
	// 3. Create or update the record
	// 4. Handle errors appropriately

	// Example implementation:
	/*
		// Step 1: Get zone ID (if your provider uses zones)
		zoneID, err := p.getZoneID(record.Domain)
		if err != nil {
			return fmt.Errorf("failed to get zone ID for domain %s: %v", record.Domain, err)
		}

		// Step 2: Check if record already exists
		existingRecordID, err := p.findExistingRecord(zoneID, record)
		if err != nil {
			return fmt.Errorf("failed to check existing record: %v", err)
		}

		// Step 3: Create or update
		if existingRecordID != "" {
			return p.updateRecord(zoneID, existingRecordID, record)
		} else {
			return p.createRecord(zoneID, record)
		}
	*/

	// For now, just log what would happen
	log.Info("[output/PROVIDER] Would sync record: %s.%s %s -> %s",
		record.Hostname, record.Domain, record.RecordType, record.Target)
	return nil
}

// STEP 5: Implement helper methods for your provider's API
// These methods will vary significantly based on your provider's API structure

func (p *providerFormat) getZoneID(domain string) (string, error) {
	// EXAMPLE: Get zone/domain ID from your provider
	// This is needed for providers that organize records under zones/domains

	url := "https://api.PROVIDER.com/v1/domains/" + domain // Replace with actual API endpoint

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// AUTHENTICATION: Choose the appropriate method
	req.Header.Set("Authorization", "Bearer "+p.apiToken) // Token auth
	// req.Header.Set("X-API-Key", p.apiKey)               // API key auth
	// req.SetBasicAuth(p.username, p.password)            // Basic auth

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

	// PARSE RESPONSE: Adjust based on your provider's response format
	var response struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		// Add other fields as needed
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	return response.ID, nil
}

func (p *providerFormat) findExistingRecord(zoneID string, record *providerDNSRecord) (string, error) {
	// EXAMPLE: Check if a DNS record already exists

	recordName := record.Hostname + "." + record.Domain
	if record.Hostname == "@" || record.Hostname == "" {
		recordName = record.Domain
	}

	// Construct API URL based on your provider's API
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

	// PARSE RESPONSE: Adjust based on your provider's response format
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
	// EXAMPLE: Create a new DNS record

	recordName := record.Hostname + "." + record.Domain
	if record.Hostname == "@" || record.Hostname == "" {
		recordName = record.Domain
	}

	// PAYLOAD: Adjust based on your provider's API requirements
	payload := map[string]interface{}{
		"type":    record.RecordType,
		"name":    recordName,
		"content": record.Target,
		"ttl":     record.TTL,
		// Add provider-specific fields as needed:
		// "priority": record.Priority, // For MX records
		// "weight":   record.Weight,   // For SRV records
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
	// EXAMPLE: Update an existing DNS record

	recordName := record.Hostname + "." + record.Domain
	if record.Hostname == "@" || record.Hostname == "" {
		recordName = record.Domain
	}

	// PAYLOAD: Adjust based on your provider's API requirements
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

// STEP 6: Create the factory function
// This function will be called by Herald to create instances of your provider
func createPROVIDEROutputDirect(profileName string, config map[string]interface{}) (OutputFormat, error) {
	// VALIDATION: Check required configuration fields
	apiTokenRaw, ok := config["api_token"]
	if !ok || apiTokenRaw == nil {
		return nil, fmt.Errorf("PROVIDER DNS requires 'api_token' field")
	}

	apiToken := apiTokenRaw.(string)
	apiToken = util.ReadSecretValue(apiToken) // Handles file:// and env:// references

	if apiToken == "" {
		return nil, fmt.Errorf("PROVIDER DNS api_token cannot be empty after processing")
	}

	// OPTIONAL: Validate other configuration fields
	// endpoint, _ := config["endpoint"].(string)
	// if endpoint == "" {
	//     endpoint = "https://api.PROVIDER.com" // Default endpoint
	// }

	return &providerFormat{
		profileName: profileName,
		config:      config,
		apiToken:    apiToken,
		// endpoint:    endpoint,
		records: make(map[string]*providerDNSRecord),
	}, nil
}

// STEP 7: Register your provider (add this to the init() function in output.go)
// You'll need to add this line to the registerAllCoreFormats() function:
// RegisterFormat("dns/PROVIDER", createPROVIDEROutputDirect)

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
