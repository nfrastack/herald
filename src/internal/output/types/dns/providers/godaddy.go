// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
)

type GoDaddyProvider struct {
	*BaseProvider
	apiHost   string
	apiKey    string
	apiSecret string
}

type godaddyRecord struct {
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func NewGoDaddyProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("godaddy", config["profile_name"], config)

	apiKey := base.Secret("api_key", "key")
	if apiKey == "" {
		return nil, fmt.Errorf("godaddy provider requires 'api_key' parameter")
	}
	apiSecret := base.Secret("api_secret", "secret")
	if apiSecret == "" {
		return nil, fmt.Errorf("godaddy provider requires 'api_secret' parameter")
	}

	apiHost := base.Option("api_host", "https://api.godaddy.com")

	return &GoDaddyProvider{BaseProvider: base, apiHost: apiHost, apiKey: apiKey, apiSecret: apiSecret}, nil
}

func init() {
	dns.RegisterProvider("godaddy", NewGoDaddyProvider)
}

func (p *GoDaddyProvider) GetName() string {
	return "godaddy"
}

func (p *GoDaddyProvider) SupportsProxied() bool {
	return false
}

func (p *GoDaddyProvider) headers() map[string]string {
	return map[string]string{
		"Authorization": "sso-key " + p.apiKey + ":" + p.apiSecret,
		"Content-Type":  "application/json",
	}
}

func (p *GoDaddyProvider) recordPath(domain, recordType, hostname string) string {
	return fmt.Sprintf("%s/v1/domains/%s/records/%s/%s", p.apiHost, domain, recordType, RelativeName(hostname, domain))
}

func (p *GoDaddyProvider) listRecords(domain, recordType, hostname string) ([]godaddyRecord, error) {
	status, body, err := p.DoJSON("GET", p.recordPath(domain, recordType, hostname), p.headers(), nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, nil
	}
	if status != 200 {
		return nil, fmt.Errorf("godaddy list records failed: %d - %s", status, string(body))
	}
	var out []godaddyRecord
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *GoDaddyProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *GoDaddyProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	existing, err := p.listRecords(domain, recordType, hostname)
	if err != nil {
		return err
	}
	if len(existing) == 1 && existing[0].Data == target && existing[0].TTL == ttl {
		return nil
	}

	body := []godaddyRecord{{Data: target, TTL: ttl}}
	status, respBody, err := p.DoJSON("PUT", p.recordPath(domain, recordType, hostname), p.headers(), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("godaddy upsert record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *GoDaddyProvider) DeleteRecord(domain, recordType, hostname string) error {
	status, respBody, err := p.DoJSON("DELETE", p.recordPath(domain, recordType, hostname), p.headers(), nil)
	if err != nil {
		return err
	}
	if status == 404 {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("godaddy delete record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *GoDaddyProvider) Validate() error {
	status, body, err := p.DoJSON("GET", p.apiHost+"/v1/domains?limit=1", p.headers(), nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("godaddy validation failed: %d - %s", status, string(body))
	}
	return nil
}
