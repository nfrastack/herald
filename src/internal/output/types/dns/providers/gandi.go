// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
)

type GandiProvider struct {
	*BaseProvider
	apiHost string
	apiKey  string
}

type gandiRRSet struct {
	Name   string   `json:"rrset_name"`
	Type   string   `json:"rrset_type"`
	TTL    int      `json:"rrset_ttl"`
	Values []string `json:"rrset_values"`
}

func NewGandiProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("gandi", config["profile_name"], config)

	apiKey := base.Secret("api_key", "token", "api_token")
	if apiKey == "" {
		return nil, fmt.Errorf("gandi provider requires 'api_key' parameter")
	}

	apiHost := base.Option("api_host", "https://api.gandi.net/v5/livedns")

	return &GandiProvider{BaseProvider: base, apiHost: apiHost, apiKey: apiKey}, nil
}

func init() {
	dns.RegisterProvider("gandi", NewGandiProvider)
}

func (p *GandiProvider) GetName() string {
	return "gandi"
}

func (p *GandiProvider) SupportsProxied() bool {
	return false
}

func (p *GandiProvider) headers() map[string]string {
	return map[string]string{
		"Authorization": "Apikey " + p.apiKey,
		"Content-Type":  "application/json",
	}
}

func (p *GandiProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *GandiProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	name := RelativeName(hostname, domain)

	body := map[string]interface{}{"rrset_values": []string{target}, "rrset_ttl": ttl}
	status, respBody, err := p.DoJSON("PUT", fmt.Sprintf("%s/domains/%s/records/%s/%s", p.apiHost, domain, name, recordType), p.headers(), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("gandi upsert record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *GandiProvider) DeleteRecord(domain, recordType, hostname string) error {
	name := RelativeName(hostname, domain)

	status, respBody, err := p.DoJSON("DELETE", fmt.Sprintf("%s/domains/%s/records/%s/%s", p.apiHost, domain, name, recordType), p.headers(), nil)
	if err != nil {
		return err
	}
	if status == 404 {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("gandi delete record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *GandiProvider) Validate() error {
	status, body, err := p.DoJSON("GET", p.apiHost+"/domains", p.headers(), nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("gandi validation failed: %d - %s", status, string(body))
	}
	return nil
}

func (p *GandiProvider) listRecords(domain string) ([]gandiRRSet, error) {
	status, body, err := p.DoJSON("GET", p.apiHost+"/domains/"+domain+"/records", p.headers(), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("gandi list records failed: %d - %s", status, string(body))
	}
	var out []gandiRRSet
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
