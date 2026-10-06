// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
)

type VultrProvider struct {
	*BaseProvider
	apiHost string
	token   string
}

type vultrRecord struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func NewVultrProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("vultr", config["profile_name"], config)

	token := base.Secret("token", "api_token")
	if token == "" {
		return nil, fmt.Errorf("vultr provider requires 'token' or 'api_token' parameter")
	}

	apiHost := base.Option("api_host", "https://api.vultr.com/v2")

	return &VultrProvider{BaseProvider: base, apiHost: apiHost, token: token}, nil
}

func init() {
	dns.RegisterProvider("vultr", NewVultrProvider)
}

func (p *VultrProvider) GetName() string {
	return "vultr"
}

func (p *VultrProvider) SupportsProxied() bool {
	return false
}

func (p *VultrProvider) headers() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + p.token,
		"Content-Type":  "application/json",
	}
}

func (p *VultrProvider) name(hostname, domain string) string {
	if rel := RelativeName(hostname, domain); rel != "@" {
		return rel
	}
	return ""
}

func (p *VultrProvider) listRecords(domain string) ([]vultrRecord, error) {
	status, body, err := p.DoJSON("GET", p.apiHost+"/domains/"+domain+"/records?per_page=500", p.headers(), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("vultr list records failed: %d - %s", status, string(body))
	}
	var out struct {
		Records []vultrRecord `json:"records"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

func (p *VultrProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *VultrProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	name := p.name(hostname, domain)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			if r.Data == target && r.TTL == ttl {
				return nil
			}
			body := map[string]interface{}{"data": target, "ttl": ttl}
			status, respBody, err := p.DoJSON("PATCH", fmt.Sprintf("%s/domains/%s/records/%s", p.apiHost, domain, r.ID), p.headers(), body)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("vultr update record failed: %d - %s", status, string(respBody))
			}
			return nil
		}
	}

	body := map[string]interface{}{"type": recordType, "name": name, "data": target, "ttl": ttl}
	status, respBody, err := p.DoJSON("POST", p.apiHost+"/domains/"+domain+"/records", p.headers(), body)
	if err != nil {
		return err
	}
	if status != 201 && (status < 200 || status >= 300) {
		return fmt.Errorf("vultr create record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *VultrProvider) DeleteRecord(domain, recordType, hostname string) error {
	name := p.name(hostname, domain)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			status, respBody, err := p.DoJSON("DELETE", fmt.Sprintf("%s/domains/%s/records/%s", p.apiHost, domain, r.ID), p.headers(), nil)
			if err != nil {
				return err
			}
			if status != 204 && (status < 200 || status >= 300) {
				return fmt.Errorf("vultr delete record failed: %d - %s", status, string(respBody))
			}
		}
	}
	return nil
}

func (p *VultrProvider) Validate() error {
	status, body, err := p.DoJSON("GET", p.apiHost+"/domains", p.headers(), nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("vultr validation failed: %d - %s", status, string(body))
	}
	return nil
}
