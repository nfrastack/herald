// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
)

type DigitalOceanProvider struct {
	*BaseProvider
	apiHost string
	token   string
}

type digitalOceanRecord struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func NewDigitalOceanProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("digitalocean", config["profile_name"], config)

	token := base.Secret("token", "api_token")
	if token == "" {
		return nil, fmt.Errorf("digitalocean provider requires 'token' or 'api_token' parameter")
	}

	apiHost := base.Option("api_host", "https://api.digitalocean.com")

	return &DigitalOceanProvider{BaseProvider: base, apiHost: apiHost, token: token}, nil
}

func init() {
	dns.RegisterProvider("digitalocean", NewDigitalOceanProvider)
}

func (p *DigitalOceanProvider) GetName() string {
	return "digitalocean"
}

func (p *DigitalOceanProvider) SupportsProxied() bool {
	return false
}

func (p *DigitalOceanProvider) headers() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + p.token,
		"Content-Type":  "application/json",
	}
}

func (p *DigitalOceanProvider) listRecords(domain string) ([]digitalOceanRecord, error) {
	status, body, err := p.DoJSON("GET", p.apiHost+"/v2/domains/"+domain+"/records?per_page=200", p.headers(), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("digitalocean list records failed: %d - %s", status, string(body))
	}
	var out struct {
		Records []digitalOceanRecord `json:"domain_records"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

func (p *DigitalOceanProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *DigitalOceanProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	name := RelativeName(hostname, domain)

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
			status, respBody, err := p.DoJSON("PUT", fmt.Sprintf("%s/v2/domains/%s/records/%d", p.apiHost, domain, r.ID), p.headers(), body)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("digitalocean update record failed: %d - %s", status, string(respBody))
			}
			return nil
		}
	}

	body := map[string]interface{}{"type": recordType, "name": name, "data": target, "ttl": ttl}
	status, respBody, err := p.DoJSON("POST", p.apiHost+"/v2/domains/"+domain+"/records", p.headers(), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("digitalocean create record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *DigitalOceanProvider) DeleteRecord(domain, recordType, hostname string) error {
	name := RelativeName(hostname, domain)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			status, respBody, err := p.DoJSON("DELETE", fmt.Sprintf("%s/v2/domains/%s/records/%d", p.apiHost, domain, r.ID), p.headers(), nil)
			if err != nil {
				return err
			}
			if status != 204 && (status < 200 || status >= 300) {
				return fmt.Errorf("digitalocean delete record failed: %d - %s", status, string(respBody))
			}
		}
	}
	return nil
}

func (p *DigitalOceanProvider) Validate() error {
	status, body, err := p.DoJSON("GET", p.apiHost+"/v2/domains", p.headers(), nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("digitalocean validation failed: %d - %s", status, string(body))
	}
	return nil
}
