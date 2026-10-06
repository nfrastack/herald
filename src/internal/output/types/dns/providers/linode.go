// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
)

type LinodeProvider struct {
	*BaseProvider
	apiHost string
	token   string
}

type linodeRecord struct {
	ID     int    `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Target string `json:"target"`
	TTL    int    `json:"ttl_sec"`
}

func NewLinodeProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("linode", config["profile_name"], config)

	token := base.Secret("token", "api_token")
	if token == "" {
		return nil, fmt.Errorf("linode provider requires 'token' or 'api_token' parameter")
	}

	apiHost := base.Option("api_host", "https://api.linode.com/v4")

	return &LinodeProvider{BaseProvider: base, apiHost: apiHost, token: token}, nil
}

func init() {
	dns.RegisterProvider("linode", NewLinodeProvider)
}

func (p *LinodeProvider) GetName() string {
	return "linode"
}

func (p *LinodeProvider) SupportsProxied() bool {
	return false
}

func (p *LinodeProvider) headers() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + p.token,
		"Content-Type":  "application/json",
	}
}

func (p *LinodeProvider) name(hostname, domain string) string {
	if rel := RelativeName(hostname, domain); rel != "@" {
		return rel
	}
	return ""
}

func (p *LinodeProvider) domainID(domain string) (int, error) {
	status, body, err := p.DoJSON("GET", p.apiHost+"/domains?domain="+domain, p.headers(), nil)
	if err != nil {
		return 0, err
	}
	if status != 200 {
		return 0, fmt.Errorf("linode domain lookup failed: %d - %s", status, string(body))
	}
	var out struct {
		Data []struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, err
	}
	if len(out.Data) == 0 {
		return 0, fmt.Errorf("linode: no domain found for %s", domain)
	}
	return out.Data[0].ID, nil
}

func (p *LinodeProvider) listRecords(domainID int) ([]linodeRecord, error) {
	status, body, err := p.DoJSON("GET", fmt.Sprintf("%s/domains/%d/records", p.apiHost, domainID), p.headers(), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("linode list records failed: %d - %s", status, string(body))
	}
	var out struct {
		Data []linodeRecord `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func (p *LinodeProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *LinodeProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	name := p.name(hostname, domain)

	domainID, err := p.domainID(domain)
	if err != nil {
		return err
	}

	records, err := p.listRecords(domainID)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			if r.Target == target && r.TTL == ttl {
				return nil
			}
			body := map[string]interface{}{"target": target, "ttl_sec": ttl}
			status, respBody, err := p.DoJSON("PUT", fmt.Sprintf("%s/domains/%d/records/%d", p.apiHost, domainID, r.ID), p.headers(), body)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("linode update record failed: %d - %s", status, string(respBody))
			}
			return nil
		}
	}

	body := map[string]interface{}{"type": recordType, "name": name, "target": target, "ttl_sec": ttl}
	status, respBody, err := p.DoJSON("POST", fmt.Sprintf("%s/domains/%d/records", p.apiHost, domainID), p.headers(), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("linode create record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *LinodeProvider) DeleteRecord(domain, recordType, hostname string) error {
	name := p.name(hostname, domain)

	domainID, err := p.domainID(domain)
	if err != nil {
		return err
	}

	records, err := p.listRecords(domainID)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			status, respBody, err := p.DoJSON("DELETE", fmt.Sprintf("%s/domains/%d/records/%d", p.apiHost, domainID, r.ID), p.headers(), nil)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("linode delete record failed: %d - %s", status, string(respBody))
			}
		}
	}
	return nil
}

func (p *LinodeProvider) Validate() error {
	status, body, err := p.DoJSON("GET", p.apiHost+"/domains", p.headers(), nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("linode validation failed: %d - %s", status, string(body))
	}
	return nil
}
