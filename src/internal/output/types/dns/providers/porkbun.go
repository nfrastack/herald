// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
)

type PorkbunProvider struct {
	*BaseProvider
	apiHost string
	apiKey  string
	secret  string
}

type porkbunRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
}

func NewPorkbunProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("porkbun", config["profile_name"], config)

	apiKey := base.Secret("api_key", "apiKey")
	if apiKey == "" {
		return nil, fmt.Errorf("porkbun provider requires 'api_key' parameter")
	}
	secret := base.Secret("secret_key", "secretapikey", "secret")
	if secret == "" {
		return nil, fmt.Errorf("porkbun provider requires 'secret_key' parameter")
	}

	apiHost := base.Option("api_host", "https://api.porkbun.com/api/json/v3")

	return &PorkbunProvider{BaseProvider: base, apiHost: apiHost, apiKey: apiKey, secret: secret}, nil
}

func init() {
	dns.RegisterProvider("porkbun", NewPorkbunProvider)
}

func (p *PorkbunProvider) GetName() string {
	return "porkbun"
}

func (p *PorkbunProvider) SupportsProxied() bool {
	return false
}

func (p *PorkbunProvider) auth() map[string]interface{} {
	return map[string]interface{}{"apikey": p.apiKey, "secretapikey": p.secret}
}

func (p *PorkbunProvider) call(path string, payload map[string]interface{}) (int, []byte, error) {
	if payload == nil {
		payload = p.auth()
	} else {
		for k, v := range p.auth() {
			payload[k] = v
		}
	}
	return p.DoJSON("POST", p.apiHost+path, map[string]string{"Content-Type": "application/json"}, payload)
}

func (p *PorkbunProvider) check(status int, body []byte, op string) error {
	var out struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("porkbun %s failed: %d - %s", op, status, string(body))
	}
	if out.Status != "SUCCESS" {
		return fmt.Errorf("porkbun %s failed: %d - %s", op, status, string(body))
	}
	return nil
}

func (p *PorkbunProvider) listRecords(domain string) ([]porkbunRecord, error) {
	status, body, err := p.call("/dns/retrieve/"+domain, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Status  string          `json:"status"`
		Records []porkbunRecord `json:"records"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("porkbun retrieve failed: %d - %s", status, string(body))
	}
	if out.Status != "SUCCESS" {
		return nil, fmt.Errorf("porkbun retrieve failed: %d - %s", status, string(body))
	}
	return out.Records, nil
}

func (p *PorkbunProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *PorkbunProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	name := RelativeName(hostname, domain)
	ttlStr := fmt.Sprintf("%d", ttl)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			if r.Content == target && r.TTL == ttlStr {
				return nil
			}
			payload := map[string]interface{}{"name": name, "type": recordType, "content": target, "ttl": ttlStr}
			status, respBody, err := p.call("/dns/edit/"+domain+"/"+r.ID, payload)
			if err != nil {
				return err
			}
			return p.check(status, respBody, "update record")
		}
	}

	payload := map[string]interface{}{"name": name, "type": recordType, "content": target, "ttl": ttlStr}
	status, respBody, err := p.call("/dns/create/"+domain, payload)
	if err != nil {
		return err
	}
	return p.check(status, respBody, "create record")
}

func (p *PorkbunProvider) DeleteRecord(domain, recordType, hostname string) error {
	name := RelativeName(hostname, domain)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			status, respBody, err := p.call("/dns/delete/"+domain+"/"+r.ID, nil)
			if err != nil {
				return err
			}
			if err := p.check(status, respBody, "delete record"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *PorkbunProvider) Validate() error {
	if p.apiKey == "" || p.secret == "" {
		return fmt.Errorf("porkbun provider requires 'api_key' and 'secret_key' parameters")
	}
	return nil
}
