// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
)

type HetznerProvider struct {
	*BaseProvider
	apiHost string
	token   string
}

type hetznerRecord struct {
	ID     string `json:"id"`
	ZoneID string `json:"zone_id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
}

func NewHetznerProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("hetzner", config["profile_name"], config)

	token := base.Secret("token", "api_token")
	if token == "" {
		return nil, fmt.Errorf("hetzner provider requires 'token' or 'api_token' parameter")
	}

	apiHost := base.Option("api_host", "https://dns.hetzner.com/api/v1")

	return &HetznerProvider{BaseProvider: base, apiHost: apiHost, token: token}, nil
}

func init() {
	dns.RegisterProvider("hetzner", NewHetznerProvider)
}

func (p *HetznerProvider) GetName() string {
	return "hetzner"
}

func (p *HetznerProvider) SupportsProxied() bool {
	return false
}

func (p *HetznerProvider) headers() map[string]string {
	return map[string]string{
		"Auth-API-Token": p.token,
		"Content-Type":   "application/json",
	}
}

func (p *HetznerProvider) zoneID(domain string) (string, error) {
	status, body, err := p.DoJSON("GET", p.apiHost+"/zones?name="+domain, p.headers(), nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("hetzner zone lookup failed: %d - %s", status, string(body))
	}
	var out struct {
		Zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if len(out.Zones) == 0 {
		return "", fmt.Errorf("hetzner: no zone found for domain %s", domain)
	}
	return out.Zones[0].ID, nil
}

func (p *HetznerProvider) listRecords(zoneID string) ([]hetznerRecord, error) {
	status, body, err := p.DoJSON("GET", p.apiHost+"/zones/"+zoneID+"/records?per_page=100", p.headers(), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("hetzner list records failed: %d - %s", status, string(body))
	}
	var out struct {
		Records []hetznerRecord `json:"records"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

func (p *HetznerProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *HetznerProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	name := RelativeName(hostname, domain)

	zoneID, err := p.zoneID(domain)
	if err != nil {
		return err
	}

	records, err := p.listRecords(zoneID)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			if r.Value == target && r.TTL == ttl {
				return nil
			}
			body := map[string]interface{}{"zone_id": zoneID, "type": recordType, "name": name, "value": target, "ttl": ttl}
			status, respBody, err := p.DoJSON("PUT", p.apiHost+"/records/"+r.ID, p.headers(), body)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("hetzner update record failed: %d - %s", status, string(respBody))
			}
			return nil
		}
	}

	body := map[string]interface{}{"zone_id": zoneID, "type": recordType, "name": name, "value": target, "ttl": ttl}
	status, respBody, err := p.DoJSON("POST", p.apiHost+"/records", p.headers(), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("hetzner create record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *HetznerProvider) DeleteRecord(domain, recordType, hostname string) error {
	name := RelativeName(hostname, domain)

	zoneID, err := p.zoneID(domain)
	if err != nil {
		return err
	}

	records, err := p.listRecords(zoneID)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Name == name {
			status, respBody, err := p.DoJSON("DELETE", p.apiHost+"/records/"+r.ID, p.headers(), nil)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("hetzner delete record failed: %d - %s", status, string(respBody))
			}
		}
	}
	return nil
}

func (p *HetznerProvider) Validate() error {
	status, body, err := p.DoJSON("GET", p.apiHost+"/zones", p.headers(), nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("hetzner validation failed: %d - %s", status, string(body))
	}
	return nil
}
