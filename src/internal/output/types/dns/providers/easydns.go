// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type EasyDNSProvider struct {
	*BaseProvider
	apiHost string
	token   string
	key     string
}

type easyDNSRecord struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Rdata    string `json:"rdata"`
	TTL      string `json:"ttl"`
	Priority string `json:"priority"`
}

type easyDNSEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

func NewEasyDNSProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("easydns", config["profile_name"], config)

	token := base.Secret("token")
	if token == "" {
		return nil, fmt.Errorf("easydns provider requires 'token' parameter")
	}
	key := base.Secret("api_key", "key")
	if key == "" {
		return nil, fmt.Errorf("easydns provider requires 'api_key' parameter")
	}

	apiHost := base.Option("api_host", "https://rest.easydns.net")

	return &EasyDNSProvider{BaseProvider: base, apiHost: apiHost, token: token, key: key}, nil
}

func init() {
	dns.RegisterProvider("easydns", NewEasyDNSProvider)
}

func (p *EasyDNSProvider) GetName() string {
	return "easydns"
}

func (p *EasyDNSProvider) SupportsProxied() bool {
	return false
}

func (p *EasyDNSProvider) headers(jsonBody bool) map[string]string {
	creds := base64.StdEncoding.EncodeToString([]byte(p.token + ":" + p.key))
	h := map[string]string{
		"Authorization": "Basic " + creds,
		"Accept":        "application/json",
	}
	if jsonBody {
		h["Content-Type"] = "application/json"
	}
	return h
}

func (p *EasyDNSProvider) listRecords(domain string) ([]easyDNSRecord, error) {
	status, body, err := p.DoJSON("GET", p.apiHost+"/zones/records/all/"+domain+"?format=json", p.headers(false), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("easydns list records failed: %d - %s", status, string(body))
	}
	var env easyDNSEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, fmt.Errorf("easydns list records failed: %s", env.Error.Message)
	}
	var out []easyDNSRecord
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *EasyDNSProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *EasyDNSProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	host := RelativeName(hostname, domain)
	ttlStr := fmt.Sprintf("%d", ttl)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Host == host {
			if r.Rdata == target && r.TTL == ttlStr {
				return nil
			}
			p.pace()
			status, body, err := p.DoJSON("DELETE", fmt.Sprintf("%s/zones/records/%s/%s?format=json", p.apiHost, domain, r.ID), p.headers(false), nil)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("easydns replace delete failed: %d - %s", status, string(body))
			}
		}
	}

	p.pace()
	payload := map[string]interface{}{
		"domain": domain, "host": host, "type": recordType,
		"rdata": target, "ttl": ttlStr, "priority": "0",
	}
	status, body, err := p.DoJSON("PUT", fmt.Sprintf("%s/zones/records/add/%s/%s?format=json", p.apiHost, domain, recordType), p.headers(true), payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("easydns add record failed: %d - %s", status, string(body))
	}
	return nil
}

func (p *EasyDNSProvider) DeleteRecord(domain, recordType, hostname string) error {
	host := RelativeName(hostname, domain)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if r.Type == recordType && r.Host == host {
			p.pace()
			status, body, err := p.DoJSON("DELETE", fmt.Sprintf("%s/zones/records/%s/%s?format=json", p.apiHost, domain, r.ID), p.headers(false), nil)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("easydns delete record failed: %d - %s", status, string(body))
			}
		}
	}
	return nil
}

func (p *EasyDNSProvider) Validate() error {
	status, _, err := p.DoJSON("GET", p.apiHost+"/zones/records/all/validate.invalid?format=json", p.headers(false), nil)
	if err != nil {
		return err
	}
	if status == 401 || status == 403 {
		return fmt.Errorf("easydns validation failed: authentication rejected (%d)", status)
	}
	return nil
}

func (p *EasyDNSProvider) pace() {
	time.Sleep(1100 * time.Millisecond)
}
