// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type TechnitiumProvider struct {
	*BaseProvider
	apiHost string
	token   string
}

type technitiumRecord struct {
	Name  string                 `json:"name"`
	Type  string                 `json:"type"`
	TTL   int                    `json:"ttl"`
	RData map[string]interface{} `json:"rData"`
}

func NewTechnitiumProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("technitium", config["profile_name"], config)

	token := base.Secret("token", "api_token")
	if token == "" {
		return nil, fmt.Errorf("technitium provider requires 'token' or 'api_token' parameter")
	}

	apiHost := strings.TrimSuffix(base.Option("api_host", "http://127.0.0.1:5380"), "/")

	return &TechnitiumProvider{BaseProvider: base, apiHost: apiHost, token: token}, nil
}

func init() {
	dns.RegisterProvider("technitium", NewTechnitiumProvider)
}

func (p *TechnitiumProvider) GetName() string {
	return "technitium"
}

func (p *TechnitiumProvider) SupportsProxied() bool {
	return false
}

func (p *TechnitiumProvider) get(path string, params map[string]string) (int, []byte, error) {
	q := url.Values{}
	q.Set("token", p.token)
	for k, v := range params {
		q.Set(k, v)
	}
	return p.DoJSON("GET", p.apiHost+path+"?"+q.Encode(), nil, nil)
}

func (p *TechnitiumProvider) check(body []byte, op string) error {
	var out struct {
		Status  string `json:"status"`
		Message string `json:"errorMessage"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("technitium %s failed: unparseable response: %s", op, string(body))
	}
	if out.Status != "ok" {
		return fmt.Errorf("technitium %s failed: %s", op, out.Message)
	}
	return nil
}

func (p *TechnitiumProvider) typeParams(recordType, target string) (map[string]string, error) {
	switch recordType {
	case "A", "AAAA":
		return map[string]string{"ipAddress": target}, nil
	case "CNAME":
		return map[string]string{"cname": target}, nil
	case "TXT":
		return map[string]string{"text": target}, nil
	default:
		return nil, fmt.Errorf("technitium provider does not support record type %s", recordType)
	}
}

func (p *TechnitiumProvider) recordValue(r technitiumRecord) string {
	if r.RData == nil {
		return ""
	}
	for _, k := range []string{"ipAddress", "cname", "text", "exchange", "nameServer"} {
		if v, ok := r.RData[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func (p *TechnitiumProvider) listRecords(fqdn, zone string) ([]technitiumRecord, error) {
	status, body, err := p.get("/api/zones/records/get", map[string]string{"domain": fqdn, "zone": zone, "listZone": "false"})
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("technitium list records failed: %d - %s", status, string(body))
	}
	var out struct {
		Status   string `json:"status"`
		Message  string `json:"errorMessage"`
		Response struct {
			Records []technitiumRecord `json:"records"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.Status != "ok" {
		return nil, fmt.Errorf("technitium list records failed: %s", out.Message)
	}
	return out.Response.Records, nil
}

func (p *TechnitiumProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *TechnitiumProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	fqdn := BuildFQDN(hostname, domain)

	extra, err := p.typeParams(recordType, target)
	if err != nil {
		return err
	}

	params := map[string]string{
		"domain": fqdn, "zone": domain, "type": recordType,
		"ttl": fmt.Sprintf("%d", ttl), "overwrite": "true",
	}
	for k, v := range extra {
		params[k] = v
	}

	status, body, err := p.get("/api/zones/records/add", params)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("technitium add record failed: %d - %s", status, string(body))
	}
	return p.check(body, "add record")
}

func (p *TechnitiumProvider) DeleteRecord(domain, recordType, hostname string) error {
	fqdn := BuildFQDN(hostname, domain)

	records, err := p.listRecords(fqdn, domain)
	if err != nil {
		return err
	}

	for _, r := range records {
		if !strings.EqualFold(r.Type, recordType) {
			continue
		}
		value := p.recordValue(r)
		if value == "" {
			return fmt.Errorf("technitium cannot delete %s record %s: unknown value shape", recordType, fqdn)
		}
		extra, err := p.typeParams(recordType, value)
		if err != nil {
			return err
		}
		params := map[string]string{"domain": fqdn, "zone": domain, "type": recordType}
		for k, v := range extra {
			params[k] = v
		}
		status, body, err := p.get("/api/zones/records/delete", params)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("technitium delete record failed: %d - %s", status, string(body))
		}
		if err := p.check(body, "delete record"); err != nil {
			return err
		}
	}
	return nil
}

func (p *TechnitiumProvider) Validate() error {
	status, body, err := p.get("/api/zones/list", nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("technitium validation failed: %d - %s", status, string(body))
	}
	return p.check(body, "validate")
}
