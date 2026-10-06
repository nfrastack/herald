// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
	"strings"
)

type SpaceshipProvider struct {
	*BaseProvider
	apiHost   string
	apiKey    string
	apiSecret string
}

type spaceshipRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Address string `json:"address"`
	TTL     int    `json:"ttl"`
}

func NewSpaceshipProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("spaceship", config["profile_name"], config)

	apiKey := base.Secret("api_key")
	if apiKey == "" {
		return nil, fmt.Errorf("spaceship provider requires 'api_key' parameter")
	}
	apiSecret := base.Secret("api_secret")
	if apiSecret == "" {
		return nil, fmt.Errorf("spaceship provider requires 'api_secret' parameter")
	}

	apiHost := base.Option("api_host", "https://spaceship.dev/api")

	return &SpaceshipProvider{BaseProvider: base, apiHost: apiHost, apiKey: apiKey, apiSecret: apiSecret}, nil
}

func init() {
	dns.RegisterProvider("spaceship", NewSpaceshipProvider)
}

func (p *SpaceshipProvider) GetName() string {
	return "spaceship"
}

func (p *SpaceshipProvider) SupportsProxied() bool {
	return false
}

func (p *SpaceshipProvider) headers() map[string]string {
	return map[string]string{
		"X-API-Key":    p.apiKey,
		"X-API-Secret": p.apiSecret,
		"Content-Type": "application/json",
	}
}

func (p *SpaceshipProvider) listRecords(domain string) ([]spaceshipRecord, error) {
	var all []spaceshipRecord
	for skip := 0; ; skip += 100 {
		url := fmt.Sprintf("%s/v1/dns/records/%s?take=100&skip=%d", p.apiHost, domain, skip)
		status, body, err := p.DoJSON("GET", url, p.headers(), nil)
		if err != nil {
			return nil, err
		}
		if status != 200 {
			return nil, fmt.Errorf("spaceship list records failed: %d - %s", status, string(body))
		}
		var out struct {
			Items []spaceshipRecord `json:"items"`
			Total int               `json:"total"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Items...)
		if len(out.Items) < 100 || len(all) >= out.Total {
			break
		}
		if skip >= 900 {
			break
		}
	}
	return all, nil
}

func (p *SpaceshipProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *SpaceshipProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	name := RelativeName(hostname, domain)

	body := map[string]interface{}{
		"force": true,
		"items": []spaceshipRecord{{Type: recordType, Name: name, Address: target, TTL: ttl}},
	}
	status, respBody, err := p.DoJSON("PUT", p.apiHost+"/v1/dns/records/"+domain, p.headers(), body)
	if err != nil {
		return err
	}
	if status != 204 && (status < 200 || status >= 300) {
		return fmt.Errorf("spaceship save record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *SpaceshipProvider) DeleteRecord(domain, recordType, hostname string) error {
	name := RelativeName(hostname, domain)

	records, err := p.listRecords(domain)
	if err != nil {
		return err
	}

	var doomed []spaceshipRecord
	for _, r := range records {
		if r.Type != recordType {
			continue
		}
		match := r.Name == name
		if recordType != "TXT" {
			match = strings.EqualFold(r.Name, name)
		}
		if match {
			doomed = append(doomed, r)
		}
	}
	if len(doomed) == 0 {
		return nil
	}

	status, respBody, err := p.DoJSON("DELETE", p.apiHost+"/v1/dns/records/"+domain, p.headers(), doomed)
	if err != nil {
		return err
	}
	if status != 204 && (status < 200 || status >= 300) {
		return fmt.Errorf("spaceship delete record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *SpaceshipProvider) Validate() error {
	status, body, err := p.DoJSON("GET", p.apiHost+"/v1/domains?take=1&skip=0", p.headers(), nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("spaceship validation failed: %d - %s", status, string(body))
	}
	return nil
}
