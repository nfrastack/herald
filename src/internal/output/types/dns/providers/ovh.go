// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type OVHProvider struct {
	*BaseProvider
	endpoint   string
	appKey     string
	appSecret  string
	consumer   string
	timeDelta  int64
	deltaKnown bool
}

func NewOVHProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("ovh", config["profile_name"], config)

	appKey := base.Secret("app_key", "application_key")
	if appKey == "" {
		return nil, fmt.Errorf("ovh provider requires 'app_key' parameter")
	}
	appSecret := base.Secret("app_secret", "application_secret")
	if appSecret == "" {
		return nil, fmt.Errorf("ovh provider requires 'app_secret' parameter")
	}
	consumer := base.Secret("consumer_key")
	if consumer == "" {
		return nil, fmt.Errorf("ovh provider requires 'consumer_key' parameter")
	}

	endpoint := base.Option("endpoint", "https://eu.api.ovh.com/1.0")

	return &OVHProvider{BaseProvider: base, endpoint: endpoint, appKey: appKey, appSecret: appSecret, consumer: consumer}, nil
}

func init() {
	dns.RegisterProvider("ovh", NewOVHProvider)
}

func (p *OVHProvider) GetName() string {
	return "ovh"
}

func (p *OVHProvider) SupportsProxied() bool {
	return false
}

func (p *OVHProvider) sub(hostname, domain string) string {
	if rel := RelativeName(hostname, domain); rel != "@" {
		return rel
	}
	return ""
}

func (p *OVHProvider) syncTime() {
	if p.deltaKnown {
		return
	}
	status, body, err := p.DoJSON("GET", p.endpoint+"/auth/time", map[string]string{}, nil)
	if err == nil && status == 200 {
		var serverTime int64
		if json.Unmarshal(body, &serverTime) == nil {
			p.timeDelta = serverTime - time.Now().Unix()
			p.deltaKnown = true
		}
	}
}

func (p *OVHProvider) headers(method, url, body string) map[string]string {
	p.syncTime()
	stamp := fmt.Sprintf("%d", time.Now().Unix()+p.timeDelta)
	raw := p.appSecret + "+" + p.consumer + "+" + method + "+" + url + "+" + body + "+" + stamp
	sum := sha1.Sum([]byte(raw))
	return map[string]string{
		"X-Ovh-Application": p.appKey,
		"X-Ovh-Consumer":    p.consumer,
		"X-Ovh-Time":        stamp,
		"X-Ovh-Signature":   "$1$" + hex.EncodeToString(sum[:]),
		"Content-Type":      "application/json",
	}
}

func (p *OVHProvider) call(method, path string, payload map[string]interface{}) (int, []byte, error) {
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
	}
	url := p.endpoint + path
	return p.DoJSON(method, url, p.headers(method, url, string(raw)), payload)
}

func (p *OVHProvider) recordIDs(zone, recordType, sub string) ([]int, error) {
	path := fmt.Sprintf("/domain/zone/%s/record?fieldType=%s&subDomain=%s", zone, recordType, sub)
	status, body, err := p.call("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("ovh list records failed: %d - %s", status, string(body))
	}
	var ids []int
	if err := json.Unmarshal(body, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

func (p *OVHProvider) refresh(zone string) error {
	status, body, err := p.call("POST", "/domain/zone/"+zone+"/refresh", nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("ovh zone refresh failed: %d - %s", status, string(body))
	}
	return nil
}

func (p *OVHProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *OVHProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	sub := p.sub(hostname, domain)

	ids, err := p.recordIDs(domain, recordType, sub)
	if err != nil {
		return err
	}

	if len(ids) == 1 {
		status, body, err := p.call("GET", fmt.Sprintf("/domain/zone/%s/record/%d", domain, ids[0]), nil)
		if err != nil {
			return err
		}
		if status == 200 {
			var cur struct {
				Target string `json:"target"`
				TTL    int    `json:"ttl"`
			}
			if json.Unmarshal(body, &cur) == nil && cur.Target == target && cur.TTL == ttl {
				return nil
			}
		}
		payload := map[string]interface{}{"target": target, "ttl": ttl}
		status, respBody, err := p.call("PUT", fmt.Sprintf("/domain/zone/%s/record/%d", domain, ids[0]), payload)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("ovh update record failed: %d - %s", status, string(respBody))
		}
		return p.refresh(domain)
	}

	for _, id := range ids {
		status, respBody, err := p.call("DELETE", fmt.Sprintf("/domain/zone/%s/record/%d", domain, id), nil)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("ovh delete record failed: %d - %s", status, string(respBody))
		}
	}

	payload := map[string]interface{}{"fieldType": recordType, "subDomain": sub, "target": target, "ttl": ttl}
	status, respBody, err := p.call("POST", "/domain/zone/"+domain+"/record", payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("ovh create record failed: %d - %s", status, string(respBody))
	}
	return p.refresh(domain)
}

func (p *OVHProvider) DeleteRecord(domain, recordType, hostname string) error {
	sub := p.sub(hostname, domain)

	ids, err := p.recordIDs(domain, recordType, sub)
	if err != nil {
		return err
	}

	for _, id := range ids {
		status, respBody, err := p.call("DELETE", fmt.Sprintf("/domain/zone/%s/record/%d", domain, id), nil)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("ovh delete record failed: %d - %s", status, string(respBody))
		}
	}
	if len(ids) > 0 {
		return p.refresh(domain)
	}
	return nil
}

func (p *OVHProvider) Validate() error {
	status, body, err := p.call("GET", "/me", nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("ovh validation failed: %d - %s", status, string(body))
	}
	return nil
}
