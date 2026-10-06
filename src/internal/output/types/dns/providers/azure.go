// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const azureAPIVersion = "2018-05-01"

type AzureDNSProvider struct {
	*BaseProvider
	tenantID       string
	clientID       string
	clientSecret   string
	subscriptionID string
	resourceGroup  string
	cache          TokenCache
}

func NewAzureDNSProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("azure", config["profile_name"], config)

	tenantID := base.Option("tenant_id", "")
	if tenantID == "" {
		return nil, fmt.Errorf("azure provider requires 'tenant_id' parameter")
	}
	clientID := base.Secret("client_id", "application_id")
	if clientID == "" {
		return nil, fmt.Errorf("azure provider requires 'client_id' parameter")
	}
	clientSecret := base.Secret("client_secret")
	if clientSecret == "" {
		return nil, fmt.Errorf("azure provider requires 'client_secret' parameter")
	}
	subscriptionID := base.Option("subscription_id", "")
	if subscriptionID == "" {
		return nil, fmt.Errorf("azure provider requires 'subscription_id' parameter")
	}
	resourceGroup := base.Option("resource_group", "")
	if resourceGroup == "" {
		return nil, fmt.Errorf("azure provider requires 'resource_group' parameter")
	}

	return &AzureDNSProvider{
		BaseProvider: base, tenantID: tenantID, clientID: clientID,
		clientSecret: clientSecret, subscriptionID: subscriptionID, resourceGroup: resourceGroup,
	}, nil
}

func init() {
	dns.RegisterProvider("azure", NewAzureDNSProvider)
}

func (p *AzureDNSProvider) GetName() string {
	return "azure"
}

func (p *AzureDNSProvider) SupportsProxied() bool {
	return false
}

func (p *AzureDNSProvider) accessToken() (string, error) {
	return p.cache.Get(func() (string, time.Time, error) {
		target := "https://login.microsoftonline.com/" + p.tenantID + "/oauth2/v2/token"
		p.Logger.Debug("API Request: POST %s", target)
		req, err := http.NewRequest("POST", target, strings.NewReader(url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {p.clientID},
			"client_secret": {p.clientSecret},
			"scope":         {"https://management.azure.com/.default"},
		}.Encode()))
		if err != nil {
			return "", time.Time{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := p.HTTPClient.Do(req)
		if err != nil {
			return "", time.Time{}, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return "", time.Time{}, fmt.Errorf("azure token exchange failed: %d - %s", resp.StatusCode, string(body))
		}
		var out struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", time.Time{}, err
		}
		if out.AccessToken == "" {
			return "", time.Time{}, fmt.Errorf("azure token exchange returned no access token")
		}
		ttl := out.ExpiresIn - 60
		if ttl < 60 {
			ttl = 60
		}
		return out.AccessToken, time.Now().Add(time.Duration(ttl) * time.Second), nil
	})
}

func (p *AzureDNSProvider) headers() (map[string]string, error) {
	token, err := p.accessToken()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	}, nil
}

func (p *AzureDNSProvider) recordURL(zone, recordType, hostname string) string {
	name := RelativeName(hostname, zone)
	return fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/dnsZones/%s/%s/%s?api-version=%s",
		p.subscriptionID, p.resourceGroup, zone, recordType, url.PathEscape(name), azureAPIVersion)
}

func (p *AzureDNSProvider) properties(recordType, target string, ttl int) (map[string]interface{}, error) {
	switch recordType {
	case "A":
		return map[string]interface{}{"TTL": ttl, "ARecords": []map[string]string{{"ipv4Address": target}}}, nil
	case "AAAA":
		return map[string]interface{}{"TTL": ttl, "AAAARecords": []map[string]string{{"ipv6Address": target}}}, nil
	case "CNAME":
		return map[string]interface{}{"TTL": ttl, "CNAMERecord": map[string]string{"cname": target}}, nil
	case "TXT":
		return map[string]interface{}{"TTL": ttl, "TXTRecords": []map[string]interface{}{{"value": []string{target}}}}, nil
	default:
		return nil, fmt.Errorf("azure provider does not support record type %s", recordType)
	}
}

func (p *AzureDNSProvider) current(zone, recordType, hostname string) (map[string]interface{}, bool, error) {
	h, err := p.headers()
	if err != nil {
		return nil, false, err
	}
	status, body, err := p.DoJSON("GET", p.recordURL(zone, recordType, hostname), h, nil)
	if err != nil {
		return nil, false, err
	}
	if status == 404 {
		return nil, false, nil
	}
	if status != 200 {
		return nil, false, fmt.Errorf("azure get record failed: %d - %s", status, string(body))
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func azureTargets(recordType string, body map[string]interface{}) []string {
	props, ok := body["properties"].(map[string]interface{})
	if !ok {
		return nil
	}
	switch recordType {
	case "A":
		return azureStringField(props, "ARecords", "ipv4Address")
	case "AAAA":
		return azureStringField(props, "AAAARecords", "ipv6Address")
	case "CNAME":
		if rec, ok := props["CNAMERecord"].(map[string]interface{}); ok {
			if v, ok := rec["cname"].(string); ok {
				return []string{v}
			}
		}
	case "TXT":
		if recs, ok := props["TXTRecords"].([]interface{}); ok {
			var out []string
			for _, r := range recs {
				if m, ok := r.(map[string]interface{}); ok {
					if vals, ok := m["value"].([]interface{}); ok {
						for _, v := range vals {
							if s, ok := v.(string); ok {
								out = append(out, s)
							}
						}
					}
				}
			}
			return out
		}
	}
	return nil
}

func azureStringField(props map[string]interface{}, list, field string) []string {
	recs, ok := props[list].([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, r := range recs {
		if m, ok := r.(map[string]interface{}); ok {
			if v, ok := m[field].(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func (p *AzureDNSProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *AzureDNSProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	props, err := p.properties(recordType, target, ttl)
	if err != nil {
		return err
	}

	h, err := p.headers()
	if err != nil {
		return err
	}

	cur, exists, err := p.current(domain, recordType, hostname)
	if err != nil {
		return err
	}
	if exists {
		if curTTL(cur) == ttl && singleTarget(recordType, cur) == target {
			return nil
		}
	}

	status, respBody, err := p.DoJSON("PUT", p.recordURL(domain, recordType, hostname), h, map[string]interface{}{"properties": props})
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("azure upsert record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func curTTL(body map[string]interface{}) int {
	props, ok := body["properties"].(map[string]interface{})
	if !ok {
		return -1
	}
	switch v := props["TTL"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return -1
}

func singleTarget(recordType string, body map[string]interface{}) string {
	targets := azureTargets(recordType, body)
	if len(targets) == 1 {
		return targets[0]
	}
	return ""
}

func (p *AzureDNSProvider) DeleteRecord(domain, recordType, hostname string) error {
	h, err := p.headers()
	if err != nil {
		return err
	}

	status, respBody, err := p.DoJSON("DELETE", p.recordURL(domain, recordType, hostname), h, nil)
	if err != nil {
		return err
	}
	if status == 404 {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("azure delete record failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *AzureDNSProvider) Validate() error {
	h, err := p.headers()
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/dnszones?api-version=%s", p.subscriptionID, azureAPIVersion)
	status, body, err := p.DoJSON("GET", url, h, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("azure validation failed: %d - %s", status, string(body))
	}
	return nil
}
