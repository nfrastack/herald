// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Route53Provider struct {
	*BaseProvider
	endpoint     string
	region       string
	accessKey    string
	secretKey    string
	sessionToken string
}

type route53Zone struct {
	ID     string
	Name   string
	Public bool
}

type route53ListZonesResponse struct {
	XMLName     xml.Name `xml:"ListHostedZonesByNameResponse"`
	HostedZones []struct {
		ID     string `xml:"Id"`
		Name   string `xml:"Name"`
		Config struct {
			PrivateZone bool `xml:"PrivateZone"`
		} `xml:"Config"`
	} `xml:"HostedZones>HostedZone"`
}

type route53RecordSet struct {
	Name    string `xml:"Name"`
	Type    string `xml:"Type"`
	TTL     int    `xml:"TTL"`
	Records []struct {
		Value string `xml:"Value"`
	} `xml:"ResourceRecords>ResourceRecord"`
}

type route53ListRecordsResponse struct {
	XMLName    xml.Name           `xml:"ListResourceRecordSetsResponse"`
	RecordSets []route53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
}

func NewRoute53Provider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("route53", config["profile_name"], config)

	accessKey := base.Secret("access_key", "access_key_id", "aws_access_key_id")
	if accessKey == "" {
		return nil, fmt.Errorf("route53 provider requires 'access_key' parameter")
	}
	secretKey := base.Secret("secret_key", "aws_secret_access_key")
	if secretKey == "" {
		return nil, fmt.Errorf("route53 provider requires 'secret_key' parameter")
	}

	endpoint := strings.TrimSuffix(base.Option("endpoint", "https://route53.amazonaws.com"), "/")
	region := base.Option("region", "us-east-1")
	sessionToken := base.Secret("session_token", "aws_session_token")

	return &Route53Provider{
		BaseProvider: base, endpoint: endpoint, region: region,
		accessKey: accessKey, secretKey: secretKey, sessionToken: sessionToken,
	}, nil
}

func init() {
	dns.RegisterProvider("route53", NewRoute53Provider)
}

func (p *Route53Provider) GetName() string {
	return "route53"
}

func (p *Route53Provider) SupportsProxied() bool {
	return false
}

func route53HMAC(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (p *Route53Provider) sign(method, url string, body []byte) (amzDate string, headers map[string]string) {
	t := time.Now().UTC()
	amzDate = t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	payloadHash := sha256.Sum256(body)
	payloadHex := hex.EncodeToString(payloadHash[:])

	host := strings.TrimPrefix(strings.TrimPrefix(p.endpoint, "https://"), "http://")
	canonicalHeaders := "host:" + host + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"
	if p.sessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + p.sessionToken + "\n"
		signedHeaders += ";x-amz-security-token"
	}

	path := strings.TrimPrefix(url, p.endpoint)
	canonical := method + "\n" + path + "\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHex
	scope := dateStamp + "/" + p.region + "/route53/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))

	kDate := route53HMAC([]byte("AWS4"+p.secretKey), dateStamp)
	kRegion := route53HMAC(kDate, p.region)
	kService := route53HMAC(kRegion, "route53")
	kSigning := route53HMAC(kService, "aws4_request")
	signature := hex.EncodeToString(route53HMAC(kSigning, toSign))

	headers = map[string]string{
		"X-Amz-Date":    amzDate,
		"Authorization": "AWS4-HMAC-SHA256 Credential=" + p.accessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature,
	}
	if p.sessionToken != "" {
		headers["X-Amz-Security-Token"] = p.sessionToken
	}
	return amzDate, headers
}

func (p *Route53Provider) get(path string) (int, []byte, error) {
	_, headers := p.sign("GET", p.endpoint+path, []byte{})
	return p.DoJSON("GET", p.endpoint+path, headers, nil)
}

func (p *Route53Provider) postXML(path string, payload interface{}) (int, []byte, error) {
	raw, err := xml.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	body := append([]byte(xml.Header), raw...)
	_, headers := p.sign("POST", p.endpoint+path, body)
	headers["Content-Type"] = "text/xml"

	p.Logger.Debug("API Request: POST %s", p.endpoint+path)
	req, err := http.NewRequest("POST", p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		p.Logger.Debug("API Request failed: %v", err)
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		p.Logger.Debug("API Request successful: %s", resp.Status)
	} else {
		p.Logger.Debug("API Request failed: %s - %s", resp.Status, string(respBody))
	}
	return resp.StatusCode, respBody, nil
}

func (p *Route53Provider) zoneID(domain string) (string, error) {
	status, body, err := p.get("/2013-04-01/hostedzonebyname?DNSName=" + domain)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("route53 zone lookup failed: %d - %s", status, string(body))
	}
	var out route53ListZonesResponse
	if err := xml.Unmarshal(body, &out); err != nil {
		return "", err
	}
	fallback := ""
	for _, z := range out.HostedZones {
		if strings.TrimSuffix(z.Name, ".") != domain {
			continue
		}
		id := strings.TrimPrefix(z.ID, "/hostedzone/")
		if !z.Config.PrivateZone {
			return id, nil
		}
		if fallback == "" {
			fallback = id
		}
	}
	if fallback == "" {
		return "", fmt.Errorf("route53: no hosted zone found for domain %s", domain)
	}
	return fallback, nil
}

func (p *Route53Provider) fqdn(hostname, domain string) string {
	return BuildFQDN(hostname, domain) + "."
}

func (p *Route53Provider) normalizeValue(recordType, target string) string {
	if (recordType == "CNAME" || recordType == "NS") && !strings.HasSuffix(target, ".") {
		return target + "."
	}
	return target
}

func (p *Route53Provider) listRecords(zoneID, fqdn, recordType string) ([]route53RecordSet, error) {
	status, body, err := p.get("/2013-04-01/hostedzone/" + zoneID + "/rrset?name=" + fqdn + "&type=" + recordType)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("route53 list records failed: %d - %s", status, string(body))
	}
	var out route53ListRecordsResponse
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	var matched []route53RecordSet
	for _, rs := range out.RecordSets {
		if rs.Type == recordType && rs.Name == fqdn {
			matched = append(matched, rs)
		}
	}
	return matched, nil
}

type route53ChangeValue struct {
	Value string `xml:"Value"`
}

type route53ChangeSet struct {
	Name    string               `xml:"Name"`
	Type    string               `xml:"Type"`
	TTL     int                  `xml:"TTL"`
	Records []route53ChangeValue `xml:"ResourceRecords>ResourceRecord"`
}

type route53ChangeEntry struct {
	Action string           `xml:"Action"`
	Set    route53ChangeSet `xml:"ResourceRecordSet"`
}

type route53Change struct {
	XMLName xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	NS      string   `xml:"xmlns,attr"`
	Batch   struct {
		Changes []route53ChangeEntry `xml:"Changes>Change"`
	} `xml:"ChangeBatch"`
}

func (p *Route53Provider) change(zoneID, action, fqdn, recordType string, ttl int, values []string) error {
	var req route53Change
	req.NS = "https://route53.amazonaws.com/doc/2013-04-01/"
	entry := route53ChangeEntry{Action: action}
	entry.Set.Name = fqdn
	entry.Set.Type = recordType
	entry.Set.TTL = ttl
	for _, v := range values {
		entry.Set.Records = append(entry.Set.Records, route53ChangeValue{Value: v})
	}
	req.Batch.Changes = []route53ChangeEntry{entry}

	status, body, err := p.postXML("/2013-04-01/hostedzone/"+zoneID+"/rrset/", req)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("route53 change failed: %d - %s", status, string(body))
	}
	return nil
}

func (p *Route53Provider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *Route53Provider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	fqdn := p.fqdn(hostname, domain)
	value := p.normalizeValue(recordType, target)

	zoneID, err := p.zoneID(domain)
	if err != nil {
		return err
	}

	existing, err := p.listRecords(zoneID, fqdn, recordType)
	if err != nil {
		return err
	}
	if len(existing) == 1 && existing[0].TTL == ttl && len(existing[0].Records) == 1 && existing[0].Records[0].Value == value {
		return nil
	}

	return p.change(zoneID, "UPSERT", fqdn, recordType, ttl, []string{value})
}

func (p *Route53Provider) DeleteRecord(domain, recordType, hostname string) error {
	fqdn := p.fqdn(hostname, domain)

	zoneID, err := p.zoneID(domain)
	if err != nil {
		return err
	}

	existing, err := p.listRecords(zoneID, fqdn, recordType)
	if err != nil {
		return err
	}

	for _, rs := range existing {
		var values []string
		for _, r := range rs.Records {
			values = append(values, r.Value)
		}
		if err := p.change(zoneID, "DELETE", fqdn, recordType, rs.TTL, values); err != nil {
			return err
		}
	}
	return nil
}

func (p *Route53Provider) Validate() error {
	status, body, err := p.get("/2013-04-01/hostedzone?maxitems=1")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("route53 validation failed: %d - %s", status, string(body))
	}
	return nil
}
