// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type GoogleDNSProvider struct {
	*BaseProvider
	project  string
	keyJSON  string
	tokenURI string
	cache    TokenCache
}

type googleServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

type googleRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Rrdatas []string `json:"rrdatas"`
}

func NewGoogleDNSProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("google", config["profile_name"], config)

	project := base.Option("project", "")
	if project == "" {
		return nil, fmt.Errorf("google provider requires 'project' parameter")
	}
	credentials := base.Secret("credentials", "key_file", "service_account")
	if credentials == "" {
		return nil, fmt.Errorf("google provider requires 'credentials' parameter")
	}

	keyJSON := credentials
	if !strings.HasPrefix(strings.TrimSpace(credentials), "{") {
		raw, err := os.ReadFile(credentials)
		if err != nil {
			return nil, fmt.Errorf("google provider failed to read credentials file: %v", err)
		}
		keyJSON = string(raw)
	}

	var sa googleServiceAccount
	if err := json.Unmarshal([]byte(keyJSON), &sa); err != nil {
		return nil, fmt.Errorf("google provider credentials are not valid service account JSON: %v", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("google provider credentials missing client_email or private_key")
	}

	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	return &GoogleDNSProvider{BaseProvider: base, project: project, keyJSON: keyJSON, tokenURI: tokenURI}, nil
}

func init() {
	dns.RegisterProvider("google", NewGoogleDNSProvider)
}

func (p *GoogleDNSProvider) GetName() string {
	return "google"
}

func (p *GoogleDNSProvider) SupportsProxied() bool {
	return false
}

func (p *GoogleDNSProvider) signJWT() (string, error) {
	var sa googleServiceAccount
	if err := json.Unmarshal([]byte(p.keyJSON), &sa); err != nil {
		return "", err
	}

	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("google provider failed to decode private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("google provider private key is not RSA")
	}

	now := time.Now().Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]interface{}{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
		"aud":   p.tokenURI,
		"exp":   now + 3600,
		"iat":   now,
	})
	if err != nil {
		return "", err
	}
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (p *GoogleDNSProvider) postForm(target string, form url.Values) (int, []byte, error) {
	p.Logger.Debug("API Request: POST %s", target)
	req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

func (p *GoogleDNSProvider) accessToken() (string, error) {
	return p.cache.Get(func() (string, time.Time, error) {
		assertion, err := p.signJWT()
		if err != nil {
			return "", time.Time{}, err
		}
		status, body, err := p.postForm(p.tokenURI, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {assertion},
		})
		if err != nil {
			return "", time.Time{}, err
		}
		if status != 200 {
			return "", time.Time{}, fmt.Errorf("google token exchange failed: %d - %s", status, string(body))
		}
		var out struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", time.Time{}, err
		}
		if out.AccessToken == "" {
			return "", time.Time{}, fmt.Errorf("google token exchange returned no access token")
		}
		ttl := out.ExpiresIn - 60
		if ttl < 60 {
			ttl = 60
		}
		return out.AccessToken, time.Now().Add(time.Duration(ttl) * time.Second), nil
	})
}

func (p *GoogleDNSProvider) headers() (map[string]string, error) {
	token, err := p.accessToken()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	}, nil
}

func (p *GoogleDNSProvider) api(path string) string {
	return "https://dns.googleapis.com/dns/v1/projects/" + p.project + path
}

func (p *GoogleDNSProvider) zoneName(domain string) (string, error) {
	h, err := p.headers()
	if err != nil {
		return "", err
	}
	status, body, err := p.DoJSON("GET", p.api("/managedZones?dnsName="+domain+"."), h, nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("google zone lookup failed: %d - %s", status, string(body))
	}
	var out struct {
		Zones []struct {
			Name    string `json:"name"`
			DNSName string `json:"dnsName"`
		} `json:"managedZones"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	for _, z := range out.Zones {
		if strings.TrimSuffix(z.DNSName, ".") == domain {
			return z.Name, nil
		}
	}
	return "", fmt.Errorf("google: no managed zone found for domain %s", domain)
}

func (p *GoogleDNSProvider) fqdn(hostname, domain string) string {
	return BuildFQDN(hostname, domain) + "."
}

func (p *GoogleDNSProvider) normalizeValue(recordType, target string) string {
	if (recordType == "CNAME" || recordType == "MX" || recordType == "NS" || recordType == "PTR") && !strings.HasSuffix(target, ".") {
		return target + "."
	}
	return target
}

func (p *GoogleDNSProvider) current(zone, fqdn, recordType string) (*googleRRSet, error) {
	h, err := p.headers()
	if err != nil {
		return nil, err
	}
	status, body, err := p.DoJSON("GET", p.api("/managedZones/"+zone+"/rrsets?name="+fqdn+"&type="+recordType), h, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("google list records failed: %d - %s", status, string(body))
	}
	var out struct {
		RRSets []googleRRSet `json:"rrsets"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	for _, rs := range out.RRSets {
		if rs.Type == recordType && rs.Name == fqdn {
			found := rs
			return &found, nil
		}
	}
	return nil, nil
}

func (p *GoogleDNSProvider) applyChange(zone string, additions, deletions []googleRRSet) error {
	h, err := p.headers()
	if err != nil {
		return err
	}
	body := map[string]interface{}{}
	if additions != nil {
		body["additions"] = additions
	}
	if deletions != nil {
		body["deletions"] = deletions
	}
	status, respBody, err := p.DoJSON("POST", p.api("/managedZones/"+zone+"/changes"), h, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("google change failed: %d - %s", status, string(respBody))
	}
	return nil
}

func (p *GoogleDNSProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *GoogleDNSProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	fqdn := p.fqdn(hostname, domain)
	value := p.normalizeValue(recordType, target)

	zone, err := p.zoneName(domain)
	if err != nil {
		return err
	}

	cur, err := p.current(zone, fqdn, recordType)
	if err != nil {
		return err
	}

	want := googleRRSet{Name: fqdn, Type: recordType, TTL: ttl, Rrdatas: []string{value}}
	if cur != nil && cur.TTL == ttl && len(cur.Rrdatas) == 1 && cur.Rrdatas[0] == value {
		return nil
	}

	var deletions []googleRRSet
	if cur != nil {
		deletions = []googleRRSet{*cur}
	}
	return p.applyChange(zone, []googleRRSet{want}, deletions)
}

func (p *GoogleDNSProvider) DeleteRecord(domain, recordType, hostname string) error {
	fqdn := p.fqdn(hostname, domain)

	zone, err := p.zoneName(domain)
	if err != nil {
		return err
	}

	cur, err := p.current(zone, fqdn, recordType)
	if err != nil {
		return err
	}
	if cur == nil {
		return nil
	}
	return p.applyChange(zone, nil, []googleRRSet{*cur})
}

func (p *GoogleDNSProvider) Validate() error {
	h, err := p.headers()
	if err != nil {
		return err
	}
	status, body, err := p.DoJSON("GET", p.api("/managedZones?pageSize=1"), h, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("google validation failed: %d - %s", status, string(body))
	}
	return nil
}
