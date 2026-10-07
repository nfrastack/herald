// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var PowerDNSProviderName = "powerdns"

type PowerDNSConfig struct {
	APIHost  string `yaml:"api_host"`
	APIToken string `yaml:"api_token"`
	TLS      struct {
		CA         string `yaml:"ca"`
		Cert       string `yaml:"cert"`
		Key        string `yaml:"key"`
		SkipVerify bool   `yaml:"skip_verify"`
	} `yaml:"tls"`
	ServerID string `yaml:"server_id"`
}

type PowerDNSProvider struct {
	*BaseProvider
	config     PowerDNSConfig
	httpClient *http.Client
}

func NewPowerDNSProvider(profileName string, cfg PowerDNSConfig) (*PowerDNSProvider, error) {
	client, err := newPowerDNSHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	base := NewBaseProvider("powerdns", profileName, nil)
	base.HTTPClient = client

	return &PowerDNSProvider{
		BaseProvider: base,
		config:       cfg,
		httpClient:   client,
	}, nil
}

func newPowerDNSHTTPClient(cfg PowerDNSConfig) (*http.Client, error) {
	if cfg.TLS.CA == "" && cfg.TLS.Cert == "" && cfg.TLS.Key == "" && !cfg.TLS.SkipVerify {
		return http.DefaultClient, nil
	}
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if cfg.TLS.CA != "" {
		caCert, err := os.ReadFile(cfg.TLS.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		rootCAs.AppendCertsFromPEM(caCert)
	}
	var certs []tls.Certificate
	if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert/key: %w", err)
		}
		certs = append(certs, cert)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCAs,
			Certificates:       certs,
			InsecureSkipVerify: cfg.TLS.SkipVerify,
		},
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

func (p *PowerDNSProvider) SupportsProxied() bool {
	return false
}

func (p *PowerDNSProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *PowerDNSProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	p.Logger.With("action", "record.sync").Debug("record: domain=%s, type=%s, hostname=%s, target=%s, ttl=%d", domain, recordType, hostname, target, ttl)

	apiURL := p.apiURL("/servers/%s/zones/%s.", p.serverID(), domain)

	recordName := BuildFQDN(hostname, domain)

	recordContent := target
	if recordType == "CNAME" && !strings.HasSuffix(target, ".") {
		recordContent = target + "."
	}

	p.Logger.With("action", "record.sync").Trace("record name: %s, content: %s", recordName, recordContent)

	rrset := map[string]interface{}{
		"name":       recordName + ".",
		"type":       recordType,
		"ttl":        ttl,
		"changetype": "REPLACE",
		"records": []map[string]interface{}{
			{"content": recordContent, "disabled": false},
		},
	}
	if comment != "" {
		rrset["comments"] = []map[string]interface{}{
			{"content": comment, "account": source},
		}
	}
	body := map[string]interface{}{
		"rrsets": []interface{}{rrset},
	}
	return p.sendPowerDNSPatch(apiURL, body)
}

func (p *PowerDNSProvider) DeleteRecord(domain, recordType, hostname string) error {
	p.Logger.With("action", "record.delete").Debug("record: domain=%s, type=%s, hostname=%s", domain, recordType, hostname)

	apiURL := p.apiURL("/servers/%s/zones/%s.", p.serverID(), domain)

	recordName := BuildFQDN(hostname, domain)

	p.Logger.With("action", "record.delete").Trace("record name for deletion: %s", recordName)

	rrset := map[string]interface{}{
		"name":       recordName + ".",
		"type":       recordType,
		"changetype": "DELETE",
	}
	body := map[string]interface{}{
		"rrsets": []interface{}{rrset},
	}
	return p.sendPowerDNSPatch(apiURL, body)
}

func NewPowerDNSProviderFromConfig(profileName string, config map[string]string) (*PowerDNSProvider, error) {
	base := NewBaseProvider("powerdns", profileName, config)

	cfg := PowerDNSConfig{}
	cfg.APIHost = base.Option("api_host", "")
	cfg.APIToken = base.Secret("api_token")
	cfg.ServerID = base.Option("server_id", "")
	cfg.TLS.CA = base.Option("tls.ca", "")
	cfg.TLS.Cert = base.Option("tls.cert", "")
	cfg.TLS.Key = base.Option("tls.key", "")
	if v := base.Option("tls.skip_verify", ""); v == "true" || v == "1" {
		cfg.TLS.SkipVerify = true
	}
	return NewPowerDNSProvider(profileName, cfg)
}

func init() {
	dns.RegisterProvider("powerdns", func(config map[string]string) (interface{}, error) {
		profileName := "default"
		if pn, ok := config["profile_name"]; ok {
			profileName = pn
		}
		return NewPowerDNSProviderFromConfig(profileName, config)
	})
}

func (p *PowerDNSProvider) GetName() string {
	return "powerdns"
}

func (p *PowerDNSProvider) Validate() error {
	p.Logger.With("action", "provider.validate").Debug("PowerDNS API connection")

	apiURL := p.apiURL("/servers/%s/zones", p.serverID())

	p.Logger.With("action", "provider.validate").Trace("request to: %s", apiURL)

	status, respBody, err := p.patch("GET", apiURL, nil)
	if err != nil {
		p.Logger.With("action", "provider.validate").Debug("request: %v", err)
		return err
	}

	if status != 200 {
		p.Logger.With("action", "provider.validate").Debug("with status: %d", status)
		return fmt.Errorf("PowerDNS API validation failed: %d - %s", status, string(respBody))
	}

	p.Logger.With("action", "provider.validate").Debug("API validation successful")
	return nil
}

func (p *PowerDNSProvider) serverID() string {
	if p.config.ServerID != "" {
		return p.config.ServerID
	}
	return "localhost"
}

func (p *PowerDNSProvider) apiURL(format string, args ...interface{}) string {
	apiHost := strings.TrimSuffix(p.config.APIHost, "/")
	format = strings.TrimPrefix(format, "/")
	return fmt.Sprintf(apiHost+"/"+format, args...)
}

func (p *PowerDNSProvider) authHeaders() map[string]string {
	headers := map[string]string{"Content-Type": "application/json"}
	if p.config.APIToken != "" {
		headers["X-API-Key"] = p.config.APIToken
	}
	return headers
}

func (p *PowerDNSProvider) patch(method, apiURL string, body map[string]interface{}) (int, []byte, error) {
	return p.BaseProvider.DoJSON(method, apiURL, p.authHeaders(), body)
}

func (p *PowerDNSProvider) sendPowerDNSPatch(apiURL string, body map[string]interface{}) error {
	status, respBody, err := p.patch("PATCH", apiURL, body)
	if err != nil {
		return err
	}

	if status >= 200 && status < 300 {
		return nil
	}

	return fmt.Errorf("PowerDNS API error: %d - %s", status, string(respBody))
}
