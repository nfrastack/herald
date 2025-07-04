// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"herald/pkg/log"
	"herald/pkg/output/types/dns"
	"herald/pkg/util"

	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// PowerDNSProviderName is exported to ensure this file is included in builds
var PowerDNSProviderName = "powerdns"

// PowerDNSConfig holds configuration for the PowerDNS provider
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

// PowerDNSProvider implements the DNSProvider interface for PowerDNS
type PowerDNSProvider struct {
	config     PowerDNSConfig
	httpClient *http.Client
	logger     *log.ScopedLogger
}

func NewPowerDNSProvider(profileName string, cfg PowerDNSConfig) (*PowerDNSProvider, error) {
	client, err := newPowerDNSHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	// Create logger with profile prefix
	logPrefix := fmt.Sprintf("[output/dns/powerdns/%s]", profileName)
	logger := log.NewScopedLogger(logPrefix, "")

	return &PowerDNSProvider{
		config:     cfg,
		httpClient: client,
		logger:     logger,
	}, nil
}

func newPowerDNSHTTPClient(cfg PowerDNSConfig) (*http.Client, error) {
	if cfg.TLS.CA == "" && cfg.TLS.Cert == "" && cfg.TLS.Key == "" && !cfg.TLS.SkipVerify {
		return http.DefaultClient, nil
	}
	// Load CA cert
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
	// Load client cert
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

// CreateOrUpdateRecord creates or updates a DNS record
func (p *PowerDNSProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald")
}

// CreateOrUpdateRecordWithSource creates or updates a DNS record with source/comment
func (p *PowerDNSProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string) error {
	p.logger.Debug("Creating/updating record: domain=%s, type=%s, hostname=%s, target=%s, ttl=%d", domain, recordType, hostname, target, ttl)

	zoneID := p.config.ServerID
	if zoneID == "" {
		zoneID = "localhost"
	}
	apiURL := p.apiURL("/servers/%s/zones/%s.", zoneID, domain)

	recordName := hostname
	if hostname == "@" || hostname == "" {
		recordName = domain
	} else if hostname != "" && hostname != domain && !strings.HasSuffix(hostname, "."+domain) {
		recordName = hostname + "." + domain
	}

	// PowerDNS API expects a RRset structure
	// For CNAME records, ensure target ends with a dot (FQDN)
	recordContent := target
	if recordType == "CNAME" && !strings.HasSuffix(target, ".") {
		recordContent = target + "."
	}

	p.logger.Trace("Using record name: %s, content: %s", recordName, recordContent)

	rrset := map[string]interface{}{
		"name":       recordName + ".", // FQDN
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

// DeleteRecord deletes a DNS record
func (p *PowerDNSProvider) DeleteRecord(domain, recordType, hostname string) error {
	p.logger.Debug("Deleting record: domain=%s, type=%s, hostname=%s", domain, recordType, hostname)

	zoneID := p.config.ServerID
	if zoneID == "" {
		zoneID = "localhost"
	}
	apiURL := p.apiURL("/servers/%s/zones/%s.", zoneID, domain)

	recordName := hostname
	if hostname == "@" || hostname == "" {
		recordName = domain
	} else if hostname != "" && hostname != domain && !strings.HasSuffix(hostname, "."+domain) {
		recordName = hostname + "." + domain
	}

	p.logger.Trace("Using record name for deletion: %s", recordName)

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
	cfg := PowerDNSConfig{}
	if v, ok := config["api_host"]; ok {
		cfg.APIHost = v
	}
	if v, ok := config["api_token"]; ok {
		cfg.APIToken = util.ReadSecretValue(v)
	}
	if v, ok := config["server_id"]; ok {
		cfg.ServerID = v
	}
	if v, ok := config["tls.ca"]; ok {
		cfg.TLS.CA = v
	}
	if v, ok := config["tls.cert"]; ok {
		cfg.TLS.Cert = v
	}
	if v, ok := config["tls.key"]; ok {
		cfg.TLS.Key = v
	}
	if v, ok := config["tls.skip_verify"]; ok && (v == "true" || v == "1") {
		cfg.TLS.SkipVerify = true
	}
	return NewPowerDNSProvider(profileName, cfg)
}

func init() {
	// Register in the main DNS package registry, not the providers subpackage
	dns.RegisterProvider("powerdns", func(config map[string]string) (interface{}, error) {
		// Extract profile name from config or use default
		profileName := "default"
		if pn, ok := config["profile_name"]; ok {
			profileName = pn
		}
		return NewPowerDNSProviderFromConfig(profileName, config)
	})
}

// GetName returns the provider name
func (p *PowerDNSProvider) GetName() string {
	return "powerdns"
}

// Validate checks the PowerDNS API connection
func (p *PowerDNSProvider) Validate() error {
	p.logger.Debug("Validating PowerDNS API connection")

	zoneID := p.config.ServerID
	if zoneID == "" {
		zoneID = "localhost"
	}
	apiURL := p.apiURL("/servers/%s/zones", zoneID)

	p.logger.Trace("Validation request to: %s", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		p.logger.Debug("Failed to create validation request: %v", err)
		return err
	}
	p.setAuthHeaders(req)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.logger.Debug("Validation request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		p.logger.Debug("Validation failed with status: %s", resp.Status)
		return fmt.Errorf("PowerDNS API validation failed: %s", resp.Status)
	}

	p.logger.Debug("PowerDNS API validation successful")
	return nil
}

// --- Helpers ---
func (p *PowerDNSProvider) apiURL(format string, args ...interface{}) string {
	// Ensure API host doesn't end with slash, and format doesn't start with slash
	apiHost := strings.TrimSuffix(p.config.APIHost, "/")
	format = strings.TrimPrefix(format, "/")
	return fmt.Sprintf(apiHost+"/"+format, args...)
}

func (p *PowerDNSProvider) setAuthHeaders(req *http.Request) {
	if p.config.APIToken != "" {
		req.Header.Set("X-API-Key", p.config.APIToken)
	}
	req.Header.Set("Content-Type", "application/json")
}

func (p *PowerDNSProvider) sendPowerDNSPatch(apiURL string, body map[string]interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	// Debug: log the request details
	p.logger.Debug("API Request: %s", apiURL)
	p.logger.Trace("API Request Body: %s", string(jsonBody))

	req, err := http.NewRequest("PATCH", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	p.setAuthHeaders(req)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.logger.Debug("API Request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		p.logger.Debug("API Request successful: %s", resp.Status)
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	p.logger.Debug("API Request failed: %s - %s", resp.Status, string(respBody))
	return fmt.Errorf("PowerDNS API error: %s - %s", resp.Status, string(respBody))
}
