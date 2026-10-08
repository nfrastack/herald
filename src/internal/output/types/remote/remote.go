// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output/types/common"
	"github.com/nfrastack/herald/internal/util"

	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type RemoteFormat struct {
	url        string
	clientID   string
	token      string
	httpClient *http.Client
	records    map[string]*RemoteRecord
	removals   map[string]*RemoteRecord
	logger     *log.ScopedLogger
}

type RemoteRecord struct {
	Domain     string `json:"domain"`
	Hostname   string `json:"hostname"`
	Target     string `json:"target"`
	RecordType string `json:"type"`
	TTL        int    `json:"ttl"`
	Source     string `json:"source"`
}

func NewRemoteFormat(profileName string, config map[string]interface{}) (common.OutputFormat, error) {
	url := util.ReadSecretValue(remoteStringField(config, "url"))
	if url == "" {
		return nil, fmt.Errorf("remote output requires 'url' field")
	}

	clientID := util.ReadSecretValue(remoteStringField(config, "client_id"))
	if clientID == "" {
		return nil, fmt.Errorf("remote output requires 'client_id' field")
	}

	token := util.ReadSecretValue(remoteStringField(config, "token"))
	if token == "" {
		return nil, fmt.Errorf("remote output requires 'token' field")
	}

	tlsConfig, err := buildRemoteTLSConfig(config["tls"])
	if err != nil {
		return nil, fmt.Errorf("remote output TLS configuration: %w", err)
	}

	timeout := parseRemoteTimeout(config["timeout"])

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	logLevel := ""
	if level, ok := config["log_level"].(string); ok {
		logLevel = level
	}
	logPrefix := fmt.Sprintf("[output/remote/%s]", profileName)
	scopedLogger := log.NewScopedLogger(logPrefix, logLevel)

	return &RemoteFormat{
		url:      url,
		clientID: clientID,
		token:    token,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		records:  make(map[string]*RemoteRecord),
		removals: make(map[string]*RemoteRecord),
		logger:   scopedLogger,
	}, nil
}

func remoteStringField(config map[string]interface{}, key string) string {
	if v, ok := config[key].(string); ok {
		return v
	}
	return ""
}

func parseRemoteTimeout(value interface{}) time.Duration {
	const def = 30 * time.Second
	switch v := value.(type) {
	case nil:
		return def
	case string:
		if s := strings.TrimSpace(v); s != "" {
			if d, err := time.ParseDuration(s); err == nil && d > 0 {
				return d
			}
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
		return def
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
		return def
	case int64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
		return def
	case float64:
		if v > 0 {
			return time.Duration(v * float64(time.Second))
		}
		return def
	default:
		return def
	}
}

func buildRemoteTLSConfig(value interface{}) (*tls.Config, error) {
	tlsMap, _ := value.(map[string]interface{})
	verify := true
	if raw, ok := tlsMap["verify"]; ok {
		switch v := raw.(type) {
		case bool:
			verify = v
		case string:
			lower := strings.ToLower(strings.TrimSpace(util.ReadSecretValue(v)))
			verify = lower != "false" && lower != "0" && lower != "no" && lower != "off"
		}
	}

	cfg := &tls.Config{
		InsecureSkipVerify: !verify,
	}

	if raw, ok := tlsMap["ca"]; ok && raw != nil {
		caPath := util.ReadSecretValue(fmt.Sprintf("%v", raw))
		if caPath == "" {
			return nil, fmt.Errorf("tls.ca is empty")
		}
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caPath)
		}
		cfg.RootCAs = pool
	}

	certPath, hasCert := tlsMap["cert"]
	keyPath, hasKey := tlsMap["key"]
	if hasCert || hasKey {
		certFile := ""
		keyFile := ""
		if hasCert && certPath != nil {
			certFile = util.ReadSecretValue(fmt.Sprintf("%v", certPath))
		}
		if hasKey && keyPath != nil {
			keyFile = util.ReadSecretValue(fmt.Sprintf("%v", keyPath))
		}
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("both tls.cert and tls.key must be specified for client certificate authentication")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate from %s and %s: %w", certFile, keyFile, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

func (r *RemoteFormat) GetName() string {
	return "remote"
}

func (r *RemoteFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return r.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "herald")
}

func (r *RemoteFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	key := fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)

	record := &RemoteRecord{
		Domain:     domain,
		Hostname:   hostname,
		Target:     target,
		RecordType: recordType,
		TTL:        ttl,
		Source:     source,
	}

	r.records[key] = record
	r.logger.With("action", "record.create").Debug("record: %s.%s (%s) -> %s", hostname, domain, recordType, target)
	r.logger.With("action", "api.upload").Debug("domain=%s, hostname=%s, recordType=%s, target=%s, ttl=%d, source=%s", domain, hostname, recordType, target, ttl, source)
	return nil
}

func (r *RemoteFormat) RemoveRecord(domain, hostname, recordType string) error {
	key := fmt.Sprintf("%s:%s:%s", domain, hostname, recordType)
	if rec, exists := r.records[key]; exists {
		delete(r.records, key)
		r.removals[key] = rec
		r.logger.With("action", "record.delete").Debug("record: %s.%s (%s) [queued for API removal]", hostname, domain, recordType)
	} else {
		r.removals[key] = &RemoteRecord{
			Domain:     domain,
			Hostname:   hostname,
			RecordType: recordType,
		}
		r.logger.With("action", "record.delete").Debug("removal for missing record: %s.%s (%s)", hostname, domain, recordType)
	}
	return nil
}

func (r *RemoteFormat) Sync() error {

	additionsByDomain := make(map[string][]*RemoteRecord)
	for _, record := range r.records {
		additionsByDomain[record.Domain] = append(additionsByDomain[record.Domain], record)
	}

	removalsByDomain := make(map[string][]*RemoteRecord)
	for _, record := range r.removals {
		removalsByDomain[record.Domain] = append(removalsByDomain[record.Domain], record)
	}

	allDomains := make(map[string]struct{})
	for domain := range additionsByDomain {
		allDomains[domain] = struct{}{}
	}
	for domain := range removalsByDomain {
		allDomains[domain] = struct{}{}
	}

	generator := "herald"
	metadata := map[string]interface{}{
		"generator":    generator,
		"generated_at": time.Now().Format(time.RFC3339),
		"last_updated": time.Now().Format(time.RFC3339),
	}

	domains := make(map[string]map[string]interface{})
	for domain := range allDomains {
		records := additionsByDomain[domain]
		if records == nil {
			records = []*RemoteRecord{} // ensure empty slice, not nil
		}
		domains[domain] = map[string]interface{}{
			"records": records,
		}
	}

	payload := map[string]interface{}{
		"client_id": r.clientID,
		"metadata":  metadata,
		"domains":   domains,
		"removals":  removalsByDomain, // still send removals for delta sync
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	r.logger.With("action", "api.upload").Trace("payload: %s", string(jsonData))

	req, err := http.NewRequest("POST", r.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("X-Client-ID", r.clientID)
	req.Header.Set("User-Agent", generator)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote API returned status %d", resp.StatusCode)
	}

	r.logger.With("action", "sync.done").Info("%d records and %d removals to remote endpoint", len(r.records), len(r.removals))
	r.records = make(map[string]*RemoteRecord)
	r.removals = make(map[string]*RemoteRecord)
	return nil
}

var _ common.OutputFormat = (*RemoteFormat)(nil)
