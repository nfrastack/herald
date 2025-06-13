// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package formats

import (
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"
	"dns-companion/pkg/output/formats/outputCommon"

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

	"gopkg.in/yaml.v3"
)

// RemoteFormat implements OutputFormat for remote aggregator servers
type RemoteFormat struct {
	*outputCommon.CommonFormat
	url         string
	token       string
	clientID    string
	timeout     time.Duration
	format      string // "json" or "yaml"
	logger      *log.ScopedLogger
	tlsConfig   *tls.Config // TLS configuration for HTTPS requests
	logPrefix   string
}

// RemoteData represents the data structure sent to remote aggregator
type RemoteData struct {
	ClientID    string                         `json:"client_id" yaml:"client_id"`
	LastUpdate  time.Time                      `json:"last_update" yaml:"last_update"`
	Metadata    *RemoteMetadata                `json:"metadata" yaml:"metadata"`
	Domains     map[string]*RemoteDomain       `json:"domains" yaml:"domains"`
}

type RemoteMetadata struct {
	Generator   string    `json:"generator" yaml:"generator"`
	Hostname    string    `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
	Comment     string    `json:"comment,omitempty" yaml:"comment,omitempty"`
}

type RemoteDomain struct {
	Comment  string              `json:"comment,omitempty" yaml:"comment,omitempty"`
	ZoneID   string              `json:"zone_id,omitempty" yaml:"zone_id,omitempty"`
	Provider string              `json:"provider,omitempty" yaml:"provider,omitempty"`
	Records  []*RemoteRecord     `json:"records" yaml:"records"`
}

type RemoteRecord struct {
	Hostname  string    `json:"hostname" yaml:"hostname"`
	Type      string    `json:"type" yaml:"type"`
	Target    string    `json:"target" yaml:"target"`
	TTL       uint32    `json:"ttl" yaml:"ttl"`
	Comment   string    `json:"comment,omitempty" yaml:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	Source    string    `json:"source,omitempty" yaml:"source,omitempty"`
}

// Helper functions for file:// support
func getConfigValue(config map[string]interface{}, key string) string {
	val, ok := config[key].(string)
	if !ok || val == "" {
		return ""
	}

	// Support file:// references
	if strings.HasPrefix(val, "file://") {
		filePath := val[7:] // Remove "file://" prefix
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Error("[remote] Failed to read file %s: %v", filePath, err)
			return val // Return original value on error
		}
		return strings.TrimSpace(string(content))
	}

	return val
}

func getConfigValueWithDefault(config map[string]interface{}, key, defaultValue string) string {
	val := getConfigValue(config, key)
	if val == "" {
		return defaultValue
	}
	return val
}

// NewRemoteFormat creates a new remote format instance
func NewRemoteFormat(profileName string, config map[string]interface{}) (output.OutputFormat, error) {
	logPrefix := fmt.Sprintf("[output/remote/%s]", profileName)
	common, err := outputCommon.NewCommonFormat(profileName, "remote", config)
	if err != nil {
		return nil, err
	}

	url := getConfigValue(config, "url")
	if url == "" {
		return nil, fmt.Errorf("%s url is required for remote format", logPrefix)
	}

	token := getConfigValue(config, "token")
	if token == "" {
		return nil, fmt.Errorf("%s token is required for remote format", logPrefix)
	}

	clientID := getConfigValueWithDefault(config, "client_id", func() string {
		hostname, _ := os.Hostname()
		if hostname == "" {
			return "unknown"
		}
		return hostname
	}())

	timeout := 30 * time.Second
	if timeoutStr := getConfigValue(config, "timeout"); timeoutStr != "" {
		if d, err := time.ParseDuration(timeoutStr); err == nil {
			timeout = d
		}
	}

	format := "json"
	if formatStr := getConfigValue(config, "data_format"); formatStr == "yaml" || formatStr == "json" {
		format = formatStr
	}

	// Create scoped logger
	scopedLogger := outputCommon.AddScopedLogging(nil, "remote", profileName, config)
	// Configure TLS settings
	tlsConfig := &tls.Config{}

	// Configure TLS verification
	if verify, ok := config["tls"].(map[string]interface{}); ok {
		if verifyBool, ok := verify["verify"].(bool); ok && !verifyBool {
			tlsConfig.InsecureSkipVerify = true
			scopedLogger.Warn("TLS certificate verification disabled - use with caution!")
		}

		// Load custom CA certificate if provided
		if caFile := getConfigValue(verify, "ca"); caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA file: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
			scopedLogger.Info("Using custom CA certificate: %s", caFile)
		}

		// Load client certificate for mutual TLS if provided
		if certFile := getConfigValue(verify, "cert"); certFile != "" {
			if keyFile := getConfigValue(verify, "key"); keyFile != "" {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return nil, fmt.Errorf("failed to load client certificate: %w", err)
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
				scopedLogger.Info("Using client certificate for mutual TLS: %s", certFile)
			} else {
				return nil, fmt.Errorf("tls cert specified but key is missing")
			}
		}
	} else {
		// Fallback to old flat structure for backward compatibility
		if verify, ok := config["tls_verify"].(bool); ok && !verify {
			tlsConfig.InsecureSkipVerify = true
			scopedLogger.Warn("TLS certificate verification disabled - use with caution!")
		}

		if caFile := getConfigValue(config, "tls_ca"); caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA file: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
			scopedLogger.Info("Using custom CA certificate: %s", caFile)
		}

		if certFile := getConfigValue(config, "tls_cert"); certFile != "" {
			if keyFile := getConfigValue(config, "tls_key"); keyFile != "" {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return nil, fmt.Errorf("failed to load client certificate: %w", err)
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
				scopedLogger.Info("Using client certificate for mutual TLS: %s", certFile)
			} else {
				return nil, fmt.Errorf("tls_cert specified but tls_key is missing")
			}
		}
	}

	format_instance := &RemoteFormat{
		CommonFormat: common,
		url:          url,
		token:        token,
		clientID:     clientID,
		timeout:      timeout,
		format:       format,
		logger:       scopedLogger,
		tlsConfig:    tlsConfig,
		logPrefix:    logPrefix,
	}

	// Log configuration details
	scopedLogger.Info("Configured remote output")
	scopedLogger.Verbose("Remote API configuration: url=%s, client_id=%s", url, clientID)
	scopedLogger.Debug("Remote API configuration: format=%s, timeout=%v", format, timeout)
	scopedLogger.Debug("Remote API TLS configuration: verify=%t, ca=%s, cert=%s",
		!tlsConfig.InsecureSkipVerify,
		func() string {
			if tlsConfig.RootCAs != nil {
				return "configured"
			} else {
				return "system"
			}
		}(),
		func() string {
			if len(tlsConfig.Certificates) > 0 {
				return "configured"
			} else {
				return "none"
			}
		}())
	scopedLogger.Trace("Remote API format instance created successfully for profile '%s'", profileName)

	return format_instance, nil
}

// GetName returns the format name
func (r *RemoteFormat) GetName() string {
	return "remote"
}

// Sync sends all domain data to the remote aggregator
func (r *RemoteFormat) Sync() error {
	r.logger.Debug("Starting sync to remote aggregator")
	r.logger.Trace("Sync called on remote format with %d records", r.GetRecordCount())

	// For remote, we bypass the normal file writing and only send via HTTP
	// We call the serializer directly with the current data
	return r.SyncWithoutFile(r.serializeAndSend)
}

// SyncWithoutFile performs sync without file operations (HTTP only)
func (r *RemoteFormat) SyncWithoutFile(serializer func(*outputCommon.ExportData) ([]byte, error)) error {
	exportData := r.CommonFormat.GetExportData()

	_, err := serializer(exportData)
	if err != nil {
		r.logger.Error("Failed to sync to remote aggregator: %v", err)
		return err
	}

	return nil
}

// serializeAndSend handles the serialization and HTTP transmission
func (r *RemoteFormat) serializeAndSend(export *outputCommon.ExportData) ([]byte, error) {
	r.logger.Trace("Starting serialization and send process")

	// Convert export data to remote API format
	domains := make(map[string]*RemoteDomain)

	r.logger.Debug("Converting %d domains to remote API format", len(export.Domains))
	for domainName, domainData := range export.Domains {
		apiRecords := make([]*RemoteRecord, 0, len(domainData.Records))

		r.logger.Trace("Processing domain '%s' with %d records", domainName, len(domainData.Records))
		for _, record := range domainData.Records {
			apiRecord := &RemoteRecord{
				Hostname:  record.Hostname,
				Type:      record.Type,
				Target:    record.Target,
				TTL:       uint32(record.TTL),
				Comment:   record.Comment,
				CreatedAt: record.CreatedAt,
				Source:    record.Source,
			}
			apiRecords = append(apiRecords, apiRecord)
			r.logger.Trace("Converted record: %s.%s (%s) -> %s", record.Hostname, domainName, record.Type, record.Target)
		}

		domains[domainName] = &RemoteDomain{
			Comment: domainData.Comment,
			Records: apiRecords,
		}
	}

	// Get hostname for metadata
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
		r.logger.Debug("Unable to determine hostname, using 'unknown'")
	} else {
		r.logger.Trace("Using hostname for metadata: %s", hostname)
	}

	// Create the data structure to send
	data := &RemoteData{
		ClientID:   r.clientID,
		LastUpdate: time.Now(),
		Metadata: &RemoteMetadata{
			Generator:   export.Metadata.Generator,
			Hostname:    hostname,
			GeneratedAt: export.Metadata.GeneratedAt,
			LastUpdated: export.Metadata.LastUpdated,
			Comment:     export.Metadata.Comment,
		},
		Domains: domains,
	}

	r.logger.Debug("Prepared data structure with client_id=%s, %d domains", r.clientID, len(domains))
	r.logger.Trace("Data structure: %+v", data)

	return r.sendData(data)
}

// sendData sends the data to the remote aggregator
func (r *RemoteFormat) sendData(data *RemoteData) ([]byte, error) {
	var payload []byte
	var contentType string
	var err error

	switch r.format {
	case "yaml":
		payload, err = yaml.Marshal(data)
		contentType = "application/x-yaml"
		r.logger.Trace("Marshaled data to YAML format (%d bytes)", len(payload))
	default: // json
		payload, err = json.Marshal(data)
		contentType = "application/json"
		r.logger.Trace("Marshaled data to JSON format (%d bytes)", len(payload))
	}

	if err != nil {
		r.logger.Error("Failed to marshal data to %s: %v", r.format, err)
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", r.url, bytes.NewBuffer(payload))
	if err != nil {
		r.logger.Error("Failed to create HTTP request: %v", err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("X-Client-ID", r.clientID)
	r.logger.Trace("Set request headers: Content-Type=%s, X-Client-ID=%s", contentType, r.clientID)

	// Create HTTP client with timeout and TLS config
	client := &http.Client{
		Timeout: r.timeout,
		Transport: &http.Transport{
			TLSClientConfig: r.tlsConfig,
		},
	}

	// Send request
	r.logger.Debug("Sending %d bytes to %s", len(payload), r.url)
	r.logger.Trace("Request payload preview: %s", func() string {
		preview := string(payload)
		if len(preview) > 200 {
			return preview[:200] + "..."
		}
		return preview
	}())

	resp, err := client.Do(req)
	if err != nil {
		r.logger.Error("HTTP request failed: %v", err)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for logging/debugging
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		r.logger.Warn("Failed to read response body: %v", readErr)
		body = []byte("(unable to read response)")
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		r.logger.Error("Request failed with status %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	r.logger.Info("Successfully sent %d domains to remote API server", len(data.Domains))
	r.logger.Debug("Response status: %d, body length: %d bytes", resp.StatusCode, len(body))
	r.logger.Trace("Response body: %s", string(body))
	return payload, nil
}

// init registers this format
func init() {
	output.RegisterFormat("remote", NewRemoteFormat)
}