// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// TLSConfig represents TLS configuration for HTTP clients
type TLSConfig struct {
	Verify bool   `mapstructure:"verify" yaml:"verify" json:"verify"`
	CA     string `mapstructure:"ca" yaml:"ca" json:"ca"`
	Cert   string `mapstructure:"cert" yaml:"cert" json:"cert"`
	Key    string `mapstructure:"key" yaml:"key" json:"key"`
}

// DefaultTLSConfig returns a default TLS configuration with verification enabled
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{
		Verify: true,
		CA:     "",
		Cert:   "",
		Key:    "",
	}
}

// ParseTLSConfigFromOptions parses TLS configuration from options map
func ParseTLSConfigFromOptions(options map[string]string) TLSConfig {
	config := DefaultTLSConfig()

	// Support legacy dns_verify option (convert to tls.verify)
	if verify, ok := options["dns_verify"]; ok {
		config.Verify = strings.ToLower(verify) != "false" && verify != "0"
	}

	// Parse tls_verify from options
	if verify, ok := options["tls_verify"]; ok {
		config.Verify = strings.ToLower(verify) != "false" && verify != "0"
	}

	// Parse nested tls.* options (e.g., tls.verify, tls.ca, tls.cert, tls.key)
	if verify, ok := options["tls.verify"]; ok {
		config.Verify = strings.ToLower(verify) != "false" && verify != "0"
	}
	if ca, ok := options["tls.ca"]; ok {
		config.CA = ca
	}
	if cert, ok := options["tls.cert"]; ok {
		config.Cert = cert
	}
	if key, ok := options["tls.key"]; ok {
		config.Key = key
	}

	// Also check for non-nested versions
	if config.CA == "" {
		config.CA = options["tls_ca"]
	}
	if config.Cert == "" {
		config.Cert = options["tls_cert"]
	}
	if config.Key == "" {
		config.Key = options["tls_key"]
	}

	return config
}

// IsSecure returns true if TLS verification is enabled or custom certificates are provided
func (tc TLSConfig) IsSecure() bool {
	return tc.Verify || (tc.CA != "" || tc.Cert != "" || tc.Key != "")
}

// HasCustomCerts returns true if custom certificates are configured
func (tc TLSConfig) HasCustomCerts() bool {
	return tc.CA != "" || (tc.Cert != "" && tc.Key != "")
}

// ValidateConfig validates the TLS configuration
func (tc TLSConfig) ValidateConfig() error {
	// If both cert and key are specified, both must exist
	if tc.Cert != "" && tc.Key != "" {
		if _, err := os.Stat(tc.Cert); os.IsNotExist(err) {
			return fmt.Errorf("client certificate file not found: %s", tc.Cert)
		}
		if _, err := os.Stat(tc.Key); os.IsNotExist(err) {
			return fmt.Errorf("client key file not found: %s", tc.Key)
		}
	} else if tc.Cert != "" || tc.Key != "" {
		return fmt.Errorf("both tls.cert and tls.key must be specified for client certificate authentication")
	}

	// If CA is specified, it must exist
	if tc.CA != "" {
		if _, err := os.Stat(tc.CA); os.IsNotExist(err) {
			return fmt.Errorf("CA certificate file not found: %s", tc.CA)
		}
	}

	return nil
}

// CreateTLSConfig creates a crypto/tls.Config from our TLSConfig
func (tc TLSConfig) CreateTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !tc.Verify,
	}

	// Load custom CA if specified
	if tc.CA != "" {
		caCert, err := os.ReadFile(tc.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file %s: %w", tc.CA, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", tc.CA)
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if both cert and key are specified
	if tc.Cert != "" && tc.Key != "" {
		cert, err := tls.LoadX509KeyPair(tc.Cert, tc.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate from %s and %s: %w", tc.Cert, tc.Key, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// CreateHTTPClient creates an HTTP client with the TLS configuration applied
func (tc TLSConfig) CreateHTTPClient() (*http.Client, error) {
	tlsConfig, err := tc.CreateTLSConfig()
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Connection pooling optimizations
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// CreateConfiguredHTTPClient creates an HTTP client with TLS configuration from options
func CreateConfiguredHTTPClient(options map[string]string, logPrefix string) (*http.Client, error) {
	tlsConfig := ParseTLSConfigFromOptions(options)
	if err := tlsConfig.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	client, err := tlsConfig.CreateHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return client, nil
}

// RemoteProviderConfig represents configuration for remote-based providers
type RemoteProviderConfig struct {
	TLS      TLSConfig `yaml:"tls" json:"tls"`
	Endpoint string    `yaml:"endpoint" json:"endpoint"`
	Timeout  int       `yaml:"timeout" json:"timeout"`
}

// ParseRemoteProviderConfig parses remote provider configuration from options
func ParseRemoteProviderConfig(options map[string]string) RemoteProviderConfig {
	config := RemoteProviderConfig{
		TLS:     ParseTLSConfigFromOptions(options),
		Timeout: 30, // Default 30 second timeout
	}

	if endpoint, exists := options["endpoint"]; exists {
		config.Endpoint = endpoint
	}
	if timeout, exists := options["timeout"]; exists {
		if t, err := strconv.Atoi(timeout); err == nil && t > 0 {
			config.Timeout = t
		}
	}

	return config
}

// CreateHTTPClient creates an HTTP client with the configured TLS settings
func (r RemoteProviderConfig) CreateHTTPClient() (*http.Client, error) {
	tlsConfig, err := r.TLS.CreateTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(r.Timeout) * time.Second,
	}

	return client, nil
}

// ValidateConfig validates the remote provider configuration
func (r RemoteProviderConfig) ValidateConfig() error {
	if err := r.TLS.ValidateConfig(); err != nil {
		return fmt.Errorf("TLS configuration error: %w", err)
	}

	if r.Endpoint == "" {
		return fmt.Errorf("endpoint is required for remote providers")
	}

	if r.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	return nil
}
