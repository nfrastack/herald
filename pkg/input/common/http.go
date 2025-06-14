// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"fmt"
	"io"
	"net/http"
)

// FetchRemoteResourceWithTLSConfig fetches a remote HTTP/HTTPS
func FetchRemoteResourceWithTLSConfig(url, user, pass string, headers map[string]string, tlsConfig *TLSConfig, logPrefix string) ([]byte, error) {
	// Create HTTP client with custom TLS configuration
	httpClient, err := tlsConfig.CreateHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("%s failed to create HTTP client: %w", logPrefix, err)
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s failed to create HTTP request: %w", logPrefix, err)
	}

	// Add basic auth if provided
	if user != "" && pass != "" {
		req.SetBasicAuth(user, pass)
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Perform request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s HTTP request failed: %w", logPrefix, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s HTTP %d: %s", logPrefix, resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s failed to read response body: %w", logPrefix, err)
	}

	return body, nil
}

// FetchRemoteResourceWithTLS fetches a remote HTTP/HTTPS resource with optional basic auth, custom headers, and TLS verification control.
// The user and pass parameters can be empty if no authentication is needed.
// The headers parameter can be nil if no custom headers are needed.
// The tlsVerify parameter controls whether to verify TLS certificates (false = skip verification like curl -k).
func FetchRemoteResourceWithTLS(url, user, pass string, headers map[string]string, logPrefix string, tlsVerify bool) ([]byte, error) {
	// Create a simple TLS config for backward compatibility
	tlsConfig := &TLSConfig{
		Verify: tlsVerify,
	}
	return FetchRemoteResourceWithTLSConfig(url, user, pass, headers, tlsConfig, logPrefix)
}

// FetchRemoteResource fetches a remote HTTP/HTTPS resource with optional basic auth and logs errors consistently.
// The user and pass parameters can be empty if no authentication is needed.
// This function uses TLS verification by default.
func FetchRemoteResource(url, user, pass, logPrefix string) ([]byte, error) {
	return FetchRemoteResourceWithTLS(url, user, pass, nil, logPrefix, true)
}

// FetchRemoteResourceWithHeaders fetches a remote HTTP/HTTPS resource with optional basic auth and custom headers.
// The user and pass parameters can be empty if no authentication is needed.
// The headers parameter can be nil if no custom headers are needed.
func FetchRemoteResourceWithHeaders(url, user, pass string, headers map[string]string, logPrefix string) ([]byte, error) {
	return FetchRemoteResourceWithTLS(url, user, pass, headers, logPrefix, true)
}
