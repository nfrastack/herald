// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FetchRemoteResourceWithTLS fetches a remote HTTP/HTTPS resource with optional basic auth, custom headers, and TLS verification control.
// The user and pass parameters can be empty if no authentication is needed.
// The headers parameter can be nil if no custom headers are needed.
// The tlsVerify parameter controls whether to verify TLS certificates (false = skip verification like curl -k).
func FetchRemoteResourceWithTLS(url, user, pass string, headers map[string]string, logPrefix string, tlsVerify bool) ([]byte, error) {
	// Create transport with optional TLS verification
	transport := &http.Transport{}
	if !tlsVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		// Note: Debug logging is intentionally not used here to avoid import cycles
	}
	
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s HTTP request creation error for %s: %v", logPrefix, url, err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s HTTP GET error for %s: %v", logPrefix, url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("%s HTTP 401 Unauthorized: authentication required for %s", logPrefix, url)
	}
	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("%s HTTP 403 Forbidden: authorization failed for %s", logPrefix, url)
	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("%s HTTP 404 Not Found: resource not found at %s", logPrefix, url)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s HTTP error: response code %d for %s: %s", logPrefix, resp.StatusCode, url, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s Error reading response body: %v", logPrefix, err)
	}
	return data, nil
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
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s HTTP request creation error for %s: %v", logPrefix, url, err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
		// Optionally log that basic auth is being used
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s HTTP GET error for %s: %v", logPrefix, url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("%s HTTP 401 Unauthorized: authentication required for %s", logPrefix, url)
	}
	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("%s HTTP 403 Forbidden: authorization failed for %s", logPrefix, url)
	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("%s HTTP 404 Not Found: resource not found at %s", logPrefix, url)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s HTTP error: response code %d for %s: %s", logPrefix, resp.StatusCode, url, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s Error reading response body: %v", logPrefix, err)
	}
	return data, nil
}
