// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"fmt"
	"io"
	"net/http"
)

func FetchRemoteResourceWithTLSConfig(url, user, pass string, headers map[string]string, tlsConfig *TLSConfig, logPrefix string) ([]byte, error) {
	httpClient, err := tlsConfig.CreateHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("%s failed to create HTTP client: %w", logPrefix, err)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s failed to create HTTP request: %w", logPrefix, err)
	}

	if user != "" && pass != "" {
		req.SetBasicAuth(user, pass)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

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

func FetchRemoteResourceWithTLS(url, user, pass string, headers map[string]string, logPrefix string, tlsVerify bool) ([]byte, error) {
	tlsConfig := &TLSConfig{
		Verify: tlsVerify,
	}
	return FetchRemoteResourceWithTLSConfig(url, user, pass, headers, tlsConfig, logPrefix)
}

func FetchRemoteResource(url, user, pass, logPrefix string) ([]byte, error) {
	return FetchRemoteResourceWithTLS(url, user, pass, nil, logPrefix, true)
}

func FetchRemoteResourceWithHeaders(url, user, pass string, headers map[string]string, logPrefix string) ([]byte, error) {
	return FetchRemoteResourceWithTLS(url, user, pass, headers, logPrefix, true)
}
