// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"fmt"
	"io"
	"net/http"
)

// FetchRemoteResource fetches a remote HTTP/HTTPS resource with optional basic auth and logs errors consistently.
// The user and pass parameters can be empty if no authentication is needed.
func FetchRemoteResource(url, user, pass, logPrefix string) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s HTTP request creation error for %s: %v", logPrefix, url, err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
		// Optionally log that basic auth is being used
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s HTTP GET error for %s: %v", logPrefix, url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 401 {
			return nil, fmt.Errorf("%s HTTP 401 Unauthorized: authentication required for %s", logPrefix, url)
		}
		return nil, fmt.Errorf("%s HTTP error: response code %d for %s", logPrefix, resp.StatusCode, url)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s Error reading response body: %v", logPrefix, err)
	}
	return data, nil
}
