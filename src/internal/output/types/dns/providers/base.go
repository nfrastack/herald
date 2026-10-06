// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/util"

	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type BaseProvider struct {
	Name        string
	ProfileName string
	Config      map[string]string
	Logger      *log.ScopedLogger
	HTTPClient  *http.Client
	Timeout     time.Duration
	Retries     int
}

func NewBaseProvider(name, profileName string, config map[string]string) *BaseProvider {
	if profileName == "" {
		profileName = "default"
	}
	if config == nil {
		config = make(map[string]string)
	}

	retries := 3
	if v, ok := config["retries"]; ok && v != "" {
		if r, err := strconv.Atoi(v); err == nil {
			retries = r
		}
	}

	timeout := 30 * time.Second
	if v, ok := config["timeout"]; ok && v != "" {
		if t, err := strconv.Atoi(v); err == nil {
			timeout = time.Duration(t) * time.Second
		}
	}

	prefix := fmt.Sprintf("[output/dns/%s/%s]", name, profileName)
	logger := log.NewScopedLogger(prefix, config["log_level"])

	return &BaseProvider{
		Name:        name,
		ProfileName: profileName,
		Config:      config,
		Logger:      logger,
		HTTPClient:  &http.Client{Timeout: timeout},
		Timeout:     timeout,
		Retries:     retries,
	}
}

func BuildFQDN(hostname, domain string) string {
	if hostname == "" || hostname == "@" {
		return domain
	}
	if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
		return hostname
	}
	return hostname + "." + domain
}

func RelativeName(hostname, domain string) string {
	fqdn := BuildFQDN(hostname, domain)
	if fqdn == domain {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+domain)
}

func (b *BaseProvider) Secret(key string, fallbacks ...string) string {
	keys := append([]string{key}, fallbacks...)
	for _, k := range keys {
		if v, ok := b.Config[k]; ok && v != "" {
			return util.ReadSecretValue(v)
		}
	}
	return ""
}

func (b *BaseProvider) Option(key, def string) string {
	if v, ok := b.Config[key]; ok && v != "" {
		return util.ReadSecretValue(v)
	}
	if v, ok := b.Config["options."+key]; ok && v != "" {
		return util.ReadSecretValue(v)
	}
	return def
}

func (b *BaseProvider) DoJSON(method, url string, headers map[string]string, body interface{}) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		b.Logger.Trace("API Request Body: %s", string(raw))
		reader = bytes.NewReader(raw)
	}

	b.Logger.Debug("API Request: %s %s", method, url)

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := b.HTTPClient.Do(req)
	if err != nil {
		b.Logger.Debug("API Request failed: %v", err)
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		b.Logger.Debug("API Request successful: %s", resp.Status)
	} else {
		b.Logger.Debug("API Request failed: %s - %s", resp.Status, string(respBody))
	}
	return resp.StatusCode, respBody, nil
}

func (b *BaseProvider) Sleep(attempt int, base time.Duration) {
	time.Sleep(base * time.Duration(attempt))
}

type TokenCache struct {
	mu     sync.Mutex
	token  string
	expiry time.Time
}

func (c *TokenCache) Get(refresh func() (string, time.Time, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry) {
		return c.token, nil
	}
	token, expiry, err := refresh()
	if err != nil {
		return "", err
	}
	c.token = token
	c.expiry = expiry
	return token, nil
}
