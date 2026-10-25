// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	state "github.com/nfrastack/herald/internal/state"
)

type Provider interface {
	CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error

	CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error

	DeleteRecord(domain, recordType, hostname string) error

	GetName() string

	SupportsProxied() bool

	Validate() error
}

type ProviderConstructor func(config map[string]string) (Provider, error)

var providerRegistry = make(map[string]ProviderConstructor)
var registryMutex sync.RWMutex

func RegisterProvider(name string, constructor func(map[string]string) (interface{}, error)) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	providerRegistry[name] = func(config map[string]string) (Provider, error) {
		prov, err := constructor(config)
		if err != nil {
			return nil, err
		}
		provider, ok := prov.(Provider)
		if !ok {
			return nil, fmt.Errorf("provider '%s' does not implement Provider interface", name)
		}
		return provider, nil
	}
}

func GetProvider(name string, config map[string]string) (Provider, error) {
	registryMutex.RLock()
	constructor, exists := providerRegistry[name]
	registryMutex.RUnlock()

	if !exists {
		availableProviders := GetAvailableProviders()
		return nil, fmt.Errorf("unknown DNS provider '%s'. Available providers: %v", name, availableProviders)
	}

	processedConfig := ProcessConfigValues(config)

	return constructor(processedConfig)
}

func GetAvailableProviders() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	providers := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		providers = append(providers, name)
	}
	return providers
}

func ValidateProviderExists(providerName string) error {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	if _, exists := providerRegistry[providerName]; !exists {
		availableProviders := GetAvailableProviders()
		return fmt.Errorf("unknown DNS provider '%s'. Available providers: %v", providerName, availableProviders)
	}
	return nil
}

func ProcessConfigValues(config map[string]string) map[string]string {
	processed := make(map[string]string)
	for key, value := range config {
		processed[key] = processConfigValue(value)
	}
	return processed
}

func processConfigValue(value string) string {
	if strings.HasPrefix(value, "file://") {
		filePath := value[7:] // Remove "file://" prefix

		content, err := os.ReadFile(filePath)
		if err != nil {
			return value
		}

		return strings.TrimSpace(string(content))
	}

	if strings.HasPrefix(value, "env://") {
		envName := value[6:] // Remove "env://" prefix

		envValue := os.Getenv(envName)
		if envValue == "" {
			return value
		}

		return envValue
	}

	return value
}

type writtenState struct {
	target  string
	ttl     int
	proxied bool
	touched time.Time
}

type DNSOutputFormat struct {
	ProfileName string
	Provider    Provider
	Config      map[string]interface{}

	mu               sync.Mutex
	lastWritten      map[string]writtenState
	reassertInterval time.Duration
	reassertParsed   bool
}

func dnsCacheKey(domain, hostname, recordType string) string {
	return domain + "\x00" + hostname + "\x00" + recordType
}

func (d *DNSOutputFormat) shouldWrite(domain, hostname, target, recordType string, ttl int, proxied bool) bool {
	key := dnsCacheKey(domain, hostname, recordType)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lastWritten == nil {
		d.lastWritten = make(map[string]writtenState)
	}
	if !d.reassertParsed {
		d.reassertParsed = true
		d.reassertInterval = parseReassertInterval(d.Config["reassert_interval"])
	}
	if prev, ok := d.lastWritten[key]; ok && prev.target == target && prev.ttl == ttl && prev.proxied == proxied {
		if d.reassertInterval > 0 && time.Since(prev.touched) >= d.reassertInterval {
			return true
		}
		return false
	}
	return true
}
func parseReassertInterval(v interface{}) time.Duration {
	switch t := v.(type) {
	case nil:
		return 0
	case string:
		if s := strings.TrimSpace(t); s != "" {
			if s == "0" || strings.ToLower(s) == "off" || strings.ToLower(s) == "never" {
				return 0
			}
			if d, err := time.ParseDuration(s); err == nil && d > 0 {
				return d
			}
		}
		return 0
	case int:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
		return 0
	case int64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
		return 0
	case float64:
		if t > 0 {
			return time.Duration(t * float64(time.Second))
		}
		return 0
	default:
		return 0
	}
}

func (d *DNSOutputFormat) noteWritten(domain, hostname, target, recordType string, ttl int, proxied bool) {
	key := dnsCacheKey(domain, hostname, recordType)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lastWritten == nil {
		d.lastWritten = make(map[string]writtenState)
	}
	d.lastWritten[key] = writtenState{target: target, ttl: ttl, proxied: proxied, touched: time.Now()}
}

func (d *DNSOutputFormat) forget(domain, hostname, recordType string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.lastWritten, dnsCacheKey(domain, hostname, recordType))
}

func (d *DNSOutputFormat) GetName() string {
	return fmt.Sprintf("dns/%s", d.Provider.GetName())
}

func (d *DNSOutputFormat) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	proxied := false
	if d.Config != nil {
		if p, ok := d.Config["proxied"].(bool); ok {
			proxied = p
		} else if ps, ok := d.Config["proxied"].(string); ok {
			if strings.ToLower(ps) == "true" {
				proxied = true
			}
		}
	}
	if !d.shouldWrite(domain, hostname, target, recordType, ttl, proxied) {
		return nil
	}
	if err := d.Provider.CreateOrUpdateRecord(domain, recordType, hostname, target, ttl, proxied, false); err != nil {
		return err
	}
	d.noteWritten(domain, hostname, target, recordType, ttl, proxied)
	return nil
}

func (d *DNSOutputFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	proxied := false
	if d.Config != nil {
		if p, ok := d.Config["proxied"].(bool); ok {
			proxied = p
		} else if ps, ok := d.Config["proxied"].(string); ok {
			if strings.ToLower(ps) == "true" {
				proxied = true
			}
		}
	}
	if !d.shouldWrite(domain, hostname, target, recordType, ttl, proxied) {
		return nil
	}
	comment := state.CommentFor(domain, hostname, recordType, source)
	if err := d.Provider.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, comment, source, false); err != nil {
		return err
	}
	d.noteWritten(domain, hostname, target, recordType, ttl, proxied)
	return nil
}

func (d *DNSOutputFormat) RemoveRecord(domain, hostname, recordType string) error {
	d.forget(domain, hostname, recordType)
	return d.Provider.DeleteRecord(domain, recordType, hostname)
}

func (d *DNSOutputFormat) Sync() error {
	return nil
}
