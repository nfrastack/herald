// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"fmt"
	"sync"
)

// Provider defines the interface that all DNS providers must implement
type Provider interface {
	CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool) error
	CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string) error
	DeleteRecord(domain, recordType, hostname string) error
	GetName() string
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
		return nil, fmt.Errorf("unknown DNS provider '%s'", name)
	}
	return constructor(config)
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
