// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"herald/pkg/domain"
)

type ProviderFactory func(profileName string, config map[string]interface{}, outputWriter domain.OutputWriter, outputSyncer domain.OutputSyncer) (interface{}, error)

var providerFactories = make(map[string]ProviderFactory)

func RegisterProviderFactory(providerType string, factory ProviderFactory) {
	providerFactories[providerType] = factory
}

func GetProviderFactory(providerType string) (ProviderFactory, bool) {
	factory, ok := providerFactories[providerType]
	return factory, ok
}

func GetAvailableTypes() []string {
	types := make([]string, 0, len(providerFactories))
	for t := range providerFactories {
		types = append(types, t)
	}
	return types
}
