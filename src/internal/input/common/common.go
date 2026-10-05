// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"sync"
)

// Pool for reusable string maps to reduce GC pressure
var stringMapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]string, 16) // Pre-allocate with reasonable capacity
	},
}

// GetStringMap gets a reusable string map from the pool
func GetStringMap() map[string]string {
	return stringMapPool.Get().(map[string]string)
}

// PutStringMap returns a string map to the pool after clearing it
func PutStringMap(m map[string]string) {
	// Clear the map but keep the allocated capacity
	for k := range m {
		delete(m, k)
	}
	stringMapPool.Put(m)
}
