// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"sync"
)

var stringMapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]string, 16) // Pre-allocate with reasonable capacity
	},
}

func GetStringMap() map[string]string {
	return stringMapPool.Get().(map[string]string)
}

func PutStringMap(m map[string]string) {
	for k := range m {
		delete(m, k)
	}
	stringMapPool.Put(m)
}
