// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

type Record struct {
	Type    string
	Name    string
	Target  string
	TTL     int
	Proxied bool
}
