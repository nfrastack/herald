// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

type OutputWriter interface {
	WriteRecordToOutputs(allowedOutputs []string, domain, hostname, target, recordType string, ttl int, source string, proxied bool, overwrite bool) error
	RemoveRecordFromOutputs(allowedOutputs []string, domain, hostname, recordType, source string) error
}

type OutputSyncer interface {
	SyncAllFromSource(source string) error
}
