// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package output

import (
	"github.com/nfrastack/herald/internal/common"
	"github.com/nfrastack/herald/internal/log"

	"fmt"
	"strings"
)

var mgrLog = log.NewScopedLogger("[output/manager]", "")

func (m *OutputManager) RouteRecords(domainConfigKey, domain string, records []common.Record) error {
	logPrefix := common.GetDomainLogPrefix(domainConfigKey, domain)
	fmt.Printf("%s Routing %d records\n", logPrefix, len(records))
	mgrLog.With("action", "domain.route", "domain", domain, "config", domainConfigKey).Debug("records")

	if err := m.SyncAll(); err != nil {
		mgrLog.With("action", "sync.fail", "domain", domain, "config", domainConfigKey).Error("SyncAll after routing records: %v", err)
		return err
	}

	return nil
}

func (om *OutputManager) WriteRecordToOutputs(allowedOutputs []string, domain, hostname, target, recordType string, ttl int, source string, proxied bool, overwrite bool) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	if len(allowedOutputs) == 0 {
		mgrLog.With("action", "record.skip", "domain", domain).Warn("outputs allowed: none, skipping write: %s", hostname)
		return nil
	}

	mgrLog.With("action", "domain.route", "domain", domain, "source", source).Debug("record write: hostname='%s', target='%s', recordType='%s', ttl=%d, proxied=%t, allowedOutputs=%v", hostname, target, recordType, ttl, proxied, allowedOutputs)

	writtenCount := 0
	var errors []string

	for _, outputProfile := range allowedOutputs {
		if profile, exists := om.profiles[outputProfile]; exists {
			written, errStr := om.writeToProfile(outputProfile, profile, domain, hostname, target, recordType, ttl, source, proxied, overwrite)
			if errStr != "" {
				errors = append(errors, errStr)
			} else if written {
				writtenCount++
			}
		} else {
			mgrLog.With("action", "output.write", "profile", outputProfile).Warn("profile not found")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to write to some outputs: %s", strings.Join(errors, "; "))
	}

	if writtenCount > 0 {
		mgrLog.With("action", "output.write").Debug("to %d output profiles", writtenCount)
	}

	return nil
}

func (om *OutputManager) RemoveRecordFromOutputs(allowedOutputs []string, domain, hostname, recordType, source string) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	if len(allowedOutputs) == 0 {
		mgrLog.With("action", "output.remove").Debug("output profiles specified for removal: none, skipping")
		return nil
	}

	mgrLog.With("action", "domain.route", "domain", domain, "source", source).Debug("record removal: hostname='%s', recordType='%s', allowedOutputs=%v",
		hostname, recordType, allowedOutputs)

	var errors []string
	removedCount := 0

	for _, profileName := range allowedOutputs {
		provider, exists := om.profiles[profileName]
		if !exists {
			errStr := fmt.Sprintf("output profile '%s' not found for domain '%s'", profileName, domain)
			mgrLog.With("action", "output.remove").Error("%s", errStr)
			errors = append(errors, errStr)
			continue
		}

		err := provider.RemoveRecord(domain, hostname, recordType)
		if err != nil {
			errStr := fmt.Sprintf("failed to remove record from profile '%s': %v", profileName, err)
			mgrLog.With("action", "output.remove").Error("%s", errStr)
			errors = append(errors, errStr)
		} else {
			mgrLog.With("action", "output.remove", "profile", profileName).Debug("record from profile")
			removedCount++

			om.changesMutex.Lock()
			if om.changedProfiles[source] == nil {
				om.changedProfiles[source] = make(map[string]bool)
			}
			om.changedProfiles[source][profileName] = true
			om.changesMutex.Unlock()
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove from %d output profiles: %s", len(errors), strings.Join(errors, "; "))
	}

	return nil
}

func (om *OutputManager) ListProfileNames() []string {
	om.mutex.RLock()
	defer om.mutex.RUnlock()
	profileNames := make([]string, 0, len(om.profiles))
	for name := range om.profiles {
		profileNames = append(profileNames, name)
	}
	return profileNames
}
