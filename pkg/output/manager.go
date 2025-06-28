package output

import (
	"fmt"
	"herald/pkg/common"
	"herald/pkg/log"
	"strings"
)

func (m *OutputManager) RouteRecords(domainConfigKey, domain string, records []common.Record) error {
	logPrefix := common.GetDomainLogPrefix(domainConfigKey, domain)
	fmt.Printf("%s Routing %d records\n", logPrefix, len(records))
	log.Debug("%s Successfully routed records\n", logPrefix) // Changed to log.Debug

	// Route each record to the appropriate outputs (existing logic)
	// ...existing code...

	// After routing, flush outputs if any changes occurred
	if err := m.SyncAll(); err != nil {
		log.Error("%s OutputManager SyncAll failed after routing records: %v", logPrefix, err)
		return err
	}

	return nil
}

// WriteRecordToOutputs writes a DNS record to the specified list of output profiles.
func (om *OutputManager) WriteRecordToOutputs(allowedOutputs []string, domain, hostname, target, recordType string, ttl int, source string) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	if len(allowedOutputs) == 0 {
		log.Warn("[output/manager] No outputs allowed for record %s.%s - skipping write", hostname, domain)
		return nil
	}

	log.Debug("[output/manager] Routing record write: domain='%s', hostname='%s', target='%s', recordType='%s', ttl=%d, source='%s', allowedOutputs=%v", domain, hostname, target, recordType, ttl, source, allowedOutputs)

	writtenCount := 0
	var errors []string

	for _, outputProfile := range allowedOutputs {
		if profile, exists := om.profiles[outputProfile]; exists {
			if err := profile.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source); err != nil {
				errors = append(errors, fmt.Sprintf("profile '%s': %v", outputProfile, err))
			} else {
				log.Debug("[output/manager] Successfully wrote record to profile '%s'", outputProfile)
				writtenCount++

				// Mark this profile as changed for this source
				om.changesMutex.Lock()
				if om.changedProfiles[source] == nil {
					om.changedProfiles[source] = make(map[string]bool)
				}
				om.changedProfiles[source][outputProfile] = true
				om.changesMutex.Unlock()
			}
		} else {
			log.Warn("[output/manager] Output profile '%s' not found", outputProfile)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to write to some outputs: %s", strings.Join(errors, "; "))
	}

	if writtenCount > 0 {
		log.Debug("[output/manager] Successfully wrote to %d output profiles", writtenCount)
	}

	return nil
}

// RemoveRecordFromOutputs removes a record from the specified list of output profiles.
func (om *OutputManager) RemoveRecordFromOutputs(allowedOutputs []string, domain, hostname, recordType, source string) error {
	om.mutex.RLock()
	defer om.mutex.RUnlock()

	if len(allowedOutputs) == 0 {
		log.Debug("No output profiles specified for removal, skipping")
		return nil
	}

	log.Debug("Routing record removal: domain='%s', hostname='%s', recordType='%s', source='%s', allowedOutputs=%v",
		domain, hostname, recordType, source, allowedOutputs)

	var errors []string
	removedCount := 0

	for _, profileName := range allowedOutputs {
		provider, exists := om.profiles[profileName]
		if !exists {
			errStr := fmt.Sprintf("output profile '%s' not found for domain '%s'", profileName, domain)
			log.Error(errStr)
			errors = append(errors, errStr)
			continue
		}

		err := provider.RemoveRecord(domain, hostname, recordType)
		if err != nil {
			errStr := fmt.Sprintf("failed to remove record from profile '%s': %v", profileName, err)
			log.Error(errStr)
			errors = append(errors, errStr)
		} else {
			log.Debug("Successfully removed record from profile '%s'", profileName)
			removedCount++
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove from %d output profiles: %s", len(errors), strings.Join(errors, "; "))
	}

	return nil
}
