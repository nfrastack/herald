// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"errors"
	"fmt"
	"github.com/nfrastack/herald/internal/common"
	"github.com/nfrastack/herald/internal/log"
	"net"
	"strings"
)

type RouterState struct {
	Name                 string
	Rule                 string
	EntryPoints          []string
	Service              string
	SourceType           string // e.g. "container", "router", "file", "remote", etc.
	RecordType           string // DNS record type (A, AAAA, CNAME) - from input provider
	ForceServiceAsTarget bool   // When true, always use Service field as target (for VPN providers)
	Overwrite            bool   // When true, allow overwriting conflicting records
}

func getDomainLogger(domain string, domainConfig map[string]string) *log.ScopedLogger {
	logLevel := ""
	if val, ok := domainConfig["log_level"]; ok {
		logLevel = val
	}

	logPrefix := fmt.Sprintf("[domain/%s]", domain)
	return log.NewScopedLogger(logPrefix, logLevel)
}

func EnsureDNSForRouterState(domain, fqdn string, state RouterState) error {
	return EnsureDNSForRouterStateWithProvider(domain, fqdn, state, "", nil)
}

func EnsureDNSForRouterStateWithProvider(domain, fqdn string, state RouterState, inputProviderName string, outputWriter OutputWriter) error {
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	var domainConfig *DomainConfig
	var domainConfigKey string
	found := false

	for key, config := range GlobalDomainManager.GetAllDomains() {
		if config.Name == domain {
			if inputProviderName == "" {
				continue
			}

			if GlobalDomainManager.ValidateInputProviderAccess(key, inputProviderName) {
				domainConfig = config
				domainConfigKey = key
				found = true
				log.NewScopedLogger("", "").With("action", "domain.match", "domain", domain, "config", key, "input", inputProviderName).Debug("domain config for input provider")
				break
			} else {
				log.NewScopedLogger("", "").With("action", "domain.skip", "domain", domain, "config", key, "input", inputProviderName).Debug("config does not allow input provider")
			}
		}
	}

	if !found {
		log.NewScopedLogger("", "").With("action", "domain.skip", "domain", domain, "input", inputProviderName).Debug("no domain config for input provider on domain '%s'", fqdn)
		return nil // Not an error - just filtered out
	}

	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}

	recordType := state.RecordType
	target := ""
	dlog := log.NewScopedLogger("", "").With("domain", domain, "config", domainConfigKey, "input", inputProviderName)

	dlog.With("action", "state.load").Debug("state: RecordType='%s', Service='%s'", recordType, state.Service)

	if domainConfig.Record.Target != "" {
		target = domainConfig.Record.Target
		dlog.With("action", "record.sync").Debug("target from domain config: '%s'", target)
	} else if state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			target = state.Service
			dlog.With("action", "record.sync").Debug("Service as target (IP): '%s'", target)
		} else if strings.Contains(state.Service, ".") {
			target = state.Service
			dlog.With("action", "record.sync").Debug("Service as target (hostname): '%s'", target)
		}
	}

	if state.ForceServiceAsTarget && state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			if target != state.Service {
				dlog.With("action", "record.update").Verbose("supplying IP '%s' for hostname '%s' (overriding domain target '%s')", state.Service, hostname, target)
			} else {
				dlog.With("action", "record.update").Verbose("supplying IP '%s' for hostname '%s'", state.Service, hostname)
			}
			target = state.Service
		} else {
			dlog.With("action", "record.reject").Error("Service field '%s' is not a valid IP address (SourceType=%s)", state.Service, state.SourceType)
			return fmt.Errorf("invalid IP address in Service field for VPN provider: %s", state.Service)
		}
	}

	if target != "" {
		expectedRecordType := ""
		if ip := net.ParseIP(target); ip != nil {
			if ip.To4() != nil {
				expectedRecordType = "A"
			} else {
				expectedRecordType = "AAAA"
			}
		} else if strings.Contains(target, ".") {
			expectedRecordType = "CNAME"
		} else {
			expectedRecordType = "CNAME"
		}

		explicitType := domainConfig.Record.Type != ""

		if !explicitType {
			recordType = expectedRecordType
			dlog.With("action", "record.sync").Debug("record type: %s (target: %s)", recordType, target)
		} else if recordType == "" {
			recordType = domainConfig.Record.Type
		}

		if explicitType && recordType != expectedRecordType {
			if (expectedRecordType == "A" || expectedRecordType == "AAAA") && (recordType != "A" && recordType != "AAAA") {
				dlog.With("action", "record.update").Warn("type mismatch: configured as '%s' but target '%s' requires '%s' - correcting to %s", recordType, target, expectedRecordType, expectedRecordType)
				recordType = expectedRecordType
			} else if expectedRecordType == "CNAME" && (recordType == "A" || recordType == "AAAA") {
				dlog.With("action", "record.update").Warn("type mismatch: configured as '%s' but target '%s' requires '%s' - correcting to %s", recordType, target, expectedRecordType, expectedRecordType)
				recordType = expectedRecordType
			}
		}
	}

	ttl := 60
	if domainConfig.Record.TTL > 0 {
		ttl = domainConfig.Record.TTL
	}

	if target == "" {
		dlog.With("action", "record.reject").Error("no target for domain '%s' (fqdn: %s, service: %s)", domain, fqdn, state.Service)
		return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
	}

	dlog.With("action", "output.write").Debug("params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", domain, recordType, hostname, target, ttl)

	if outputWriter == nil {
		dlog.With("action", "output.write").Error("writer not provided")
		return fmt.Errorf("output writer not provided")
	}

	proxiedFlag := domainConfig.Record.Proxied
	outputErr := outputWriter.WriteRecordToOutputs(domainConfig.GetOutputs(), domain, hostname, target, recordType, ttl, state.SourceType, proxiedFlag, state.Overwrite)
	if outputErr != nil {
		dlog.With("action", "output.write").Error("to output system: %v", outputErr)
		return outputErr
	} else {
		dlog.With("action", "output.write").Debug("to output system")
	}
	return nil
}

func EnsureDNSRemoveForRouterState(domain, fqdn string, state RouterState, outputWriter OutputWriter) error {
	return EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn, state, "", outputWriter)
}

func EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn string, state RouterState, inputProviderName string, outputWriter OutputWriter) error {
	if GlobalDomainManager == nil {
		return fmt.Errorf("domain manager not initialized")
	}

	var domainConfig *DomainConfig
	var domainConfigKey string
	found := false

	for key, config := range GlobalDomainManager.GetAllDomains() {
		if config.Name == domain {
			if inputProviderName == "" {
				continue
			}

			if GlobalDomainManager.ValidateInputProviderAccess(key, inputProviderName) {
				domainConfig = config
				domainConfigKey = key
				found = true
				log.NewScopedLogger("", "").With("action", "record.delete", "domain", domain, "config", key, "input", inputProviderName).Debug("domain config for input provider (removal)")
				break
			} else {
				log.NewScopedLogger("", "").With("action", "record.skip", "domain", domain, "config", key, "input", inputProviderName).Debug("config does not allow input provider (removal)")
			}
		}
	}

	if !found {
		log.NewScopedLogger("", "").With("action", "record.skip", "domain", domain, "input", inputProviderName).Error("no domain config for '%s'", fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}

	domainLogger := getDomainLogger(domain, make(map[string]string)).With("domain", domain, "config", domainConfigKey, "input", inputProviderName)

	if inputProviderName != "" {
		if !GlobalDomainManager.ValidateInputProviderAccess(domainConfigKey, inputProviderName) {
			domainLogger.With("action", "domain.skip").Debug("not allowed for domain")
			return fmt.Errorf("input provider '%s' not allowed for domain '%s'", inputProviderName, domain)
		}
		domainLogger.With("action", "domain.match").Trace("allowed for domain")
	}

	domainLogger.With("action", "record.delete", "fqdn", fqdn).Debug("record through unified output system")

	hostname := fqdn
	if fqdn == domain {
		hostname = "@"
	} else if strings.HasSuffix(fqdn, "."+domain) {
		hostname = strings.TrimSuffix(fqdn, "."+domain)
	}

	recordType := state.RecordType
	if recordType == "" {
		target := ""
		if state.Service != "" {
			target = state.Service
		}
		if target != "" {
			if ip := net.ParseIP(target); ip != nil {
				if ip.To4() != nil {
					recordType = "A"
				} else {
					recordType = "AAAA"
				}
			} else {
				recordType = "CNAME"
			}
		} else {
			recordType = "A" // Default fallback
		}
	}

	domainLogger.With("action", "output.remove").Debug("removal params: domain=%s, recordType=%s, hostname=%s", domain, recordType, hostname)

	if outputWriter == nil {
		domainLogger.With("action", "output.remove").Error("writer not provided")
		return fmt.Errorf("output writer not provided")
	}

	outputErr := outputWriter.RemoveRecordFromOutputs(domainConfig.GetOutputs(), domain, hostname, recordType, state.SourceType)
	if outputErr != nil {
		domainLogger.With("action", "output.remove").Error("from output system: %v", outputErr)
		return outputErr
	}
	return nil
}

func (bp *BatchProcessor) FinalizeBatch() {
	if !bp.hasChanges {
		bp.logger.With("action", "sync.skip").Debug("no changes in batch, skipping output sync")
		return
	}

	if bp.outputSyncer != nil {
		err := bp.outputSyncer.SyncAllFromSource(bp.inputProvider)
		if err != nil {
			bp.logger.With("action", "sync.fail").Error("output files: %v", err)
		}
	} else {
		bp.logger.With("action", "sync.fail").Error("syncer not provided, cannot sync batch")
	}

	bp.hasChanges = false
}

type BatchProcessor struct {
	hasChanges    bool
	logPrefix     string
	inputProvider string // Track which input provider is using this batch
	logger        *log.ScopedLogger
	outputWriter  OutputWriter // Dependency for writing/removing records
	outputSyncer  OutputSyncer // Dependency for triggering syncs
}

func NewBatchProcessor(logPrefix string, writer OutputWriter, syncer OutputSyncer) *BatchProcessor {
	provider := extractInputProviderFromLogPrefix(logPrefix)
	return newBatchProcessorInternal(logPrefix, provider, writer, syncer)
}

func NewBatchProcessorWithProvider(logPrefix string, inputProviderName string, writer OutputWriter, syncer OutputSyncer) *BatchProcessor {
	return newBatchProcessorInternal(logPrefix, inputProviderName, writer, syncer)
}

func newBatchProcessorInternal(logPrefix string, inputProviderName string, writer OutputWriter, syncer OutputSyncer) *BatchProcessor {
	return &BatchProcessor{
		hasChanges:    false,
		logPrefix:     logPrefix,
		inputProvider: inputProviderName,
		logger:        log.NewScopedLogger(logPrefix, ""),
		outputWriter:  writer,
		outputSyncer:  syncer,
	}
}

func (bp *BatchProcessor) isInputProviderAllowed(domain, inputProviderName string) bool {
	for domainKey, domainConfig := range GlobalDomainManager.GetAllDomains() {
		if domainConfig.Name == domain {
			inputProfiles := domainConfig.GetInputProfiles()

			domainLogPrefix := GetDomainLogPrefix(domainKey, domain)
			domainLogger := log.NewScopedLogger(domainLogPrefix, "")

			domainLogger.With("action", "domain.match").Debug("domain config '%s' for domain '%s' - allowed inputs: %v", domainKey, domain, inputProfiles)

			for _, allowedProvider := range inputProfiles {
				if allowedProvider == inputProviderName {
					domainLogger.With("action", "domain.match").Debug("'%s' allowed for domain '%s' via config '%s'", inputProviderName, domain, domainKey)
					return true
				}
			}
		}
	}

	return false
}

func extractInputProviderFromLogPrefix(logPrefix string) string {
	if strings.HasPrefix(logPrefix, "[input/") && strings.HasSuffix(logPrefix, "]") {
		parts := strings.Split(logPrefix[7:len(logPrefix)-1], "/")
		if len(parts) >= 2 {
			return parts[1] // Return the profile name
		}
	}
	return ""
}

func (bp *BatchProcessor) ProcessRecord(domain, fqdn string, state RouterState) error {
	if !bp.isInputProviderAllowed(domain, bp.inputProvider) {
		bp.logger.With("action", "domain.skip", "domain", domain).Debug("not allowed for domain")
		return nil // Not an error, just filtered out
	}

	err := EnsureDNSForRouterStateWithProvider(domain, fqdn, state, bp.inputProvider, bp.outputWriter)
	if err == nil {
		bp.hasChanges = true
	}
	return err
}

func (bp *BatchProcessor) ProcessRecordRemoval(domain, fqdn string, state RouterState) error {
	if !bp.isInputProviderAllowed(domain, bp.inputProvider) {
		bp.logger.With("action", "record.skip", "domain", domain).Debug("not allowed for domain (removal)")
		return nil // Not an error, just filtered out
	}

	err := EnsureDNSRemoveForRouterStateWithProvider(domain, fqdn, state, bp.inputProvider, bp.outputWriter)
	if err == nil {
		bp.hasChanges = true
	}
	return err
}

func (bp *BatchProcessor) HasChanges() bool {
	return bp.hasChanges
}

type Domain struct {
	Name      string
	ConfigKey string // Unique key for this domain's config
	logger    *log.ScopedLogger
}

func (d *Domain) SyncRecords(records []common.Record) error {
	logPrefix := GetDomainLogPrefix(d.ConfigKey, d.Name)
	d.logger.With("action", "record.sync").Info("%s %d records", logPrefix, len(records))

	d.logger.With("action", "record.sync").Info("%s synced records", logPrefix)
	return nil
}

func (d *Domain) Validate() error {
	logPrefix := GetDomainLogPrefix(d.ConfigKey, d.Name)
	if d.Name == "" {
		d.logger.With("action", "config.error").Error("%s name is empty", logPrefix)
		return errors.New("domain name is empty")
	}

	if d.ConfigKey == "" {
		d.logger.With("action", "config.error").Warn("%s config key is empty", logPrefix)
	}
	return nil
}

func GetDomainLogPrefix(domainConfigKey, domain string) string {
	if domainConfigKey != "" {
		return fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
	}
	return fmt.Sprintf("[domain/%s]", strings.ReplaceAll(domain, ".", "_"))
}
