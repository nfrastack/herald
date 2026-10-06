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
				log.NewScopedLogger("", "").With("domain", domain, "config", key, "input", inputProviderName).Debug("Found domain config for input provider")
				break
			} else {
				log.NewScopedLogger("", "").With("domain", domain, "config", key, "input", inputProviderName).Debug("Domain config does not allow input provider")
			}
		}
	}

	if !found {
		log.NewScopedLogger("", "").With("domain", domain, "input", inputProviderName).Debug("No domain config found for input provider on domain '%s'", fqdn)
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

	dlog.Debug("Initial state: RecordType='%s', Service='%s'", recordType, state.Service)

	if domainConfig.Record.Target != "" {
		target = domainConfig.Record.Target
		dlog.Debug("Using target from domain config: '%s'", target)
	} else if state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			target = state.Service
			dlog.Debug("Using Service as target (IP): '%s'", target)
		} else if strings.Contains(state.Service, ".") {
			target = state.Service
			dlog.Debug("Using Service as target (hostname): '%s'", target)
		}
	}

	if state.ForceServiceAsTarget && state.Service != "" {
		if ip := net.ParseIP(state.Service); ip != nil {
			if target != state.Service {
				dlog.Verbose("Input provider supplying IP '%s' for hostname '%s' (overriding domain target '%s')", state.Service, hostname, target)
			} else {
				dlog.Verbose("Input provider supplying IP '%s' for hostname '%s'", state.Service, hostname)
			}
			target = state.Service
		} else {
			dlog.Error("ForceServiceAsTarget=true but Service field '%s' is not a valid IP address (SourceType=%s)", state.Service, state.SourceType)
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
			dlog.Debug("Auto-detected record type: %s (target: %s)", recordType, target)
		} else if recordType == "" {
			recordType = domainConfig.Record.Type
		}

		if explicitType && recordType != expectedRecordType {
			if (expectedRecordType == "A" || expectedRecordType == "AAAA") && (recordType != "A" && recordType != "AAAA") {
				dlog.Warn("Record type mismatch: configured as '%s' but target '%s' requires '%s' - correcting to %s", recordType, target, expectedRecordType, expectedRecordType)
				recordType = expectedRecordType
			} else if expectedRecordType == "CNAME" && (recordType == "A" || recordType == "AAAA") {
				dlog.Warn("Record type mismatch: configured as '%s' but target '%s' requires '%s' - correcting to %s", recordType, target, expectedRecordType, expectedRecordType)
				recordType = expectedRecordType
			}
		}
	}

	ttl := 60
	if domainConfig.Record.TTL > 0 {
		ttl = domainConfig.Record.TTL
	}

	if target == "" {
		dlog.Error("No target specified for domain '%s' (fqdn: %s, service: %s)", domain, fqdn, state.Service)
		return fmt.Errorf("no target specified for domain %s (fqdn: %s, service: %s)", domain, fqdn, state.Service)
	}

	dlog.Debug("Output params: domain=%s, recordType=%s, hostname=%s, target=%s, ttl=%d", domain, recordType, hostname, target, ttl)

	if outputWriter == nil {
		dlog.Error("Output writer not provided")
		return fmt.Errorf("output writer not provided")
	}

	proxiedFlag := domainConfig.Record.Proxied
	outputErr := outputWriter.WriteRecordToOutputs(domainConfig.GetOutputs(), domain, hostname, target, recordType, ttl, state.SourceType, proxiedFlag, state.Overwrite)
	if outputErr != nil {
		dlog.Error("Failed to write to output system: %v", outputErr)
		return outputErr
	} else {
		dlog.Debug("Successfully wrote to output system")
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
				log.NewScopedLogger("", "").With("domain", domain, "config", key, "input", inputProviderName).Debug("Found domain config for input provider (removal)")
				break
			} else {
				log.NewScopedLogger("", "").With("domain", domain, "config", key, "input", inputProviderName).Debug("Domain config does not allow input provider (removal)")
			}
		}
	}

	if !found {
		log.NewScopedLogger("", "").With("domain", domain, "input", inputProviderName).Error("No domain config found for '%s'", fqdn)
		return fmt.Errorf("no domain config for %s", fqdn)
	}

	domainLogger := getDomainLogger(domain, make(map[string]string)).With("domain", domain, "config", domainConfigKey, "input", inputProviderName)

	if inputProviderName != "" {
		if !GlobalDomainManager.ValidateInputProviderAccess(domainConfigKey, inputProviderName) {
			domainLogger.Debug("Input provider not allowed for domain")
			return fmt.Errorf("input provider '%s' not allowed for domain '%s'", inputProviderName, domain)
		}
		domainLogger.Trace("Input provider allowed for domain")
	}

	domainLogger.With("fqdn", fqdn).Debug("Removing record through unified output system")

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

	domainLogger.Debug("Output removal params: domain=%s, recordType=%s, hostname=%s", domain, recordType, hostname)

	if outputWriter == nil {
		domainLogger.Error("Output writer not provided")
		return fmt.Errorf("output writer not provided")
	}

	outputErr := outputWriter.RemoveRecordFromOutputs(domainConfig.GetOutputs(), domain, hostname, recordType, state.SourceType)
	if outputErr != nil {
		domainLogger.Error("Failed to remove from output system: %v", outputErr)
		return outputErr
	}
	return nil
}

func (bp *BatchProcessor) FinalizeBatch() {
	if !bp.hasChanges {
		bp.logger.Debug("No changes in batch, skipping output sync")
		return
	}

	if bp.outputSyncer != nil {
		err := bp.outputSyncer.SyncAllFromSource(bp.inputProvider)
		if err != nil {
			bp.logger.Error("Failed to sync output files: %v", err)
		}
	} else {
		bp.logger.Error("Output syncer not provided, cannot sync batch")
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

			domainLogger.Debug("Checking domain config '%s' for domain '%s' - allowed inputs: %v", domainKey, domain, inputProfiles)

			for _, allowedProvider := range inputProfiles {
				if allowedProvider == inputProviderName {
					domainLogger.Debug("Input provider '%s' allowed for domain '%s' via config '%s'", inputProviderName, domain, domainKey)
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
		bp.logger.With("domain", domain).Debug("Input provider not allowed for domain")
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
		bp.logger.With("domain", domain).Debug("Input provider not allowed for domain (removal)")
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
	d.logger.Info("%s Syncing %d records", logPrefix, len(records))

	d.logger.Info("%s Successfully synced records", logPrefix)
	return nil
}

func (d *Domain) Validate() error {
	logPrefix := GetDomainLogPrefix(d.ConfigKey, d.Name)
	if d.Name == "" {
		d.logger.Error("%s Domain name is empty", logPrefix)
		return errors.New("domain name is empty")
	}

	if d.ConfigKey == "" {
		d.logger.Warn("%s Domain config key is empty", logPrefix)
	}
	return nil
}

func GetDomainLogPrefix(domainConfigKey, domain string) string {
	if domainConfigKey != "" {
		return fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
	}
	return fmt.Sprintf("[domain/%s]", strings.ReplaceAll(domain, ".", "_"))
}
