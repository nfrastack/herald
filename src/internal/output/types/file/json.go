// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output/common"

	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	loadedJSONFiles = make(map[string]bool)
	loadedJSONMutex sync.RWMutex
)

type JSONFormat struct {
	*common.CommonFormat
	logger *log.ScopedLogger
}

func NewJSONFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
	commonFormat, err := common.NewCommonFormat(profileName, "json", config)
	if err != nil {
		return nil, err
	}

	scopedLogger := common.AddScopedLogging(nil, "json", profileName, config)

	format := &JSONFormat{
		CommonFormat: commonFormat,
		logger:       scopedLogger,
	}

	if err := format.LoadExistingData(json.Unmarshal); err != nil {
		format.logger.With("action", "state.load").Warn("existing JSON export load failed for domain %s: %v", profileName, err)
	}

	return format, nil
}

func (j *JSONFormat) GetName() string {
	return "json"
}

func (j *JSONFormat) Sync() error {
	err := j.CommonFormat.SyncWithSerializer(j.serializeJSON)
	if err != nil {
		j.logger.With("action", "sync.fail").Error("sync failed for domain=%s, profile=%s, file=%s: %v", j.GetDomain(), j.GetProfile(), j.GetFilePath(), err)
	}
	return err
}

func (j *JSONFormat) serializeJSON(domain string, export *common.ExportData) ([]byte, error) {
	export.Metadata.LastUpdated = time.Now().UTC()
	for _, d := range export.Domains {
		for _, r := range d.Records {
			if !r.CreatedAt.IsZero() {
				r.Comment = fmt.Sprintf("created_at: %s input: %s", r.CreatedAt.Format(time.RFC3339), r.Source)
			} else {
				r.Comment = fmt.Sprintf("input: %s", r.Source)
			}
		}
	}
	return json.MarshalIndent(export, "", "  ")
}

func (j *JSONFormat) GetFilePath() string {
	path := "export_%domain_underscore%.json" // default fallback
	if j.CommonFormat != nil && j.CommonFormat.GetConfig() != nil {
		if p, ok := j.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTags(path, j.CommonFormat.GetDomain(), j.CommonFormat.GetProfile())
}

func (j *JSONFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	j.logger.With("action", "record.create").Debug("domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", domain, hostname, target, recordType, ttl, source)
	defer func() {
		j.logger.With("action", "record.create").Debug("domain=%s, hostname=%s, type=%s", domain, hostname, recordType)
	}()

	filePath := j.GetFilePath()
	loadKey := filePath + "|" + domain

	loadedJSONMutex.RLock()
	loaded := loadedJSONFiles[loadKey]
	loadedJSONMutex.RUnlock()

	if !loaded {
		if _, err := os.Stat(filePath); err == nil {
			j.logger.With("action", "state.load").Debug("loading existing records from JSON file: %s", filePath)
			if err := j.LoadExistingData(json.Unmarshal); err != nil {
				j.logger.With("action", "state.load").Warn("existing records load failed from %s: %v", filePath, err)
			} else {
				j.logger.With("action", "state.load").Debug("existing records loaded from %s", filePath)
			}
		}

		loadedJSONMutex.Lock()
		loadedJSONFiles[loadKey] = true
		loadedJSONMutex.Unlock()
	}

	return j.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
}

func (j *JSONFormat) Records() int {
	export := j.GetExportData()
	if export.Domains == nil {
		return 0
	}
	n := 0
	for _, d := range export.Domains {
		n += len(d.Records)
	}
	return n
}
