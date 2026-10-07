// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output/common"

	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	loadedYAMLFiles = make(map[string]bool)
	loadedYAMLMutex sync.RWMutex
)

type YAMLFormat struct {
	*common.CommonFormat
}

func NewYAMLFormat(profileName string, config map[string]interface{}) (OutputFormat, error) {
	commonFormat, err := common.NewCommonFormat(profileName, "yaml", config)
	if err != nil {
		return nil, err
	}

	format := &YAMLFormat{
		CommonFormat: commonFormat,
	}

	if err := format.LoadExistingData(yaml.Unmarshal); err != nil {
		log.NewScopedLogger("", "").With("action", "state.load").Warn("%s existing export load failed: %v", format.GetLogPrefix(), err)
	}

	return format, nil
}

func (y *YAMLFormat) GetName() string {
	return "yaml"
}

func (y *YAMLFormat) Sync() error {
	err := y.CommonFormat.SyncWithSerializer(y.serializeYAML)
	if err != nil {
		log.NewScopedLogger("", "").With("action", "sync.fail").Error("[output/yaml] sync failed for domain=%s, profile=%s, file=%s: %v", y.GetDomain(), y.GetProfile(), y.GetFilePath(), err)
	}
	return err
}

func (y *YAMLFormat) serializeYAML(domain string, export *common.ExportData) ([]byte, error) {
	var buf strings.Builder
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

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

	err := encoder.Encode(export)
	encoder.Close()
	if err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

func (y *YAMLFormat) GetFilePath() string {
	path := "export_%domain_underscore%.yaml" // default fallback
	if y.CommonFormat != nil && y.CommonFormat.GetConfig() != nil {
		if p, ok := y.CommonFormat.GetConfig()["path"].(string); ok && p != "" {
			path = p
		}
	}
	return expandTags(path, y.CommonFormat.GetDomain(), y.CommonFormat.GetProfile())
}

func (y *YAMLFormat) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	log.NewScopedLogger("", "").With("action", "record.create").Debug("[output/yaml] domain=%s, hostname=%s, target=%s, type=%s, ttl=%d, source=%s", domain, hostname, target, recordType, ttl, source)
	defer func() {
		log.NewScopedLogger("", "").With("action", "record.create").Debug("[output/yaml] domain=%s, hostname=%s, type=%s", domain, hostname, recordType)
	}()

	filePath := y.GetFilePath()
	loadKey := filePath + "|" + domain

	loadedYAMLMutex.RLock()
	loaded := loadedYAMLFiles[loadKey]
	loadedYAMLMutex.RUnlock()

	if !loaded {
		if _, err := os.Stat(filePath); err == nil {
			log.NewScopedLogger("", "").With("action", "state.load").Debug("[output/yaml] loading existing records from YAML file: %s", filePath)
			if err := y.LoadExistingData(yaml.Unmarshal); err != nil {
				log.NewScopedLogger("", "").With("action", "state.load").Warn("[output/yaml] existing records load failed from %s: %v", filePath, err)
			} else {
				log.NewScopedLogger("", "").With("action", "state.load").Debug("[output/yaml] existing records loaded from %s", filePath)
			}
		}

		loadedYAMLMutex.Lock()
		loadedYAMLFiles[loadKey] = true
		loadedYAMLMutex.Unlock()
	}

	return y.CommonFormat.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
}

func (y *YAMLFormat) Records() int {
	export := y.GetExportData()
	if export.Domains == nil {
		return 0
	}
	n := 0
	for _, d := range export.Domains {
		n += len(d.Records)
	}
	return n
}
