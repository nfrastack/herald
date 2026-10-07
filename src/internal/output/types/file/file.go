// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output/types/common"

	"fmt"
	"strings"
	"time"
)

func expandTags(s, domain, profile string) string {
	domainUnderscore := strings.ReplaceAll(domain, ".", "_")
	now := time.Now().Format("20060102-150405") // yyyymmdd-hhmmss
	replacer := strings.NewReplacer(
		"%domain%", domain,
		"%domain_underscore%", domainUnderscore,
		"%date%", now,
		"%profile%", profile,
	)
	return replacer.Replace(s)
}

func expandTagsWithUnderscore(s, domain, profile string) string {
	domainUnderscore := strings.ReplaceAll(domain, ".", "_")
	now := time.Now().Format("20060102-150405") // yyyymmdd-hhmmss
	replacer := strings.NewReplacer(
		"%domain%", domainUnderscore,
		"%domain_underscore%", domainUnderscore,
		"%date%", now,
		"%profile%", profile,
	)
	return replacer.Replace(s)
}

type OutputFormat = common.OutputFormat

type FileOutput struct {
	format     string
	underlying OutputFormat
}

func NewFileOutput(profileName string, config map[string]interface{}) (OutputFormat, error) {
	format, ok := config["format"].(string)
	if !ok || format == "" {
		log.NewScopedLogger("", "").With("action", "config.error").Error("[output/file] Missing or invalid 'format' field in config: %+v", config)
		return nil, fmt.Errorf("file output requires 'format' field")
	}

	log.NewScopedLogger("", "").With("action", "provider.init").Debug("[output/file] file output '%s' (format: %s) with config: %+v", profileName, format, config)

	switch format {
	case "json":
		return NewJSONFormat(profileName, config)
	case "yaml":
		return NewYAMLFormat(profileName, config)
	case "zone":
		if domain, ok := config["domain"].(string); ok && domain != "" {
			return NewZoneFormat(profileName, domain, config)
		} else {
			return nil, fmt.Errorf("zone output requires 'domain' field in config")
		}
	case "hosts":
		if domain, ok := config["domain"].(string); ok && domain != "" {
			return NewHostsFormat(domain, profileName, config)
		} else {
			return nil, fmt.Errorf("hosts output requires 'domain' field in config")
		}
	default:
		return nil, fmt.Errorf("unsupported file format '%s', must be one of: json, yaml, zone, hosts", format)
	}
}

func NewProvider(name string, config map[string]interface{}) (OutputFormat, error) {
	log.NewScopedLogger("", "").With("action", "provider.init").Debug("[output/file] name='%s', config: %+v", name, config)
	return NewFileOutput(name, config)
}

func init() {
	log.NewScopedLogger("", "").With("action", "provider.init").Debug("[output/file] output types loaded")
}
