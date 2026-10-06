// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/util"

	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var SecretRegex = regexp.MustCompile(`\${([^}]+)}`)

type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	return "[" + strings.Join(*s, ", ") + "]"
}

func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func LoadConfigFile(path string) (*ConfigFile, error) {
	log.Debug("[config/file] Loading configuration from %s", path)

	var cfg ConfigFile

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to read config file: %w", err)
	}

	processed, err := preprocessIncludes(data, path, map[string]bool{})
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to process includes: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(processed))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("[config/file] failed to decode YAML: %w", err)
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		cfg.General.LogLevel = logLevel
	}

	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "verbose"
	}
	if os.Getenv("LOG_TIMESTAMPS") == "" && !FieldSetInConfigFile(path, "log_timestamps") {
		cfg.General.LogTimestamps = true
	}
	if cfg.General.LogType == "" {
		cfg.General.LogType = "console"
	}

	return &cfg, nil
}

func deepMergeSectionMap(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = map[string]interface{}{}
	}
	for k, v := range src {
		if vMap, ok := v.(map[string]interface{}); ok {
			if dstMap, ok := dst[k].(map[string]interface{}); ok {
				dst[k] = deepMergeSectionMap(dstMap, vMap)
			} else {
				dst[k] = deepMergeSectionMap(nil, vMap)
			}
		} else {
			dst[k] = v
		}
	}
	return dst
}

func preprocessIncludes(data []byte, basePath string, seen map[string]bool) ([]byte, error) {
	log.Trace("[config/file] Parsing config file: %s", basePath)
	absPath, _ := os.Getwd()
	if !strings.HasPrefix(basePath, "/") && absPath != "" {
		basePath = absPath + "/" + basePath
	}
	if seen[basePath] {
		return nil, fmt.Errorf("[config/file] circular include detected for %s", basePath)
	}
	seen[basePath] = true

	var raw map[string]interface{}
	err := yaml.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}
	log.Trace("[config/file] Raw YAML map in %s: %#v", basePath, util.MaskSensitiveMapRecursive(raw))

	topKeys := make([]string, 0, len(raw))
	for k := range raw {
		topKeys = append(topKeys, k)
	}
	log.Trace("[config/file] Top-level keys in %s: %v", basePath, topKeys)

	if inc, ok := raw["include"]; ok {
		var includeFiles []string
		switch v := inc.(type) {
		case string:
			includeFiles = []string{v}
		case []interface{}:
			for _, f := range v {
				if s, ok := f.(string); ok {
					includeFiles = append(includeFiles, s)
				}
			}
		}
		for _, incFile := range includeFiles {
			incPath := incFile
			if !strings.HasPrefix(incFile, "/") && basePath != "" {
				incPath = getIncludePath(basePath, incFile)
			}
			log.Debug("[config/file] Including file: %s", incPath)
			incData, err := os.ReadFile(incPath)
			if err != nil {
				log.Error("[config/file] Failed to read included file %s: %v", incPath, err)
				return nil, fmt.Errorf("failed to read included file %s: %w", incPath, err)
			}
			incProcessed, err := preprocessIncludes(incData, incPath, seen)
			if err != nil {
				log.Error("[config/file] Failed to process includes in %s: %v", incPath, err)
				return nil, err
			}
			var incRaw map[string]interface{}
			yaml.Unmarshal(incProcessed, &incRaw)
			topKeys := make([]string, 0, len(incRaw))
			for k := range incRaw {
				topKeys = append(topKeys, k)
			}
			log.Trace("[config/file] Imported keys from %s: %v", incPath, topKeys)
			for _, k := range topKeys {
				log.Trace("[config/file] Key '%s' from %s: %v", k, incPath, util.MaskSensitiveMapRecursive(map[string]interface{}{k: incRaw[k]})[k])
			}
			for _, section := range []string{"inputs", "domains", "defaults", "general", "outputs", "api"} {
				if v, ok := incRaw[section]; ok {
					if dstMap, ok := raw[section].(map[string]interface{}); ok {
						if srcMap, ok := v.(map[string]interface{}); ok {
							raw[section] = deepMergeSectionMap(dstMap, srcMap)
						}
					} else {
						raw[section] = v
					}
				}
			}
			for k, v := range incRaw {
				if k == "include" || k == "inputs" || k == "domains" || k == "defaults" || k == "general" || k == "outputs" || k == "api" {
					continue
				}
				raw[k] = v
			}
		}
		delete(raw, "include")
	}

	return yaml.Marshal(raw)
}

func getIncludePath(basePath, incFile string) string {
	dir := basePath
	if idx := strings.LastIndex(basePath, "/"); idx != -1 {
		dir = basePath[:idx]
	}
	return dir + "/" + incFile
}

func FindConfigFile(requested string) (string, error) {
	candidates := []string{}
	if requested != "" {
		candidates = append(candidates, requested)
	}
	candidates = append(candidates,
		"herald.yml",
		"herald.yaml",
		"herald.conf",
	)
	for _, name := range candidates {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
		etcPath := "/etc/" + name
		if _, err := os.Stat(etcPath); err == nil {
			return etcPath, nil
		}
		if !strings.HasPrefix(name, "/") {
			rootPath := "/" + name
			if _, err := os.Stat(rootPath); err == nil {
				return rootPath, nil
			}
		}
	}
	return "", fmt.Errorf("no configuration file found (tried: %v)", candidates)
}

func FieldSetInConfigFile(configFilePath, field string) bool {
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return false
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}
	general, ok := raw["general"].(map[string]interface{})
	if !ok {
		return false
	}
	_, exists := general[field]
	return exists
}

func processConfigFileSecrets(content string) string {
	processedContent := SecretRegex.ReplaceAllStringFunc(content, func(match string) string {
		varName := match[2 : len(match)-1]

		if strings.HasPrefix(varName, "file:") {
			filePath := strings.TrimPrefix(varName, "file:")

			fileData, err := os.ReadFile(filePath)
			if err != nil {
				log.Error("[config/file] Failed to read secret file %s: %v", filePath, err)
				return match // Keep original if error
			}

			return strings.TrimSpace(string(fileData))
		}

		if strings.HasPrefix(varName, "env:") {
			envVar := strings.TrimPrefix(varName, "env:")

			if value, exists := os.LookupEnv(envVar); exists {
				return value
			}

			return match
		}

		if value, exists := os.LookupEnv(varName); exists {
			return value
		}

		return match
	})

	return processedContent
}

func ProcessSecrets(value string) string {
	return processConfigFileSecrets(value)
}

func ProcessSecretsInMap(options map[string]string) map[string]string {
	processed := make(map[string]string, len(options))
	for k, v := range options {
		processed[k] = ProcessSecrets(v)
	}
	return processed
}

func MergeConfigFile(dst, src *ConfigFile) *ConfigFile {
	if dst == nil {
		dst = &ConfigFile{}
	}
	if src == nil {
		return dst
	}
	if src.General.LogLevel != "" {
		dst.General.LogLevel = src.General.LogLevel
	}
	if src.General.LogType != "" {
		dst.General.LogType = src.General.LogType
	}
	if src.General.LogTimestamps {
		dst.General.LogTimestamps = src.General.LogTimestamps
	}
	if len(src.General.InputProfiles) > 0 {
		dst.General.InputProfiles = src.General.InputProfiles
	}
	if src.General.DryRun {
		dst.General.DryRun = src.General.DryRun
	}
	if (src.Defaults != DefaultsConfig{}) {
		dst.Defaults = src.Defaults
	}
	if src.StateDir != "" {
		dst.StateDir = src.StateDir
	}
	if src.StaleAfter != "" {
		dst.StaleAfter = src.StaleAfter
	}
	if dst.Inputs == nil {
		dst.Inputs = map[string]InputProviderConfig{}
	}
	for k, v := range src.Inputs {
		dst.Inputs[k] = v
	}
	if dst.Domains == nil {
		dst.Domains = map[string]DomainConfig{}
	}
	for k, v := range src.Domains {
		dst.Domains[k] = v
	}
	return dst
}
