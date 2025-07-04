// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"herald/pkg/log"
	"herald/pkg/util"

	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecretRegex matches environment variable references like ${ENV_VAR}
var SecretRegex = regexp.MustCompile(`\${([^}]+)}`)

// StringSliceFlag is a flag.Value that collects multiple string values
type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	return "[" + strings.Join(*s, ", ") + "]"
}

func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// LoadConfigFile loads the configuration from a YAML file (any extension)
func LoadConfigFile(path string) (*ConfigFile, error) {
	log.Debug("[config/file] Loading configuration from %s", path)

	var cfg ConfigFile

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to read config file: %w", err)
	}

	// Preprocess for includes
	processed, err := preprocessIncludes(data, path, map[string]bool{})
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to process includes: %w", err)
	}

	err = yaml.Unmarshal(processed, &cfg)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to decode YAML: %w", err)
	}

	// Basic environment loading - only core global settings
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		cfg.General.LogLevel = logLevel
	}

	// Set application-level defaults ONLY if still unset after config and env
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

// deepMergeSectionMap merges only matching top-level keys as maps, others are overwritten
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

// preprocessIncludes recursively processes 'include' keys in YAML files
func preprocessIncludes(data []byte, basePath string, seen map[string]bool) ([]byte, error) {
	log.Trace("[config/file] Parsing config file: %s", basePath)
	// Prevent circular includes
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

	// Check for 'include' key (can be string or list)
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
			// Resolve relative to basePath
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
			// Only merge known top-level sections as maps
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
			// For any other keys, just set/overwrite
			for k, v := range incRaw {
				if k == "include" || k == "inputs" || k == "domains" || k == "defaults" || k == "general" || k == "outputs" || k == "api" {
					continue
				}
				raw[k] = v
			}
		}
		delete(raw, "include")
	}

	// Marshal back to YAML
	return yaml.Marshal(raw)
}

// getIncludePath resolves incFile relative to basePath
func getIncludePath(basePath, incFile string) string {
	dir := basePath
	if idx := strings.LastIndex(basePath, "/"); idx != -1 {
		dir = basePath[:idx]
	}
	return dir + "/" + incFile
}

// FindConfigFile searches for the config file in the current directory and common locations
func FindConfigFile(requested string) (string, error) {
	candidates := []string{}
	if requested != "" {
		candidates = append(candidates, requested)
	}
	// Always prefer herald.yml, then .yaml, then .conf
	candidates = append(candidates,
		"herald.yml",
		"herald.yaml",
		"herald.conf",
	)
	for _, name := range candidates {
		// Check current directory
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
		// Check /etc directory
		etcPath := "/etc/" + name
		if _, err := os.Stat(etcPath); err == nil {
			return etcPath, nil
		}
		// Check root directory if not absolute path
		if !strings.HasPrefix(name, "/") {
			rootPath := "/" + name
			if _, err := os.Stat(rootPath); err == nil {
				return rootPath, nil
			}
		}
	}
	return "", fmt.Errorf("no configuration file found (tried: %v)", candidates)
}

// FieldSetInConfigFile checks if a field is explicitly set in the config file (top-level only)
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

// processConfigFileSecrets replaces environment variable references in the config file
func processConfigFileSecrets(content string) string {
	// Replace ${ENV_VAR} with the environment variable value
	processedContent := SecretRegex.ReplaceAllStringFunc(content, func(match string) string {
		// Extract variable name (remove ${ and })
		varName := match[2 : len(match)-1]

		// Check if it's prefixed with "file:"
		if strings.HasPrefix(varName, "file:") {
			// Extract file path
			filePath := strings.TrimPrefix(varName, "file:")

			// Read file content
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				log.Error("[config/file] Failed to read secret file %s: %v", filePath, err)
				return match // Keep original if error
			}

			// Trim whitespace and return content
			return strings.TrimSpace(string(fileData))
		}

		// Check if it's prefixed with "env:"
		if strings.HasPrefix(varName, "env:") {
			// Extract environment variable name
			envVar := strings.TrimPrefix(varName, "env:")

			// Look up environment variable
			if value, exists := os.LookupEnv(envVar); exists {
				return value
			}

			// If environment variable doesn't exist, keep original
			return match
		}

		// Look up environment variable
		if value, exists := os.LookupEnv(varName); exists {
			return value
		}

		// If environment variable doesn't exist, keep original
		return match
	})

	return processedContent
}

// ProcessSecrets is a centralized function for processing secrets in any configuration value
func ProcessSecrets(value string) string {
	return processConfigFileSecrets(value)
}

// ProcessSecretsInMap processes secrets in all string values within a map
func ProcessSecretsInMap(options map[string]string) map[string]string {
	processed := make(map[string]string, len(options))
	for k, v := range options {
		processed[k] = ProcessSecrets(v)
	}
	return processed
}

// MergeConfigFile merges src into dst, with src overriding dst where set
func MergeConfigFile(dst, src *ConfigFile) *ConfigFile {
	if dst == nil {
		dst = &ConfigFile{}
	}
	if src == nil {
		return dst
	}
	// Merge General section
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
	// Merge Defaults
	if (src.Defaults != DefaultsConfig{}) {
		dst.Defaults = src.Defaults
	}
	// Merge Input Providers (src overrides dst)
	if dst.Inputs == nil {
		dst.Inputs = map[string]InputProviderConfig{}
	}
	for k, v := range src.Inputs {
		dst.Inputs[k] = v
	}
	// Merge Domains (src overrides dst)
	if dst.Domains == nil {
		dst.Domains = map[string]DomainConfig{}
	}
	for k, v := range src.Domains {
		dst.Domains[k] = v
	}
	return dst
}
