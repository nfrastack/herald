// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"container-dns-companion/pkg/log"

	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecretRegex matches environment variable references like ${ENV_VAR}
var SecretRegex = regexp.MustCompile(`\${([^}]+)}`)

// LoadConfigFile loads the configuration from a YAML file (any extension)
func LoadConfigFile(path string) (*ConfigFile, error) {
	log.Debug("[config/file] Loading configuration from %s", path)

	var cfg ConfigFile

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to read config file: %w", err)
	}

	// Process secrets in config file (env vars and file: expansion)
	processedSecrets := processConfigFileSecrets(string(data))

	// Preprocess for includes
	processed, err := preprocessIncludes([]byte(processedSecrets), path, map[string]bool{})
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to process includes: %w", err)
	}

	err = yaml.Unmarshal(processed, &cfg)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to decode YAML: %w", err)
	}

	// Load environment variable configuration (overrides config file)
	LoadFromEnvironment(&cfg)

	// Set application-level defaults ONLY if still unset after config and env
	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "info"
	}
	cfg.General.LogTimestamps = true // Remove FieldSetInConfigFile check for simplicity
	if cfg.General.LogType == "" {
		cfg.General.LogType = "console"
	}

	// If poll_profiles is not set, but only one poll is defined, set it automatically
	if len(cfg.General.PollProfiles) == 0 && len(cfg.Polls) == 1 {
		for k := range cfg.Polls {
			cfg.General.PollProfiles = []string{k}
		}
	}

	return &cfg, nil
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
	log.Trace("[config/file] Raw YAML map in %s: %#v", basePath, maskSensitiveMap(raw))

	topKeys := make([]string, 0, len(raw))
	for k := range raw {
		topKeys = append(topKeys, k)
	}
	log.Trace("[config/file] Top-level keys in %s: %v", basePath, topKeys)

	// Process includes
	raw = processIncludes(raw, filepath.Dir(basePath))

	// Marshal back to YAML
	return yaml.Marshal(raw)
}

// processIncludes processes 'include' keys in the configuration, logging warnings for inaccessible files
func processIncludes(baseConfig map[string]interface{}, baseDir string) map[string]interface{} {
	includes, ok := baseConfig["include"]
	if !ok {
		return baseConfig
	}
	files := []string{}
	switch v := includes.(type) {
	case string:
		files = append(files, v)
	case []interface{}:
		for _, f := range v {
			if s, ok := f.(string); ok {
				files = append(files, s)
			}
		}
	}
	for _, incFile := range files {
		incPath := incFile
		if !filepath.IsAbs(incFile) {
			incPath = filepath.Join(baseDir, incFile)
		}
		data, err := os.ReadFile(incPath)
		if err != nil {
			log.Warn("[config] Included file '%s' could not be loaded: %v (skipping)", incPath, err)
			continue
		}
		incConfig := make(map[string]interface{})
		if err := yaml.Unmarshal(data, &incConfig); err != nil {
			log.Warn("[config] Included file '%s' could not be parsed: %v (skipping)", incPath, err)
			continue
		}
		baseConfig = mergeConfig(baseConfig, incConfig)
	}
	delete(baseConfig, "include")
	return baseConfig
}

// Replace deepMergeMap with a simple merge function
func mergeConfig(dst, src map[string]interface{}) map[string]interface{} {
	for k, v := range src {
		if vMap, ok := v.(map[string]interface{}); ok {
			if dstMap, ok := dst[k].(map[string]interface{}); ok {
				dst[k] = mergeConfig(dstMap, vMap)
			} else {
				dst[k] = vMap
			}
		} else {
			dst[k] = v
		}
	}
	return dst
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

		// Look up environment variable
		if value, exists := os.LookupEnv(varName); exists {
			return value
		}

		// If environment variable doesn't exist, keep original
		return match
	})

	return processedContent
}

// maskSensitiveMap returns a copy of the map with sensitive values masked
func maskSensitiveMap(m map[string]interface{}) map[string]interface{} {
	masked := make(map[string]interface{}, len(m))
	for k, v := range m {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "token") || strings.Contains(kl, "key") || strings.Contains(kl, "secret") || strings.Contains(kl, "password") || strings.Contains(kl, "email") {
			masked[k] = "****"
		} else if subMap, ok := v.(map[string]interface{}); ok {
			masked[k] = maskSensitiveMap(subMap)
		} else {
			masked[k] = v
		}
	}
	return masked
}

// FindConfigFile searches for a config file in the current directory or given path
func FindConfigFile(filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("no config file specified")
	}
	if _, err := os.Stat(filename); err == nil {
		return filename, nil
	}
	return "", fmt.Errorf("config file not found: %s", filename)
}

// CleanConfigSections removes any keys from the config that are not valid top-level sections
func CleanConfigSections(cfg *ConfigFile) {
	// No-op for now, but can be used to remove/validate keys after merging includes
}

// FieldSetInConfigFile checks if a field is set in the config file (not env/flag)
func FieldSetInConfigFile(path, field string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), field)
}

// StringSliceFlag implements flag.Value for []string, for multiple -config flags
// (restored for cli.go compatibility)
type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}
