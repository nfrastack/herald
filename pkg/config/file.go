// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"container-dns-companion/pkg/log"

	"fmt"
	"net"
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

	// Load environment variable configuration (overrides config file)
	LoadFromEnvironment(&cfg)

	// Set application-level defaults ONLY if still unset after config and env
	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "info"
	}
	if os.Getenv("LOG_TIMESTAMPS") == "" && !FieldSetInConfigFile(path, "log_timestamps") {
		cfg.General.LogTimestamps = true
	}
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

// deepMergeMap recursively merges src into dst (both map[string]interface{}), combining nested maps
func deepMergeMap(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = map[string]interface{}{}
	}
	for k, v := range src {
		if vMap, ok := v.(map[string]interface{}); ok {
			if dstMap, ok := dst[k].(map[string]interface{}); ok {
				dst[k] = deepMergeMap(dstMap, vMap)
			} else {
				dst[k] = deepMergeMap(nil, vMap)
			}
		} else {
			dst[k] = v
		}
	}
	return dst
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
	log.Trace("[config/file] Raw YAML map in %s: %#v", basePath, maskSensitiveMap(raw))

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
				log.Trace("[config/file] Key '%s' from %s: %v", k, incPath, maskSensitiveMap(map[string]interface{}{k: incRaw[k]})[k])
			}
			// Only merge known top-level sections as maps
			for _, section := range []string{"providers", "polls", "domains", "defaults", "general"} {
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
				if k == "include" || k == "providers" || k == "polls" || k == "domains" || k == "defaults" || k == "general" {
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

// FindConfigFile searches for the config file in the current directory and common variants
func FindConfigFile(requested string) (string, error) {
	candidates := []string{}
	if requested != "" {
		candidates = append(candidates, requested)
	}
	// Always prefer container-dns-companion.yml, then .yaml, then .conf
	candidates = append(candidates,
		"container-dns-companion.yml",
		"container-dns-companion.yaml",
		"container-dns-companion.conf",
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

// Helper to check if a string is an IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
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

// Helper to parse a comma-separated list into a slice of strings
func parseCommaList(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
	if len(src.General.PollProfiles) > 0 {
		dst.General.PollProfiles = src.General.PollProfiles
	}
	if src.General.DryRun {
		dst.General.DryRun = src.General.DryRun
	}
	// Merge Defaults
	if (src.Defaults != DefaultsConfig{}) {
		dst.Defaults = src.Defaults
	}
	// Merge DNS Providers (src overrides dst)
	if dst.Providers == nil {
		dst.Providers = map[string]DNSProviderConfig{}
	}
	for k, v := range src.Providers {
		dst.Providers[k] = v
	}
	// Merge Poll Providers (src overrides dst)
	if dst.Polls == nil {
		dst.Polls = map[string]PollProviderConfig{}
	}
	for k, v := range src.Polls {
		dst.Polls[k] = v
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

// CleanConfigSections removes invalid keys from DNS providers and poll providers after merging includes
func CleanConfigSections(cfg *ConfigFile) {
	// Define valid keys for DNS providers and poll providers
	validDNSProviderKeys := map[string]struct{}{
		"type": {}, "api_token": {}, "api_key": {}, "api_email": {}, "zone_id": {},
	}
	validPollProviderKeys := map[string]struct{}{
		"type": {}, "host": {}, "expose_containers": {}, "filter_type": {}, "process_existing_containers": {}, "record_remove_on_stop": {}, "tls": {}, "poll_url": {}, "poll_interval": {},
	}

	// Clean DNS providers
	for name, provider := range cfg.Providers {
		for k := range provider.Options {
			if _, ok := validDNSProviderKeys[k]; !ok {
				log.Debug("[config/clean] Removing invalid DNS provider key '%s' from provider '%s'", k, name)
				delete(provider.Options, k)
			}
		}
		cfg.Providers[name] = provider
	}

	// Clean poll providers
	for name, poll := range cfg.Polls {
		for k := range poll.Options {
			if _, ok := validPollProviderKeys[k]; !ok {
				log.Debug("[config/clean] Removing invalid poll provider key '%s' from poll '%s'", k, name)
				delete(poll.Options, k)
			}
		}
		cfg.Polls[name] = poll
	}
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
