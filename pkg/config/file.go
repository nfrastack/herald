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
	if os.Getenv("LOG_TIMESTAMPS") == "" && !fieldSetInConfigFile(path, "log_timestamps") {
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

// preprocessIncludes recursively processes 'include' keys in YAML files
func preprocessIncludes(data []byte, basePath string, seen map[string]bool) ([]byte, error) {
	// Prevent circular includes
	absPath, _ := os.Getwd()
	if !strings.HasPrefix(basePath, "/") && absPath != "" {
		basePath = absPath + "/" + basePath
	}
	if seen[basePath] {
		return nil, fmt.Errorf("circular include detected for %s", basePath)
	}
	seen[basePath] = true

	var raw map[string]interface{}
	err := yaml.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}

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
			incData, err := os.ReadFile(incPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read included file %s: %w", incPath, err)
			}
			incProcessed, err := preprocessIncludes(incData, incPath, seen)
			if err != nil {
				return nil, err
			}
			var incRaw map[string]interface{}
			yaml.Unmarshal(incProcessed, &incRaw)
			// Merge incRaw into raw (shallow merge, top-level keys)
			for k, v := range incRaw {
				if k == "include" {
					continue // don't re-merge includes
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
		"dns-companion.yml",
		"dns-companion.yaml",
		"dns-companion.conf",
	)
	for _, name := range candidates {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no configuration file found (tried: %v)", candidates)
}

// Helper to check if a field is set in the config file (for booleans)
func fieldSetInConfigFile(path, field string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if strings.Contains(string(buf[:n]), field+" = ") {
				return true
			}
		}
		if err != nil {
			break
		}
	}
	return false
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
	// Merge Providers (src overrides dst)
	if dst.Providers == nil {
		dst.Providers = map[string]ProviderConfig{}
	}
	for k, v := range src.Providers {
		dst.Providers[k] = v
	}
	// Merge Polls (src overrides dst)
	if dst.Polls == nil {
		dst.Polls = map[string]ProviderConfig{}
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
