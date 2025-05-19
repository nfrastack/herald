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

// LoadConfigFile loads the configuration from a YAML file (any extension)
func LoadConfigFile(path string) (*ConfigFile, error) {
	log.Debug("[config/file] Loading configuration from %s", path)

	var cfg ConfigFile

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[config/file] failed to read config file: %w", err)
	}
	err = yaml.Unmarshal(data, &cfg)
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
