// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package util

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

func NormalizeDomainKey(domain string) string {
	return strings.ReplaceAll(domain, ".", "_")
}

func ExtractHostsFromRule(rule string) []string {
	var hostnames []string
	re := regexp.MustCompile(`Host\(\s*['"` + "`" + `](.*?)['"` + "`" + `]\s*\)`)
	matches := re.FindAllStringSubmatch(rule, -1)
	for _, match := range matches {
		if len(match) > 1 {
			hosts := strings.Split(match[1], ",")
			for _, h := range hosts {
				h = strings.TrimSpace(h)
				h = strings.Trim(h, "'\"` ")
				if h != "" {
					hostnames = append(hostnames, h)
				}
			}
		}
	}
	return hostnames
}

func GetMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func GetMapKeysGeneric(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func GetProfileNameFromOptions(options map[string]string, defaultName string) string {
	profileName := options["profile_name"]

	if profileName == "" {
		profileName = options["name"]
	}

	if profileName == "" {
		profileName = options["profile"]
	}

	if profileName == "" {
		profileName = defaultName
	}

	return profileName
}

func MaskSensitiveValue(value string) string {
	if value == "" {
		return ""
	}

	if len(value) < 6 {
		return "****"
	}

	visiblePrefix := 2
	visibleSuffix := 2

	if len(value) > 12 {
		visiblePrefix = 3
		visibleSuffix = 3
	}

	if visiblePrefix+visibleSuffix > len(value)/2 {
		visiblePrefix = 2
		visibleSuffix = 2
	}

	prefix := value[:visiblePrefix]
	suffix := value[len(value)-visibleSuffix:]
	masked := strings.Repeat("*", len(value)-visiblePrefix-visibleSuffix)

	return fmt.Sprintf("%s%s%s", prefix, masked, suffix)
}

func IsSensitiveKey(key string) bool {
	sensitiveKeywords := []string{
		"api_email",
		"api_key",
		"api_user",
		"apikey",
		"auth_pass",
		"auth_token",
		"auth",
		"code",
		"cred",
		"credential",
		"key",
		"pass",
		"password",
		"secret",
		"token",
		"username",
		"user",
	}

	lowerKey := strings.ToLower(key)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerKey, keyword) {
			if keyword == "auth" && (strings.Contains(lowerKey, "author") ||
				strings.Contains(lowerKey, "oath") ||
				strings.HasSuffix(lowerKey, "auth_user")) {
				continue
			}
			return true
		}
	}
	return false
}

func MaskSensitiveOptions(options map[string]string) map[string]string {
	if options == nil {
		return nil
	}

	masked := make(map[string]string, len(options))
	for k, v := range options {
		if IsSensitiveKey(k) {
			masked[k] = MaskSensitiveValue(v)
		} else {
			masked[k] = v
		}
	}
	return masked
}

func MaskSensitiveMapRecursive(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}

	masked := make(map[string]interface{}, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			if sv, ok := v.(string); ok {
				masked[k] = MaskSensitiveValue(sv)
			} else {
				masked[k] = "****"
			}
		} else if subMap, ok := v.(map[string]interface{}); ok {
			masked[k] = MaskSensitiveMapRecursive(subMap)
		} else {
			masked[k] = v
		}
	}
	return masked
}

func ValidateListenPatterns(patterns []string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			return fmt.Errorf("empty listen pattern")
		}
		if strings.Contains(pattern, "..") {
			return fmt.Errorf("invalid pattern: %s", pattern)
		}
	}
	return nil
}

func resolveInterfacePatterns(pattern, port string) ([]string, error) {
	var addresses []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	regexPattern := strings.ReplaceAll(pattern, "*", ".*")
	regex, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return nil, fmt.Errorf("invalid pattern '%s': %w", pattern, err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		if !regex.MatchString(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					resolvedAddr := fmt.Sprintf("%s:%s", ipNet.IP.String(), port)
					addresses = append(addresses, resolvedAddr)
				}
			}
		}
	}

	if len(addresses) == 0 {
		var ifaceNames []string
		for _, iface := range interfaces {
			ifaceNames = append(ifaceNames, iface.Name)
		}
		return nil, fmt.Errorf("no interfaces matched pattern '%s' (available: %s)", pattern, strings.Join(ifaceNames, ", "))
	}

	return addresses, nil
}

func ResolveListenAddressesQuiet(patterns []string, port string) ([]string, error) {
	addresses := []string{}

	for _, pattern := range patterns {
		if strings.Contains(pattern, ":") {
			addresses = append(addresses, pattern)
			continue
		}

		if strings.Contains(pattern, "*") {
			resolved, err := resolveInterfacePatterns(pattern, port)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve interface pattern '%s': %w", pattern, err)
			}
			addresses = append(addresses, resolved...)
			continue
		}

		if pattern == "all" {
			addresses = append(addresses, ":"+port)
		} else if pattern == "localhost" {
			addresses = append(addresses, "127.0.0.1:"+port)
		} else {
			addresses = append(addresses, pattern+":"+port)
		}
	}

	if len(addresses) == 0 {
		addresses = append(addresses, ":"+port)
	}

	return addresses, nil
}
