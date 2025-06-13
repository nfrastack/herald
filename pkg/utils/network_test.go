// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"net"
	"testing"
)

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		str     string
		pattern string
		want    bool
	}{
		{"eth0", "eth*", true},
		{"eth0", "enp*", false},
		{"enp0s3", "enp*", true},
		{"docker0", "docker*", true},
		{"lo", "lo", true},
		{"anything", "*", true},
		{"eth0", "eth0", true},
		{"eth1", "eth0", false},
	}

	for _, tt := range tests {
		got := matchesPattern(tt.str, tt.pattern)
		if got != tt.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.str, tt.pattern, got, tt.want)
		}
	}
}

func TestShouldIncludeInterface(t *testing.T) {
	tests := []struct {
		name            string
		interfaceName   string
		includePatterns []string
		excludePatterns []string
		want            bool
	}{
		{
			name:            "include all",
			interfaceName:   "eth0",
			includePatterns: []string{"*"},
			excludePatterns: nil,
			want:            true,
		},
		{
			name:            "exclude docker",
			interfaceName:   "docker0",
			includePatterns: []string{"*"},
			excludePatterns: []string{"docker*"},
			want:            false,
		},
		{
			name:            "include specific",
			interfaceName:   "eth0",
			includePatterns: []string{"eth0"},
			excludePatterns: nil,
			want:            true,
		},
		{
			name:            "exclude overrides include",
			interfaceName:   "eth0",
			includePatterns: []string{"eth*"},
			excludePatterns: []string{"eth0"},
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldIncludeInterface(tt.interfaceName, tt.includePatterns, tt.excludePatterns)
			if got != tt.want {
				t.Errorf("shouldIncludeInterface() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveListenAddresses(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		port     string
		wantLen  int // We can't predict exact addresses, but we can check minimum length
	}{
		{
			name:     "empty patterns defaults to all",
			patterns: []string{},
			port:     "8080",
			wantLen:  1, // Should return at least ":8080"
		},
		{
			name:     "explicit IP",
			patterns: []string{"127.0.0.1"},
			port:     "8080",
			wantLen:  1,
		},
		{
			name:     "all interfaces",
			patterns: []string{"all"},
			port:     "8080",
			wantLen:  1, // At least one interface
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveListenAddresses(tt.patterns, tt.port)
			if err != nil {
				t.Errorf("ResolveListenAddresses() error = %v", err)
				return
			}
			if len(got) < tt.wantLen {
				t.Errorf("ResolveListenAddresses() returned %d addresses, want at least %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestValidateListenPatterns(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		wantErr  bool
	}{
		{
			name:     "valid IP",
			patterns: []string{"192.168.1.1"},
			wantErr:  false,
		},
		{
			name:     "valid pattern",
			patterns: []string{"eth*"},
			wantErr:  false,
		},
		{
			name:     "valid exclusion",
			patterns: []string{"!docker*"},
			wantErr:  false,
		},
		{
			name:     "invalid pattern",
			patterns: []string{"eth["},
			wantErr:  true,
		},
		{
			name:     "special keywords",
			patterns: []string{"all", "*"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateListenPatterns(tt.patterns)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateListenPatterns() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGetInterfaceAddresses tests the getInterfaceAddresses function
func TestGetInterfaceAddresses(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("Unable to get network interfaces for testing")
	}

	// Find a valid interface to test with
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addresses := getInterfaceAddresses(iface)
			// We can't predict how many addresses, but it should not error
			t.Logf("Interface %s has %d addresses", iface.Name, len(addresses))
			break
		}
	}
}