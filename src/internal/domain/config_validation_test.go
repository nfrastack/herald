// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package domain

import (
	"strings"
	"testing"
)

func testDomainConfigs() map[string]*DomainConfig {
	return map[string]*DomainConfig{
		"good": {
			Name:     "example.com",
			Profiles: &DomainProfiles{Inputs: []string{"docker_pub"}, Outputs: []string{"output01"}},
		},
		"dangling": {
			Name:     "missing.example.com",
			Profiles: &DomainProfiles{Inputs: []string{"docker_pub"}, Outputs: []string{"nope"}},
		},
	}
}

func testProfiles() (map[string]interface{}, map[string]interface{}, map[string]interface{}) {
	inputs := map[string]interface{}{"docker_pub": struct{}{}}
	outputs := map[string]interface{}{"output01": struct{}{}, "output02": struct{}{}}
	return inputs, outputs, map[string]interface{}{}
}

func TestValidateMissingOutputsStrict(t *testing.T) {
	inputs, outputs, dns := testProfiles()
	err := ValidateDomainConfigurations(testDomainConfigs(), inputs, outputs, dns, false)
	if err == nil {
		t.Fatal("expected error for dangling output without flag")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should name the missing output, got: %v", err)
	}
}

func TestValidateMissingOutputsAllowed(t *testing.T) {
	inputs, outputs, dns := testProfiles()
	domains := testDomainConfigs()
	if err := ValidateDomainConfigurations(domains, inputs, outputs, dns, true); err != nil {
		t.Fatalf("expected no error with flag, got: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("expected dangling domain pruned, %d remain", len(domains))
	}
	if _, ok := domains["good"]; !ok {
		t.Error("healthy domain should be kept")
	}
}

func TestValidateMissingOutputsPartial(t *testing.T) {
	inputs, outputs, dns := testProfiles()
	domains := map[string]*DomainConfig{
		"partial": {
			Name:     "example.com",
			Profiles: &DomainProfiles{Inputs: []string{"docker_pub"}, Outputs: []string{"output01", "gone"}},
		},
	}
	if err := ValidateDomainConfigurations(domains, inputs, outputs, dns, true); err != nil {
		t.Fatalf("expected no error with flag, got: %v", err)
	}
	got := domains["partial"].Profiles.Outputs
	if len(got) != 1 || got[0] != "output01" {
		t.Errorf("expected only surviving output kept, got %v", got)
	}
}

func TestValidateMissingInputsStillFatal(t *testing.T) {
	_, outputs, dns := testProfiles()
	inputs := map[string]interface{}{}
	domains := map[string]*DomainConfig{
		"bad": {
			Name:     "example.com",
			Profiles: &DomainProfiles{Inputs: []string{"ghost"}, Outputs: []string{"output01"}},
		},
	}
	if err := ValidateDomainConfigurations(domains, inputs, outputs, dns, true); err == nil {
		t.Error("missing inputs should still fail even with flag")
	}
}
