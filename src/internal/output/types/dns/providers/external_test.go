// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"os/exec"
	"strconv"
	"testing"
)

func helperBin(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s helper not available", name)
	}
	return path
}

func externalWith(command string, args ...string) map[string]string {
	config := map[string]string{"command": command}
	for i, a := range args {
		config["args."+strconv.Itoa(i)] = a
	}
	return config
}

func TestExternalUpsertSuccess(t *testing.T) {
	prov, err := NewExternalProvider(externalWith(helperBin(t, "true"), "{action}", "{domain}", "{name}", "{type}", "{target}", "{ttl}"))
	if err != nil {
		t.Fatal(err)
	}
	p := prov.(*ExternalProvider)
	if err := p.CreateOrUpdateRecord("example.com", "A", "www", "1.2.3.4", 300, false, false); err != nil {
		t.Errorf("upsert failed: %v", err)
	}
}

func TestExternalDeleteSuccess(t *testing.T) {
	prov, err := NewExternalProvider(externalWith(helperBin(t, "true"), "{action}"))
	if err != nil {
		t.Fatal(err)
	}
	p := prov.(*ExternalProvider)
	if err := p.DeleteRecord("example.com", "A", "www"); err != nil {
		t.Errorf("delete failed: %v", err)
	}
}

func TestExternalFailureSurfaced(t *testing.T) {
	prov, err := NewExternalProvider(map[string]string{"command": helperBin(t, "false")})
	if err != nil {
		t.Fatal(err)
	}
	p := prov.(*ExternalProvider)
	if err := p.CreateOrUpdateRecord("example.com", "A", "www", "1.2.3.4", 300, false, false); err == nil {
		t.Error("expected error from failing command")
	}
	if err := p.DeleteRecord("example.com", "A", "www"); err == nil {
		t.Error("expected error from failing command")
	}
}

func TestExternalRejectsBadConfig(t *testing.T) {
	if _, err := NewExternalProvider(map[string]string{}); err == nil {
		t.Error("expected error for missing command")
	}
	if _, err := NewExternalProvider(map[string]string{"command": "relative/hook"}); err == nil {
		t.Error("expected error for relative command path")
	}
}

func TestExternalRejectsUnknownPlaceholder(t *testing.T) {
	prov, err := NewExternalProvider(externalWith(helperBin(t, "true"), "{bogus}"))
	if err != nil {
		t.Fatal(err)
	}
	p := prov.(*ExternalProvider)
	if err := p.CreateOrUpdateRecord("example.com", "A", "www", "1.2.3.4", 300, false, false); err == nil {
		t.Error("expected error for unknown placeholder")
	}
}

func TestExternalValidate(t *testing.T) {
	prov, err := NewExternalProvider(externalWith(helperBin(t, "true")))
	if err != nil {
		t.Fatal(err)
	}
	p := prov.(*ExternalProvider)
	if err := p.Validate(); err != nil {
		t.Errorf("validate failed for true helper: %v", err)
	}

	bad, err := NewExternalProvider(map[string]string{"command": "/nonexistent-hook-xyz"})
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.(*ExternalProvider).Validate(); err == nil {
		t.Error("expected validate error for missing binary")
	}
}
