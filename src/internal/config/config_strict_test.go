// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "herald.yml")
	content := `general:
  log_level: info
  tll: 300
inputs:
  docker_pub:
    type: docker
    custom_option: anything
domains:
  d01:
    name: example.com
    profiles:
      inputs: [docker_pub]
      outputs: [out]
outputs:
  out:
    type: file
    format: json
    path: ./out.json
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path); err == nil {
		t.Fatal("expected unknown field tll to fail")
	}
}

func TestLoadAcceptsKnownAndFreeformFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "herald.yml")
	content := `general:
  log_level: info
inputs:
  docker_pub:
    type: docker
    custom_option: anything
domains:
  d01:
    name: example.com
    profiles:
      inputs: [docker_pub]
      outputs: [out]
outputs:
  out:
    type: file
    format: json
    path: ./out.json
api:
  enabled: true
  profiles:
    edge01:
      token: abc
      output_profile: out
      domains: [example.com]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.General.LogLevel != "info" {
		t.Errorf("log level = %q", cfg.General.LogLevel)
	}
	if len(cfg.API.Profiles["edge01"].Domains) != 1 {
		t.Error("api profile domains not parsed")
	}
}
