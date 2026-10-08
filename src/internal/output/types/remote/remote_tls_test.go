// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"testing"
	"time"
)

func TestParseRemoteTimeout(t *testing.T) {
	def := 30 * time.Second
	cases := []struct {
		name  string
		value interface{}
		want  time.Duration
	}{
		{"nil", nil, def},
		{"empty", "", def},
		{"duration string", "45s", 45 * time.Second},
		{"minutes", "2m", 2 * time.Minute},
		{"plain seconds", "60", 60 * time.Second},
		{"int", 10, 10 * time.Second},
		{"garbage", "soon", def},
		{"zero string", "0", def},
		{"negative", "-5s", def},
	}
	for _, tc := range cases {
		if got := parseRemoteTimeout(tc.value); got != tc.want {
			t.Errorf("%s: parseRemoteTimeout(%v) = %v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
}

func TestBuildRemoteTLSConfigDefaults(t *testing.T) {
	cfg, err := buildRemoteTLSConfig(nil)
	if err != nil {
		t.Fatalf("defaults errored: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("verification should be on by default")
	}
	if cfg.RootCAs != nil {
		t.Error("no custom roots expected by default")
	}

	cfg, err = buildRemoteTLSConfig(map[string]interface{}{"verify": false})
	if err != nil {
		t.Fatalf("verify=false errored: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("verification should be off with verify=false")
	}
}

func TestBuildRemoteTLSConfigErrors(t *testing.T) {
	if _, err := buildRemoteTLSConfig(map[string]interface{}{"ca": "/nonexistent/ca.pem"}); err == nil {
		t.Error("missing CA file should error")
	}
	if _, err := buildRemoteTLSConfig(map[string]interface{}{"cert": "/nonexistent/c.pem"}); err == nil {
		t.Error("cert without key should error")
	}
}

func TestNewRemoteFormatSecrets(t *testing.T) {
	t.Setenv("HERALD_TEST_REMOTE_TOKEN", "s3cret")
	format, err := NewRemoteFormat("test", map[string]interface{}{
		"url":       "http://atlas:8080/api/dns",
		"client_id": "nomad",
		"token":     "env://HERALD_TEST_REMOTE_TOKEN",
		"timeout":   "10s",
	})
	if err != nil {
		t.Fatalf("NewRemoteFormat errored: %v", err)
	}
	rf, ok := format.(*RemoteFormat)
	if !ok {
		t.Fatal("unexpected format type")
	}
	if rf.token != "s3cret" {
		t.Errorf("token = %q, want resolved secret", rf.token)
	}
	if rf.httpClient.Timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", rf.httpClient.Timeout)
	}
}

func TestNewRemoteFormatRequiresFields(t *testing.T) {
	base := map[string]interface{}{
		"url":       "http://atlas:8080/api/dns",
		"client_id": "nomad",
		"token":     "t",
	}
	for _, key := range []string{"url", "client_id", "token"} {
		cfg := map[string]interface{}{}
		for k, v := range base {
			cfg[k] = v
		}
		delete(cfg, key)
		if _, err := NewRemoteFormat("test", cfg); err == nil {
			t.Errorf("missing %q should error", key)
		}
	}
}
