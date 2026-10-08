// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package docker

import (
	"testing"
)

func TestIsTCPAPIURL(t *testing.T) {
	cases := map[string]bool{
		"unix:///var/run/docker.sock":           false,
		"http://socket-proxy.socket-proxy:2375": true,
		"https://docker.example.com:2376":       true,
		"HTTP://upper.example.com":              true,
		"":                                      false,
		"tcp://docker:2375":                     false,
	}
	for url, want := range cases {
		if got := isTCPAPIURL(url); got != want {
			t.Errorf("isTCPAPIURL(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestBasicAuthHeader(t *testing.T) {
	got := basicAuthHeader("aladdin", "opensesame")
	// echo -n 'aladdin:opensesame' | base64
	want := "Basic YWxhZGRpbjpvcGVuc2VzYW1l"
	if got != want {
		t.Errorf("basicAuthHeader = %q, want %q", got, want)
	}
}

func TestHasAuthorizationHeader(t *testing.T) {
	if !hasAuthorizationHeader(map[string]string{"Authorization": "x"}) {
		t.Error("exact match not detected")
	}
	if !hasAuthorizationHeader(map[string]string{"authorization": "x"}) {
		t.Error("case-insensitive match not detected")
	}
	if hasAuthorizationHeader(map[string]string{"X-Token": "x"}) {
		t.Error("false positive on unrelated header")
	}
	if hasAuthorizationHeader(nil) {
		t.Error("false positive on nil map")
	}
}

func TestCollectCustomHeaders(t *testing.T) {
	t.Setenv("HERALD_TEST_HEADER", "from-env")
	opts := map[string]string{
		"api_url":                   "http://socket-proxy:2375",
		"api_header_X-Custom-Token": "env://HERALD_TEST_HEADER",
		"api_header_X-Empty":        "",
		"api_header_":               "ignored",
		"unrelated":                 "ignored",
	}
	got := collectCustomHeaders(opts)
	if len(got) != 1 {
		t.Fatalf("collectCustomHeaders returned %d headers, want 1: %v", len(got), got)
	}
	if got["X-Custom-Token"] != "from-env" {
		t.Errorf("header value = %q, want %q", got["X-Custom-Token"], "from-env")
	}
}
