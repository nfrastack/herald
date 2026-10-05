// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"reflect"
	"testing"
)

func TestParseDomainList(t *testing.T) {
	cases := map[string][]string{
		"":                                  nil,
		"  ":                                nil,
		"zt.example.com":                    {"zt.example.com"},
		"a.com, b.org":                      {"a.com", "b.org"},
		"a.com b.org":                       {"a.com", "b.org"},
		"a.com\nb.org":                      {"a.com", "b.org"},
		"[a.com b.org]":                     {"a.com", "b.org"},
		"[a.com, b.org]":                    {"a.com", "b.org"},
		`["a.com", "b.org"]`:                {"a.com", "b.org"},
		"a.com, a.com, b.org":               {"a.com", "b.org"},
		"  nfrastack.com,\nnfrastack.org  ": {"nfrastack.com", "nfrastack.org"},
	}
	for in, want := range cases {
		if got := ParseDomainList(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseDomainList(%q) = %v, want %v", in, got, want)
		}
	}
}
