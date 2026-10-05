// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package api

import (
	"testing"
	"time"

	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/output"
)

type allowFake struct {
	writes  []string
	removes []string
}

func (f *allowFake) GetName() string { return "allowfake" }

func (f *allowFake) WriteRecord(domain, hostname, target, recordType string, ttl int) error {
	return f.WriteRecordWithSource(domain, hostname, target, recordType, ttl, "test")
}

func (f *allowFake) WriteRecordWithSource(domain, hostname, target, recordType string, ttl int, source string) error {
	f.writes = append(f.writes, hostname+"."+domain)
	return nil
}

func (f *allowFake) RemoveRecord(domain, hostname, recordType string) error {
	f.removes = append(f.removes, hostname+"."+domain)
	return nil
}

func (f *allowFake) Sync() error { return nil }

var allowFakeInst = &allowFake{}

func TestAllowlistFiltersUploadsAndRemovals(t *testing.T) {
	output.RegisterFormat("allowfake_test", func(string, map[string]interface{}) (output.OutputFormat, error) {
		return allowFakeInst, nil
	})
	allowFakeInst.writes = nil
	allowFakeInst.removes = nil

	om := output.NewOutputManager()
	if err := om.AddProfile("p", "", nil, map[string]interface{}{"type": "allowfake_test"}); err != nil {
		t.Fatal(err)
	}
	s := NewAPIServer(nil, &config.APIConfig{})
	s.outputManager = om
	s.clientExpiry = time.Hour
	s.LoadClientProfiles(map[string]config.APIClientProfile{
		"scoped": {Token: "t1", OutputProfile: "p", Domains: []string{"tiredofit.ca"}},
		"open":   {Token: "t2", OutputProfile: "p"},
		"narrow": {Token: "t3", OutputProfile: "p", Hostnames: []string{"web", "*.edge"}},
		"shared": {Token: "t4", OutputProfile: "p", SharedWrites: true},
	})
	s.clients["scoped"] = &ClientData{
		ClientID: "scoped", Received: time.Now(),
		Domains: map[string]*Domain{
			"tiredofit.ca":  {Records: []*Record{{Hostname: "a", Type: "A", Target: "10.0.0.1", TTL: 60}}},
			"nfrastack.com": {Records: []*Record{{Hostname: "b", Type: "A", Target: "10.0.0.2", TTL: 60}}},
		},
	}
	s.clients["open"] = &ClientData{
		ClientID: "open", Received: time.Now(),
		Domains: map[string]*Domain{
			"nfrastack.com": {Records: []*Record{{Hostname: "c", Type: "A", Target: "10.0.0.3", TTL: 60}}},
		},
	}

	s.aggregateAndWriteWithRemovals("test", "scoped", map[string][][2]string{
		"tiredofit.ca":  {{"gone", "A"}},
		"nfrastack.com": {{"evil", "A"}},
	})

	got := map[string]bool{}
	for _, w := range allowFakeInst.writes {
		got[w] = true
	}
	if !got["a.tiredofit.ca"] {
		t.Error("allowed record missing")
	}
	if got["b.nfrastack.com"] {
		t.Error("out-of-scope record was written")
	}
	if !got["c.nfrastack.com"] {
		t.Error("open client record missing")
	}
	removed := map[string]bool{}
	for _, r := range allowFakeInst.removes {
		removed[r] = true
	}
	if !removed["gone.tiredofit.ca"] {
		t.Error("in-scope removal missing")
	}
	if removed["evil.nfrastack.com"] {
		t.Error("out-of-scope removal was applied")
	}
}

func TestOwnershipAndHostnameScope(t *testing.T) {
	output.RegisterFormat("allowfake_test", func(string, map[string]interface{}) (output.OutputFormat, error) {
		return allowFakeInst, nil
	})
	allowFakeInst.writes = nil
	allowFakeInst.removes = nil

	om := output.NewOutputManager()
	if err := om.AddProfile("p", "", nil, map[string]interface{}{"type": "allowfake_test"}); err != nil {
		t.Fatal(err)
	}
	s := NewAPIServer(nil, &config.APIConfig{})
	s.outputManager = om
	s.clientExpiry = time.Hour
	s.LoadClientProfiles(map[string]config.APIClientProfile{
		"atlas":  {Token: "t1", OutputProfile: "p"},
		"sneaky": {Token: "t2", OutputProfile: "p"},
		"narrow": {Token: "t3", OutputProfile: "p", Hostnames: []string{"web", "*.edge"}},
		"spare":  {Token: "t4", OutputProfile: "p", SharedWrites: true},
	})
	// atlas owns web.tiredofit.ca.
	s.clients["atlas"] = &ClientData{
		ClientID: "atlas", Received: time.Now(),
		Domains: map[string]*Domain{
			"tiredofit.ca": {Records: []*Record{{Hostname: "web", Type: "A", Target: "10.0.0.1", TTL: 60}}},
		},
	}
	s.aggregateAndWriteWithRemovals("t1", "atlas", nil)

	// sneaky tries to overwrite it and to add its own name.
	s.clients["sneaky"] = &ClientData{
		ClientID: "sneaky", Received: time.Now(),
		Domains: map[string]*Domain{
			"tiredofit.ca": {Records: []*Record{
				{Hostname: "web", Type: "A", Target: "6.6.6.6", TTL: 60},
				{Hostname: "sneaky", Type: "A", Target: "6.6.6.6", TTL: 60},
			}},
		},
	}
	s.aggregateAndWriteWithRemovals("t2", "sneaky", map[string][][2]string{
		"tiredofit.ca": {{"web", "A"}},
	})
	// narrow is outside its hostname scope; spare shares writes.
	s.clients["narrow"] = &ClientData{
		ClientID: "narrow", Received: time.Now(),
		Domains: map[string]*Domain{
			"tiredofit.ca": {Records: []*Record{{Hostname: "db", Type: "A", Target: "10.0.0.9", TTL: 60}}},
		},
	}
	s.clients["spare"] = &ClientData{
		ClientID: "spare", Received: time.Now(),
		Domains: map[string]*Domain{
			"tiredofit.ca": {Records: []*Record{{Hostname: "web", Type: "A", Target: "10.0.0.7", TTL: 60}}},
		},
	}
	s.aggregateAndWriteWithRemovals("t3", "spare", nil)

	got := map[string]bool{}
	for _, w := range allowFakeInst.writes {
		got[w] = true
	}
	if !got["web.tiredofit.ca"] || !got["sneaky.tiredofit.ca"] {
		t.Errorf("expected atlas + sneaky-own writes, got %v", allowFakeInst.writes)
	}
	// Every aggregation rewrites all clients: t1 atlas/web, t2 atlas/web +
	// sneaky/sneaky (overwrite + removal rejected), t3 atlas/web +
	// sneaky/sneaky + spare/web-overwrite (narrow/db rejected) = 6 writes.
	if len(allowFakeInst.writes) != 6 {
		t.Errorf("expected 6 writes, got %v", allowFakeInst.writes)
	}
	for _, r := range allowFakeInst.removes {
		if r == "web.tiredofit.ca" {
			t.Error("stranger removal of owned record was applied")
		}
	}
}
