// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package state

import (
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tr := NewTracker(dir, time.Hour)
	tr.Touch("tiredofit.ca", "cipher", "A", "10.0.0.1", "zt_toi", "")
	if tr.Count() != 1 {
		t.Fatalf("count=%d want 1", tr.Count())
	}
	tr.Save()

	loaded := NewTracker(dir, time.Hour)
	loaded.Load()
	if loaded.Count() != 1 {
		t.Fatalf("reload count=%d want 1", loaded.Count())
	}
}

func TestStaleThreshold(t *testing.T) {
	dir := t.TempDir()
	tr := NewTracker(dir, time.Hour)
	tr.Touch("tiredofit.ca", "fresh", "A", "10.0.0.1", "zt_toi", "")
	tr.Touch("tiredofit.ca", "old", "A", "10.0.0.2", "zt_toi", "")
	tr.mu.Lock()
	tr.entries[key("tiredofit.ca", "old", "A")].LastSeen = time.Now().UTC().Add(-2 * time.Hour)
	tr.mu.Unlock()

	stale := tr.Stale()
	if len(stale) != 1 || stale[0].Hostname != "old" {
		t.Fatalf("stale=%v want [old]", stale)
	}
}

func TestStaleDisabled(t *testing.T) {
	tr := NewTracker(t.TempDir(), 0)
	tr.Touch("tiredofit.ca", "old", "A", "10.0.0.2", "zt_toi", "")
	tr.mu.Lock()
	tr.entries[key("tiredofit.ca", "old", "A")].LastSeen = time.Now().UTC().Add(-8760 * time.Hour)
	tr.mu.Unlock()
	if got := tr.Stale(); len(got) != 0 {
		t.Fatalf("disabled tracker reported %d stale", len(got))
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	tr := NewTracker(dir, time.Hour)
	tr.Touch("tiredofit.ca", "cipher", "A", "10.0.0.1", "zt_toi", "")
	tr.Remove("tiredofit.ca", "cipher", "A")
	if tr.Count() != 0 {
		t.Fatalf("count=%d want 0", tr.Count())
	}
	tr.Save()

	loaded := NewTracker(dir, time.Hour)
	loaded.Load()
	if loaded.Count() != 0 {
		t.Fatalf("reload count=%d want 0", loaded.Count())
	}
}

func TestNilSafe(t *testing.T) {
	var nilTracker *Tracker
	nilTracker.Touch("a", "b", "A", "1.2.3.4", "", "")
	nilTracker.Remove("a", "b", "A")
	nilTracker.Save()
	nilTracker.Stop()
	if nilTracker.Count() != 0 || len(nilTracker.Stale()) != 0 {
		t.Fatal("nil tracker must be safe")
	}
}
