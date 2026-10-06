// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package state

import (
	"encoding/json"
	"github.com/nfrastack/herald/internal/log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Domain    string    `json:"domain"`
	Hostname  string    `json:"hostname"`
	Type      string    `json:"type"`
	Target    string    `json:"target"`
	Source    string    `json:"source,omitempty"`
	Client    string    `json:"client,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Tracker struct {
	mu         sync.RWMutex
	dir        string
	path       string
	staleAfter time.Duration
	entries    map[string]*Entry
	dirty      bool
	logger     *log.ScopedLogger
	stopCh     chan struct{}
	stopOnce   sync.Once
}

func key(domain, hostname, recordType string) string {
	return domain + "\x00" + hostname + "\x00" + recordType
}

func NewTracker(dir string, staleAfter time.Duration) *Tracker {
	return &Tracker{
		dir:        dir,
		path:       filepath.Join(dir, "lastseen.json"),
		staleAfter: staleAfter,
		entries:    make(map[string]*Entry),
		logger:     log.NewScopedLogger("[state]", ""),
		stopCh:     make(chan struct{}),
	}
}

func (t *Tracker) Load() {
	data, err := os.ReadFile(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			t.logger.Warn("Failed to read state file %s: %v (starting empty)", t.path, err)
		}
		return
	}
	var stored struct {
		Entries map[string]*Entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.logger.Warn("Failed to parse state file %s: %v (starting empty)", t.path, err)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range stored.Entries {
		if e != nil && e.Domain != "" {
			t.entries[k] = e
		}
	}
	t.logger.Debug("Loaded %d tracked records from %s", len(t.entries), t.path)
}

func (t *Tracker) Touch(domain, hostname, recordType, target, source, client string) {
	if t == nil {
		return
	}
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	k := key(domain, hostname, recordType)
	if e, ok := t.entries[k]; ok {
		e.LastSeen = now
		e.Target = target
		if source != "" {
			e.Source = source
		}
		if client != "" {
			e.Client = client
		}
	} else {
		t.entries[k] = &Entry{
			Domain: hostnameDomain(domain), Hostname: hostname, Type: recordType,
			Target: target, Source: source, Client: client,
			FirstSeen: now, LastSeen: now,
		}
	}
	t.dirty = true
}

func hostnameDomain(domain string) string {
	return strings.TrimSuffix(domain, ".")
}

func (t *Tracker) Remove(domain, hostname, recordType string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.entries[key(domain, hostname, recordType)]; ok {
		delete(t.entries, key(domain, hostname, recordType))
		t.dirty = true
	}
}

func (t *Tracker) Stale() []*Entry {
	if t == nil || t.staleAfter <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-t.staleAfter)
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []*Entry
	for _, e := range t.entries {
		if e.LastSeen.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

func (t *Tracker) Count() int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

func (t *Tracker) Save() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return
	}
	stored := struct {
		Entries map[string]*Entry `json:"entries"`
	}{Entries: make(map[string]*Entry, len(t.entries))}
	for k, e := range t.entries {
		cp := *e
		stored.Entries[k] = &cp
	}
	t.mu.Unlock()

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.logger.Warn("Failed to marshal state: %v", err)
		return
	}
	if err := os.MkdirAll(t.dir, 0700); err != nil {
		t.logger.Warn("Failed to create state dir %s: %v", t.dir, err)
		return
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.logger.Warn("Failed to write state file %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, t.path); err != nil {
		t.logger.Warn("Failed to persist state file %s: %v", t.path, err)
		return
	}
	t.mu.Lock()
	t.dirty = false
	t.mu.Unlock()
}

func (t *Tracker) Start(reportInterval time.Duration) {
	if t == nil {
		return
	}
	if reportInterval <= 0 {
		reportInterval = time.Hour
	}
	go func() {
		flush := time.NewTicker(time.Minute)
		defer flush.Stop()
		report := time.NewTicker(reportInterval)
		defer report.Stop()
		for {
			select {
			case <-t.stopCh:
				t.Save()
				return
			case <-flush.C:
				t.Save()
			case <-report.C:
				t.reportStale()
			}
		}
	}()
}

func (t *Tracker) Stop() {
	if t == nil {
		return
	}
	t.stopOnce.Do(func() { close(t.stopCh) })
}

func (t *Tracker) reportStale() {
	for _, e := range t.Stale() {
		fqdn := e.Hostname + "." + e.Domain
		if e.Hostname == "" || e.Hostname == "@" {
			fqdn = e.Domain
		}
		via := e.Source
		if e.Client != "" {
			via = e.Client + "/" + via
		}
		t.logger.Warn("Stale record %s (%s -> %s, via %s): last seen %s, first seen %s - review manually",
			fqdn, e.Type, e.Target, via,
			e.LastSeen.Format("2006-01-02"), e.FirstSeen.Format("2006-01-02"))
	}
}

var Default *Tracker

func Init(dir string, staleAfter time.Duration) {
	if dir == "" {
		return
	}
	Default = NewTracker(dir, staleAfter)
	Default.Load()
	reportInterval := time.Hour
	if staleAfter > 0 && staleAfter/4 < reportInterval {
		reportInterval = staleAfter / 4
		if reportInterval < 5*time.Minute {
			reportInterval = 5 * time.Minute
		}
	}
	Default.Start(reportInterval)
}

func Touch(domain, hostname, recordType, target, source, client string) {
	if Default != nil {
		Default.Touch(domain, hostname, recordType, target, source, client)
	}
}

func Remove(domain, hostname, recordType string) {
	if Default != nil {
		Default.Remove(domain, hostname, recordType)
	}
}
