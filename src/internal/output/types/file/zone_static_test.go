// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package file

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func testZoneConfig(path string) map[string]interface{} {
	return map[string]interface{}{
		"path": path,
		"soa": map[string]interface{}{
			"primary_ns": "ns1.%domain%", "admin_email": "admin@%domain%",
			"refresh": 3600, "retry": 900, "expire": 604800, "minimum": 300, "serial": "auto",
		},
		"ns_records": []interface{}{"ns1.%domain%"},
	}
}

func zoneSerial(content string) string {
	re := regexp.MustCompile(`(?m)^\s*([0-9]{10,})\s*;\s*Serial`)
	m := re.FindStringSubmatch(content)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func TestNoOpSyncStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "%domain%.zone")
	f, err := NewZoneFormat("testprofile", "example.com", testZoneConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(dir, "example_com.zone")

	if err := f.WriteRecordWithSource("example.com", "www", "10.0.0.1", "A", 60, "docker_int"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(fp)
	s1 := zoneSerial(string(before))
	if s1 == "" {
		t.Fatal("no serial after first sync")
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(fp)
	if string(after) != string(before) {
		t.Fatal("second sync rewrote unchanged file")
	}
	if zoneSerial(string(after)) != s1 {
		t.Fatal("serial bumped without changes")
	}
}

func TestStaticMigrationAndCollisions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "%domain%.zone")
	f, err := NewZoneFormat("testprofile", "example.com", testZoneConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(dir, "example_com.zone")

	if err := f.WriteRecordWithSource("example.com", "www", "10.0.0.1", "A", 60, "docker_int"); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteRecordWithSource("example.com", "a", "10.0.0.9", "A", 60, "docker_int"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	raw1, _ := os.ReadFile(fp)

	// Simulate a legacy file: manual lines sitting in the managed section.
	seeded := strings.Replace(string(raw1), "; Managed Records",
		"; Managed Records\nlegacy               60     IN   A     10.9.9.9        ; input: manual\na                    60     IN   CNAME a.tiredofit.ca  ; input: manual", 1)
	if err := os.WriteFile(fp, []byte(seeded), 0644); err != nil {
		t.Fatal(err)
	}

	// Fresh instance (new process): warm-load + migrate on sync.
	f2, err := NewZoneFormat("testprofile", "example.com", testZoneConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := f2.WriteRecordWithSource("example.com", "www", "10.0.0.1", "A", 60, "docker_int"); err != nil {
		t.Fatal(err)
	}
	if err := f2.WriteRecordWithSource("example.com", "a", "10.0.0.9", "A", 60, "docker_int"); err != nil {
		t.Fatal(err)
	}
	if err := f2.Sync(); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(fp)
	text := string(body)
	if !strings.Contains(text, "; Static Records") {
		t.Error("expected static section after migration")
	}
	if !strings.Contains(text, "10.9.9.9") {
		t.Error("legacy manual record should survive in static section")
	}
	managed := text[strings.Index(text, "; Managed Records"):]
	if strings.Contains(managed, "10.9.9.9") {
		t.Error("legacy record leaked back into managed section")
	}
	if !strings.Contains(text, "CONFLICT") {
		t.Error("expected CONFLICT comment for shadowed static CNAME")
	}
	managedA := 0
	for _, line := range strings.Split(managed, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, ";") {
			continue
		}
		if f := strings.Fields(line); len(f) >= 4 && f[0] == "a" {
			managedA++
			if f[3] == "CNAME" {
				t.Error("CNAME for 'a' should have been dropped from managed section")
			}
		}
	}
	if managedA != 1 {
		t.Errorf("expected exactly 1 managed 'a' record, got %d", managedA)
	}

	s2 := zoneSerial(text)
	if err := f2.Sync(); err != nil {
		t.Fatal(err)
	}
	raw3, _ := os.ReadFile(fp)
	if string(raw3) != text {
		t.Error("second sync rewrote unchanged file")
	}
	if zoneSerial(string(raw3)) != s2 {
		t.Error("serial bumped without changes")
	}
}
