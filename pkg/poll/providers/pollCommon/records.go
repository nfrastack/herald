// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"dns-companion/pkg/poll"

	"encoding/json"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

type FileRecord struct {
	Host   string `yaml:"host" json:"host"`
	Type   string `yaml:"type" json:"type"`
	TTL    int    `yaml:"ttl" json:"ttl"`
	Target string `yaml:"target" json:"target"`
}

type YamlFile struct {
	Records []FileRecord `yaml:"records"`
}

type JsonFile struct {
	Records []FileRecord `json:"records"`
}

type FileMetadata struct {
	Generator   string `yaml:"generator" json:"generator"`
	GeneratedAt string `yaml:"generated_at" json:"generated_at"`
	LastUpdated string `yaml:"last_updated" json:"last_updated"`
}

type DomainRecord struct {
	Hostname  string `yaml:"hostname" json:"hostname"`
	Type      string `yaml:"type" json:"type"`
	Target    string `yaml:"target" json:"target"`
	TTL       int    `yaml:"ttl" json:"ttl"`
	CreatedAt string `yaml:"created_at" json:"created_at"`
	Source    string `yaml:"source" json:"source"`
}

type DomainBlock struct {
	Comment string         `yaml:"comment" json:"comment"`
	Records []DomainRecord `yaml:"records" json:"records"`
}

type UnifiedFile struct {
	Records  []FileRecord           `yaml:"records" json:"records"`
	Metadata *FileMetadata          `yaml:"metadata" json:"metadata"`
	Domains  map[string]DomainBlock `yaml:"domains" json:"domains"`
}

// ParseUnifiedFile parses the new YAML/JSON structure and returns a flat list of FileRecord
func ParseUnifiedFile(data []byte, isYAML bool) ([]FileRecord, error) {
	var uf UnifiedFile
	var err error
	if isYAML {
		err = yaml.Unmarshal(data, &uf)
	} else {
		err = json.Unmarshal(data, &uf)
	}
	if err != nil {
		return nil, err
	}
	var out []FileRecord
	// Top-level records
	for _, r := range uf.Records {
		out = append(out, r)
	}
	// Domain records
	for domain, block := range uf.Domains {
		for _, dr := range block.Records {
			fqdn := dr.Hostname
			if fqdn == "@" || fqdn == "" {
				fqdn = domain
			} else {
				fqdn = dr.Hostname + "." + domain
			}
			rec := FileRecord{
				Host:   fqdn,
				Type:   dr.Type,
				TTL:    dr.TTL,
				Target: dr.Target,
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

func ParseRecordsYAML(data []byte) ([]FileRecord, error) {
	return ParseUnifiedFile(data, true)
}

func ParseRecordsJSON(data []byte) ([]FileRecord, error) {
	return ParseUnifiedFile(data, false)
}

func ConvertRecordsToDNSEntries(records []FileRecord, providerName string) []poll.DNSEntry {
	var entries []poll.DNSEntry
	for _, r := range records {
		if r.Host == "" || r.Target == "" {
			continue
		}
		fqdn := strings.TrimSuffix(r.Host, ".")
		recordType := r.Type
		if recordType == "" {
			if ip := net.ParseIP(r.Target); ip != nil {
				if ip.To4() != nil {
					recordType = "A"
				} else {
					recordType = "AAAA"
				}
			} else {
				recordType = "CNAME"
			}
		}
		entry := poll.DNSEntry{
			Hostname:   fqdn,
			Domain:     "",
			RecordType: recordType,
			Target:     r.Target,
			TTL:        r.TTL,
			Overwrite:  true,
			SourceName: providerName,
		}
		entries = append(entries, entry)
	}
	return entries
}
