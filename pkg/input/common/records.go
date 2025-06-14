// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"encoding/json"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// DNSEntry represents a DNS entry from input providers - local definition to avoid import cycle
type DNSEntry struct {
	Name                   string `json:"name"`
	Hostname               string `json:"hostname"`
	Domain                 string `json:"domain"`
	RecordType             string `json:"type"`
	Target                 string `json:"target"`
	TTL                    int    `json:"ttl"`
	Overwrite              bool   `json:"overwrite"`
	RecordTypeAMultiple    bool   `json:"record_type_a_multiple"`
	RecordTypeAAAAMultiple bool   `json:"record_type_aaaa_multiple"`
	SourceName             string `json:"source_name"`
}

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
	// First try the Herald YAML format with metadata/domains structure
	var heraldMetadataFormat struct {
		Metadata map[string]interface{} `yaml:"metadata"`
		Domains  map[string]struct {
			Comment string `yaml:"comment"`
			Records []struct {
				Hostname  string `yaml:"hostname"`
				Type      string `yaml:"type"`
				Target    string `yaml:"target"`
				TTL       int    `yaml:"ttl"`
				CreatedAt string `yaml:"created_at"`
				Source    string `yaml:"source"`
			} `yaml:"records"`
		} `yaml:"domains"`
	}

	if err := yaml.Unmarshal(data, &heraldMetadataFormat); err == nil && len(heraldMetadataFormat.Domains) > 0 {
		// Successfully parsed as Herald metadata/domains format
		var records []FileRecord
		for domain, domainData := range heraldMetadataFormat.Domains {
			for _, hr := range domainData.Records {
				host := hr.Hostname + "." + domain
				// Handle root domain
				if hr.Hostname == "@" || hr.Hostname == "" {
					host = domain
				}

				record := FileRecord{
					Host:   host,
					Type:   hr.Type,
					Target: hr.Target,
					TTL:    hr.TTL,
				}
				records = append(records, record)
			}
		}
		return records, nil
	}

	// Try the Herald YAML format (simple records array)
	var heraldSimpleFormat struct {
		Records []struct {
			Domain   string `yaml:"domain"`
			Hostname string `yaml:"hostname"`
			Target   string `yaml:"target"`
			Type     string `yaml:"type"`
			TTL      int    `yaml:"ttl"`
			Source   string `yaml:"source"`
		} `yaml:"records"`
	}

	if err := yaml.Unmarshal(data, &heraldSimpleFormat); err == nil && len(heraldSimpleFormat.Records) > 0 {
		// Successfully parsed as Herald simple format
		var records []FileRecord
		for _, hr := range heraldSimpleFormat.Records {
			host := hr.Hostname + "." + hr.Domain
			// Handle root domain
			if hr.Hostname == "@" || hr.Hostname == "" {
				host = hr.Domain
			}

			record := FileRecord{
				Host:   host,
				Type:   hr.Type,
				Target: hr.Target,
				TTL:    hr.TTL,
			}
			records = append(records, record)
		}
		return records, nil
	}

	// Fallback to existing unified file format
	return ParseUnifiedFile(data, true)
}

func ParseRecordsJSON(data []byte) ([]FileRecord, error) {
	// First try the Herald JSON format with metadata/domains structure
	var heraldMetadataFormat struct {
		Metadata map[string]interface{} `json:"metadata"`
		Domains  map[string]struct {
			Comment string `json:"comment"`
			Records []struct {
				Hostname  string `json:"hostname"`
				Type      string `json:"type"`
				Target    string `json:"target"`
				TTL       int    `json:"ttl"`
				CreatedAt string `json:"created_at"`
				Source    string `json:"source"`
			} `json:"records"`
		} `json:"domains"`
	}

	if err := json.Unmarshal(data, &heraldMetadataFormat); err == nil && len(heraldMetadataFormat.Domains) > 0 {
		// Successfully parsed as Herald metadata/domains format
		var records []FileRecord
		for domain, domainData := range heraldMetadataFormat.Domains {
			for _, hr := range domainData.Records {
				host := hr.Hostname + "." + domain
				// Handle root domain
				if hr.Hostname == "@" || hr.Hostname == "" {
					host = domain
				}

				record := FileRecord{
					Host:   host,
					Type:   hr.Type,
					Target: hr.Target,
					TTL:    hr.TTL,
				}
				records = append(records, record)
			}
		}
		return records, nil
	}

	// Try the Herald JSON format (simple array of records)
	var heraldRecords []struct {
		Domain   string `json:"domain"`
		Hostname string `json:"hostname"`
		Target   string `json:"target"`
		Type     string `json:"type"`
		TTL      int    `json:"ttl"`
		Source   string `json:"source"`
	}

	if err := json.Unmarshal(data, &heraldRecords); err == nil && len(heraldRecords) > 0 {
		// Successfully parsed as Herald simple array format
		var records []FileRecord
		for _, hr := range heraldRecords {
			host := hr.Hostname + "." + hr.Domain
			// Handle root domain
			if hr.Hostname == "@" || hr.Hostname == "" {
				host = hr.Domain
			}

			record := FileRecord{
				Host:   host,
				Type:   hr.Type,
				Target: hr.Target,
				TTL:    hr.TTL,
			}
			records = append(records, record)
		}
		return records, nil
	}

	// Fallback to existing unified file format
	return ParseUnifiedFile(data, false)
}

func ConvertRecordsToDNSEntries(records []FileRecord, providerName string) []DNSEntry {
	var entries []DNSEntry
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
		entry := DNSEntry{
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
