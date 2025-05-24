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

func ParseRecordsYAML(data []byte) ([]FileRecord, error) {
	var y YamlFile
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, err
	}
	return y.Records, nil
}

func ParseRecordsJSON(data []byte) ([]FileRecord, error) {
	var j JsonFile
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return j.Records, nil
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
