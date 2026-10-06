// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package parsers

import "github.com/nfrastack/herald/internal/input/common"

type StructuredFile struct {
	Metadata StructuredMetadata          `json:"metadata" yaml:"metadata"`
	Domains  map[string]StructuredDomain `json:"domains" yaml:"domains"`
}

type StructuredMetadata struct {
	Generator   string `json:"generator" yaml:"generator"`
	GeneratedAt string `json:"generated_at" yaml:"generated_at"`
	LastUpdated string `json:"last_updated" yaml:"last_updated"`
}

type StructuredDomain struct {
	Comment string             `json:"comment" yaml:"comment"`
	Records []StructuredRecord `json:"records" yaml:"records"`
}

type StructuredRecord struct {
	Hostname  string `json:"hostname" yaml:"hostname"`
	Type      string `json:"type" yaml:"type"`
	Target    string `json:"target" yaml:"target"`
	TTL       int    `json:"ttl" yaml:"ttl"`
	CreatedAt string `json:"created_at" yaml:"created_at"`
	Source    string `json:"source" yaml:"source"`
}

func convertStructuredToFileRecords(file StructuredFile) ([]common.FileRecord, error) {
	var records []common.FileRecord

	for domainName, domain := range file.Domains {
		for _, record := range domain.Records {
			fqdn := record.Hostname
			if record.Hostname == "@" {
				fqdn = domainName
			} else if record.Hostname != "" {
				fqdn = record.Hostname + "." + domainName
			} else {
				fqdn = domainName
			}

			fileRecord := common.FileRecord{
				Host:   fqdn,
				Type:   record.Type,
				Target: record.Target,
				TTL:    record.TTL,
			}

			records = append(records, fileRecord)
		}
	}

	return records, nil
}
