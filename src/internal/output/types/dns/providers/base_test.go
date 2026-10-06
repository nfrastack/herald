// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"testing"
)

func TestBuildFQDN(t *testing.T) {
	cases := []struct{ host, domain, want string }{
		{"@", "example.com", "example.com"},
		{"", "example.com", "example.com"},
		{"www", "example.com", "www.example.com"},
		{"www.example.com", "example.com", "www.example.com"},
		{"example.com", "example.com", "example.com"},
	}
	for _, c := range cases {
		if got := BuildFQDN(c.host, c.domain); got != c.want {
			t.Errorf("BuildFQDN(%q, %q) = %q, want %q", c.host, c.domain, got, c.want)
		}
	}
}

func TestRelativeName(t *testing.T) {
	cases := []struct{ host, domain, want string }{
		{"@", "example.com", "@"},
		{"", "example.com", "@"},
		{"www", "example.com", "www"},
		{"www.example.com", "example.com", "www"},
	}
	for _, c := range cases {
		if got := RelativeName(c.host, c.domain); got != c.want {
			t.Errorf("RelativeName(%q, %q) = %q, want %q", c.host, c.domain, got, c.want)
		}
	}
}

func TestRegistryCompleteness(t *testing.T) {
	want := []string{
		"cloudflare", "powerdns",
		"digitalocean", "hetzner", "porkbun", "linode", "ovh",
		"gandi", "vultr", "spaceship", "easydns", "technitium",
		"route53", "google", "azure", "godaddy", "external",
	}
	available := dns.GetAvailableProviders()
	have := make(map[string]bool, len(available))
	for _, name := range available {
		have[name] = true
	}
	for _, name := range want {
		if !have[name] {
			t.Errorf("provider %q not registered", name)
		}
	}
}

func TestConstructorsRejectEmptyCredentials(t *testing.T) {
	constructors := map[string]func(map[string]string) (interface{}, error){
		"cloudflare":   NewCloudflareProvider,
		"digitalocean": NewDigitalOceanProvider,
		"hetzner":      NewHetznerProvider,
		"porkbun":      NewPorkbunProvider,
		"linode":       NewLinodeProvider,
		"ovh":          NewOVHProvider,
		"gandi":        NewGandiProvider,
		"vultr":        NewVultrProvider,
		"spaceship":    NewSpaceshipProvider,
		"easydns":      NewEasyDNSProvider,
		"technitium":   NewTechnitiumProvider,
		"route53":      NewRoute53Provider,
		"google":       NewGoogleDNSProvider,
		"azure":        NewAzureDNSProvider,
		"godaddy":      NewGoDaddyProvider,
		"external":     NewExternalProvider,
	}
	for name, fn := range constructors {
		if _, err := fn(map[string]string{}); err == nil {
			t.Errorf("provider %q accepted empty credentials", name)
		}
	}
}
