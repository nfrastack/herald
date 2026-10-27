// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"

	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	dnsmsg "github.com/miekg/dns"
)

type RFC2136Provider struct {
	*BaseProvider
	server    string
	keyName   string
	keySecret string
	keyAlgo   string
	mu        sync.Mutex
	verified  map[string]bool
}

func NewRFC2136Provider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("rfc2136", config["profile_name"], config)

	server := strings.TrimSpace(base.Option("server", "127.0.0.1:53"))
	if server == "" {
		return nil, fmt.Errorf("rfc2136 provider requires 'server' parameter")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}

	keyName := strings.TrimSpace(base.Option("key_name", ""))
	keySecret := base.Secret("key_secret", "key", "api_token")
	keyAlgo := strings.ToLower(strings.TrimSpace(base.Option("key_algorithm", "hmac-sha256")))
	switch keyAlgo {
	case "hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-md5":
	default:
		return nil, fmt.Errorf("rfc2136 unsupported key_algorithm '%s': want hmac-sha256, hmac-sha384, hmac-sha512, or hmac-md5", keyAlgo)
	}
	if keyName != "" {
		if !strings.HasSuffix(keyName, ".") {
			keyName += "."
		}
		if !strings.HasSuffix(keyAlgo, ".") {
			keyAlgo += "."
		}
		if keySecret == "" {
			return nil, fmt.Errorf("rfc2136 'key_name' requires a matching 'key_secret'")
		}
		if _, err := base64.StdEncoding.DecodeString(keySecret); err != nil {
			if _, err2 := base64.URLEncoding.DecodeString(keySecret); err2 != nil {
				return nil, fmt.Errorf("rfc2136 'key_secret' is not valid base64")
			}
		}
	}

	return &RFC2136Provider{
		BaseProvider: base,
		server:       server,
		keyName:      keyName,
		keySecret:    keySecret,
		keyAlgo:      keyAlgo,
		verified:     make(map[string]bool),
	}, nil
}

func init() {
	dns.RegisterProvider("rfc2136", NewRFC2136Provider)
}

func (p *RFC2136Provider) GetName() string {
	return "rfc2136"
}

func (p *RFC2136Provider) SupportsProxied() bool {
	return false
}

func rfc2136FQDN(name, domain string) string {
	if name == "" || name == "@" {
		return strings.TrimSuffix(domain, ".") + "."
	}
	fqdn := BuildFQDN(name, domain)
	return strings.TrimSuffix(fqdn, ".") + "."
}

func rfc2136RData(recordType, target, domain string) (string, error) {
	switch recordType {
	case "A", "AAAA":
		if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
			return ip.String(), nil
		}
		return "", fmt.Errorf("rfc2136 %s target '%s' is not a valid IP address", recordType, target)
	case "CNAME":
		t := strings.TrimSpace(target)
		if t == "" || t == "@" {
			return rfc2136FQDN("", domain), nil
		}
		if ip := net.ParseIP(strings.Trim(t, "[]")); ip != nil {
			return "", fmt.Errorf("rfc2136 CNAME target '%s' must be a hostname, not an IP address", target)
		}
		return rfc2136FQDN(t, domain), nil
	default:
		return "", fmt.Errorf("rfc2136 unsupported record type '%s': want A, AAAA, or CNAME", recordType)
	}
}

func (p *RFC2136Provider) newClient() *dnsmsg.Client {
	c := &dnsmsg.Client{Net: "tcp", Timeout: p.Timeout}
	if p.keyName != "" {
		c.TsigSecret = map[string]string{p.keyName: p.keySecret}
	}
	return c
}

func (p *RFC2136Provider) sign(m *dnsmsg.Msg) {
	if p.keyName == "" {
		return
	}
	m.SetTsig(p.keyName, p.keyAlgo, 300, time.Now().Unix())
}

func (p *RFC2136Provider) ensureAuthoritative(zone string) error {
	p.mu.Lock()
	if p.verified[zone] {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	m := new(dnsmsg.Msg)
	m.SetQuestion(zone, dnsmsg.TypeSOA)
	p.sign(m)
	resp, _, err := p.newClient().Exchange(m, p.server)
	if err != nil {
		return fmt.Errorf("rfc2136 authority check for %s failed: %v", zone, err)
	}
	if resp == nil || resp.Rcode != dnsmsg.RcodeSuccess {
		return fmt.Errorf("rfc2136 authority check for %s failed: %s", zone, dnsmsg.RcodeToString[resp.Rcode])
	}
	for _, ans := range resp.Answer {
		if _, ok := ans.(*dnsmsg.SOA); ok {
			p.mu.Lock()
			p.verified[zone] = true
			p.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("rfc2136 server is not authoritative for zone %s", zone)
}

func (p *RFC2136Provider) update(zone string, remove []dnsmsg.RR, add []dnsmsg.RR) error {
	m := new(dnsmsg.Msg)
	m.SetUpdate(zone)
	m.RemoveRRset(remove)
	m.Insert(add)

	var lastErr error
	for attempt := 0; attempt < p.Retries; attempt++ {
		p.sign(m)
		resp, _, err := p.newClient().Exchange(m, p.server)
		if err != nil {
			lastErr = err
			p.Logger.With("action", "provider.retry").Debug("update attempt %d failed: %v", attempt+1, err)
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("empty response")
			continue
		}
		if resp.Rcode != dnsmsg.RcodeSuccess {
			return fmt.Errorf("rfc2136 update rejected: %s", dnsmsg.RcodeToString[resp.Rcode])
		}
		return nil
	}
	return fmt.Errorf("rfc2136 update failed after %d attempts: %v", p.Retries, lastErr)
}

func rfc2136RemoveRRSet(fqdn, recordType string) (dnsmsg.RR, error) {
	var rtype uint16
	switch recordType {
	case "A":
		rtype = dnsmsg.TypeA
	case "AAAA":
		rtype = dnsmsg.TypeAAAA
	case "CNAME":
		rtype = dnsmsg.TypeCNAME
	default:
		return nil, fmt.Errorf("rfc2136 cannot remove unsupported type '%s'", recordType)
	}
	return &dnsmsg.ANY{Hdr: dnsmsg.RR_Header{Name: fqdn, Ttl: 0, Rrtype: rtype, Class: dnsmsg.ClassANY}}, nil
}

func (p *RFC2136Provider) upsert(domain, recordType, name, target string, ttl int) error {
	zone := rfc2136FQDN("", domain)
	if err := p.ensureAuthoritative(zone); err != nil {
		return err
	}
	fqdn := rfc2136FQDN(name, domain)
	rdata, err := rfc2136RData(recordType, target, domain)
	if err != nil {
		return err
	}
	rr, err := dnsmsg.NewRR(fmt.Sprintf("%s %d IN %s %s", fqdn, ttl, recordType, rdata))
	if err != nil {
		return fmt.Errorf("rfc2136 failed to build %s record: %v", recordType, err)
	}
	var remove []dnsmsg.RR
	for _, t := range []string{"A", "AAAA", "CNAME"} {
		rrRemove, err := rfc2136RemoveRRSet(fqdn, t)
		if err != nil {
			return err
		}
		remove = append(remove, rrRemove)
	}
	if err := p.update(zone, remove, []dnsmsg.RR{rr}); err != nil {
		return err
	}
	p.Logger.With("action", "record.sync").Debug("upsert %s %s -> %s", name, recordType, target)
	return nil
}

func (p *RFC2136Provider) CreateOrUpdateRecord(domain, recordType, name, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, name, target, ttl, proxied, "", "herald", overwrite)
}

func (p *RFC2136Provider) CreateOrUpdateRecordWithSource(domain, recordType, name, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	_ = comment
	_ = overwrite
	if err := p.upsert(domain, recordType, name, target, ttl); err != nil {
		p.Logger.With("action", "record.sync", "source", source).Warn("upsert %s.%s %s failed: %v", name, domain, recordType, err)
		return err
	}
	return nil
}

func (p *RFC2136Provider) DeleteRecord(domain, recordType, name string) error {
	zone := rfc2136FQDN("", domain)
	if err := p.ensureAuthoritative(zone); err != nil {
		return err
	}
	fqdn := rfc2136FQDN(name, domain)
	rr, err := rfc2136RemoveRRSet(fqdn, recordType)
	if err != nil {
		return err
	}
	if err := p.update(zone, []dnsmsg.RR{rr}, nil); err != nil {
		p.Logger.With("action", "record.delete").Warn("delete %s.%s %s failed: %v", name, domain, recordType, err)
		return err
	}
	p.Logger.With("action", "record.delete").Debug("delete %s.%s %s", name, domain, recordType)
	return nil
}

func (p *RFC2136Provider) Validate() error {
	conn, err := net.DialTimeout("tcp", p.server, 5*time.Second)
	if err != nil {
		return fmt.Errorf("rfc2136 cannot reach server %s: %v", p.server, err)
	}
	_ = conn.Close()
	return nil
}
