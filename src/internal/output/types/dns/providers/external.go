// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package providers

import (
	"github.com/nfrastack/herald/internal/output/types/dns"
	"github.com/nfrastack/herald/internal/util"

	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

type ExternalProvider struct {
	*BaseProvider
	command []string
	env     []string
}

func NewExternalProvider(config map[string]string) (interface{}, error) {
	base := NewBaseProvider("external", config["profile_name"], config)

	command := base.Option("command", "")
	if command == "" {
		return nil, fmt.Errorf("external provider requires 'command' parameter")
	}
	if !strings.HasPrefix(command, "/") {
		return nil, fmt.Errorf("external provider 'command' must be an absolute path")
	}

	argv := []string{command}
	for i := 0; ; i++ {
		key := "args." + strconv.Itoa(i)
		raw, ok := config[key]
		if !ok {
			raw, ok = config["options."+key]
		}
		if !ok {
			break
		}
		argv = append(argv, util.ReadSecretValue(raw))
	}

	var names []string
	for k := range config {
		if strings.HasPrefix(k, "env.") {
			names = append(names, strings.TrimPrefix(k, "env."))
		} else if strings.HasPrefix(k, "options.env.") {
			names = append(names, strings.TrimPrefix(k, "options.env."))
		}
	}
	sort.Strings(names)
	var env []string
	for _, name := range names {
		if v := base.Option("env."+name, ""); v != "" {
			env = append(env, name+"="+v)
		}
	}

	return &ExternalProvider{BaseProvider: base, command: argv, env: env}, nil
}

func init() {
	dns.RegisterProvider("external", NewExternalProvider)
}

func (p *ExternalProvider) GetName() string {
	return "external"
}

func (p *ExternalProvider) SupportsProxied() bool {
	return false
}

func (p *ExternalProvider) substitute(arg, action, domain, name, fqdn, recordType, target string, ttl int, source, comment string) (string, error) {
	out := arg
	out = strings.ReplaceAll(out, "{action}", action)
	out = strings.ReplaceAll(out, "{domain}", domain)
	out = strings.ReplaceAll(out, "{zone}", domain)
	out = strings.ReplaceAll(out, "{name}", name)
	out = strings.ReplaceAll(out, "{hostname}", name)
	out = strings.ReplaceAll(out, "{fqdn}", fqdn)
	out = strings.ReplaceAll(out, "{type}", recordType)
	out = strings.ReplaceAll(out, "{target}", target)
	out = strings.ReplaceAll(out, "{ttl}", strconv.Itoa(ttl))
	out = strings.ReplaceAll(out, "{source}", source)
	out = strings.ReplaceAll(out, "{comment}", comment)
	out = strings.ReplaceAll(out, "{profile}", p.ProfileName)
	if strings.Contains(out, "{") && strings.Contains(out, "}") {
		return "", fmt.Errorf("external provider argument contains unknown placeholder: %s", arg)
	}
	return out, nil
}

func (p *ExternalProvider) run(action, domain, recordType, hostname, target string, ttl int, source, comment string) error {
	name := RelativeName(hostname, domain)
	fqdn := BuildFQDN(hostname, domain)

	argv := make([]string, 0, len(p.command))
	for _, arg := range p.command[1:] {
		sub, err := p.substitute(arg, action, domain, name, fqdn, recordType, target, ttl, source, comment)
		if err != nil {
			return err
		}
		argv = append(argv, sub)
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, p.command[0], argv...)
	cmd.Env = append(os.Environ(), p.env...)

	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("external provider command timed out after %v", p.Timeout)
	}
	if err != nil {
		text := strings.TrimSpace(string(out))
		if len(text) > 512 {
			text = text[:512]
		}
		return fmt.Errorf("external provider command failed: %v: %s", err, text)
	}
	return nil
}

func (p *ExternalProvider) CreateOrUpdateRecord(domain, recordType, hostname, target string, ttl int, proxied bool, overwrite bool) error {
	return p.CreateOrUpdateRecordWithSource(domain, recordType, hostname, target, ttl, proxied, "", "herald", overwrite)
}

func (p *ExternalProvider) CreateOrUpdateRecordWithSource(domain, recordType, hostname, target string, ttl int, proxied bool, comment, source string, overwrite bool) error {
	return p.run("upsert", domain, recordType, hostname, target, ttl, source, comment)
}

func (p *ExternalProvider) DeleteRecord(domain, recordType, hostname string) error {
	return p.run("delete", domain, recordType, hostname, "", 0, "", "")
}

func (p *ExternalProvider) Validate() error {
	if _, err := exec.LookPath(p.command[0]); err != nil {
		return fmt.Errorf("external provider command not executable: %v", err)
	}
	return nil
}
