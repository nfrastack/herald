package common

import (
	"fmt"
	"strings"
)

// GetDomainLogPrefix returns a log prefix in the format [domain/domainKey/domain_name]
func GetDomainLogPrefix(domainConfigKey, domain string) string {
	if domainConfigKey != "" {
		return fmt.Sprintf("[domain/%s/%s]", domainConfigKey, strings.ReplaceAll(domain, ".", "_"))
	}
	return fmt.Sprintf("[domain/%s]", strings.ReplaceAll(domain, ".", "_"))
}
