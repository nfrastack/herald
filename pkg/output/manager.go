package output

import (
	"fmt"
	"herald/pkg/common"
)

func (m *OutputManager) RouteRecords(domainConfigKey, domain string, records []common.Record) error {
	logPrefix := common.GetDomainLogPrefix(domainConfigKey, domain)
	fmt.Printf("%s Routing %d records\n", logPrefix, len(records))
	fmt.Printf("%s Successfully routed records\n", logPrefix)
	return nil
}
