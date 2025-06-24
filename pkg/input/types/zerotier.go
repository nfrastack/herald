// Zerotier input provider code with added debug logs and validation for FQDN/domain extraction

// ...existing code...

// Before processing each member, log FQDN/domain extraction
fqdn := member.FQDN // or however the FQDN is constructed
log.Trace("[input/zerotier/%s] Extracting domain/subdomain from FQDN: '%s' (member: %s, id: %s)", providerName, fqdn, member.Name, member.ID)
domainKey, subdomain := ExtractDomainAndSubdomain(fqdn)
log.Trace("[input/zerotier/%s] Result: domainKey='%s', subdomain='%s' for FQDN='%s'", providerName, domainKey, subdomain, fqdn)
if fqdn == "" || domainKey == "" {
	log.Warn("[input/zerotier/%s] Skipping member '%s' (id: %s): FQDN or domainKey is empty (fqdn='%s', domainKey='%s')", providerName, member.Name, member.ID, fqdn, domainKey)
	continue
}

// ...existing code for processing member...