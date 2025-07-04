# DNS Provider Implementation Guide

This guide walks you through implementing a new DNS provider for Herald. Use the template in `dns_provider_template.go` as your starting point.

## Quick Start Checklist

- [ ] Copy `dns_provider_template.go` to `dns_YOURPROVIDER_implementation.go`
- [ ] Replace all instances of "PROVIDER" with your provider name (e.g., "route53", "digitalocean")
- [ ] Update API endpoints and authentication
- [ ] Implement the API methods for your provider
- [ ] Register your provider in `output.go`
- [ ] Test with real API calls
- [ ] Document configuration requirements

## Step-by-Step Implementation

### 1. Initial Setup

```bash
# Copy the template
cp pkg/output/dns_provider_template.go pkg/output/dns_yourprovider.go

# Edit the file and replace "PROVIDER" with your provider name
sed -i 's/PROVIDER/yourprovider/g' pkg/output/dns_yourprovider.go
```

### 2. Provider Research

Before implementing, gather this information about your DNS provider:

**API Documentation:**
- Base API URL (e.g., `https://api.yourprovider.com`)
- Authentication method (API token, API key, OAuth, etc.)
- Rate limiting rules
- Supported record types

**Required Information:**
- How to authenticate (headers, query params, etc.)
- How to list domains/zones
- How to create DNS records
- How to update existing DNS records
- How to find existing records
- Error response formats

### 3. Authentication Implementation

Choose the appropriate authentication method:

#### API Token (Recommended)
```go
req.Header.Set("Authorization", "Bearer "+p.apiToken)
```

#### API Key
```go
req.Header.Set("X-API-Key", p.apiKey)
```

#### Basic Auth
```go
req.SetBasicAuth(p.username, p.password)
```

#### Custom Headers
```go
req.Header.Set("X-Auth-Token", p.authToken)
req.Header.Set("X-Auth-Email", p.email)
```

### 4. API Method Implementation

You need to implement these core methods:

#### getZoneID() - Required if provider uses zones
- Input: domain name (e.g., "example.com")
- Output: zone/domain ID from provider
- Purpose: Get the provider's internal ID for the domain

#### findExistingRecord() - Required
- Input: zone ID and DNS record details
- Output: existing record ID (if found)
- Purpose: Check if a record already exists to decide create vs update

#### createRecord() - Required
- Input: zone ID and DNS record details
- Output: success/error
- Purpose: Create a new DNS record

#### updateRecord() - Required
- Input: zone ID, record ID, and new DNS record details
- Output: success/error
- Purpose: Update an existing DNS record

### 5. Provider-Specific Considerations

#### API Endpoints
Replace these template URLs with your provider's actual endpoints:
```go
// Template
"https://api.PROVIDER.com/v1/domains"

// Examples
"https://api.digitalocean.com/v2/domains"           // DigitalOcean
"https://api.vultr.com/v2/domains"                 // Vultr
"https://dns.api.gandi.net/api/v5/domains"         // Gandi
"https://api.namecheap.com/xml.response"           // Namecheap
```

#### Record Name Handling
Different providers handle record names differently:

```go
// Full FQDN approach (Cloudflare style)
recordName := record.Hostname + "." + record.Domain

// Relative name approach (some providers)
recordName := record.Hostname
if record.Hostname == "@" {
    recordName = ""
}
```

#### TTL Handling
Some providers have restrictions:
```go
// Validate TTL range
if record.TTL < 300 {
    record.TTL = 300  // Minimum TTL
}
if record.TTL > 86400 {
    record.TTL = 86400  // Maximum TTL
}
```

### 6. Error Handling

Implement robust error handling:

```go
if resp.StatusCode != http.StatusOK {
    body, _ := io.ReadAll(resp.Body)

    // Parse provider-specific errors
    var errorResp struct {
        Error   string `json:"error"`
        Message string `json:"message"`
        Code    int    `json:"code"`
    }

    if err := json.Unmarshal(body, &errorResp); err == nil {
        return fmt.Errorf("provider error %d: %s", errorResp.Code, errorResp.Message)
    }

    // Fallback to raw response
    return fmt.Errorf("provider API error %d: %s", resp.StatusCode, string(body))
}
```

### 7. Registration

Add your provider to the registration function in `output.go`:

```go
// In registerAllCoreFormats() function, add:
RegisterFormat("dns/yourprovider", createYourProviderOutputDirect)
```

### 8. Configuration Schema

Document the required configuration for users:

```yaml
outputs:
  my_dns_provider:
    type: dns
    provider: yourprovider
    api_token: "env://YOURPROVIDER_API_TOKEN"
    # Add provider-specific options:
    # region: "us-east-1"          # If provider is region-specific
    # endpoint: "custom.api.url"   # If custom endpoints are supported
    # timeout: 30                  # If custom timeouts are needed
```

## Implemented Providers

Herald currently supports the following DNS providers:

### Cloudflare
- **Configuration**: `provider: cloudflare`
- **Authentication**: API token
- **Features**: Full DNS record management, proxied records
- **API**: Cloudflare API v4

### PowerDNS
- **Configuration**: `provider: powerdns`
- **Authentication**: API token (X-API-Key header)
- **Features**: Full DNS record management, TLS support
- **API**: PowerDNS API v1
- **TLS Options**: CA certificate, client certificates, skip verification

```yaml
# PowerDNS configuration example
powerdns_dns:
  type: dns
  provider: powerdns
  api_host: "http://powerdns.example.com:8081/api/v1"
  api_token: "your-powerdns-api-token"
  server_id: "localhost"  # Optional, defaults to "localhost"
  tls:
    ca: "/path/to/ca.pem"           # Optional CA certificate
    cert: "/path/to/client.pem"     # Optional client certificate
    key: "/path/to/client.key"      # Optional client private key
    skip_verify: false              # Optional, skip TLS verification
```

## Submission Checklist

Before submitting your implementation:

- [ ] All API methods implemented and tested
- [ ] Error handling covers common failure cases
- [ ] Configuration properly validated
- [ ] Provider registered in `output.go`
- [ ] Documentation updated with configuration example
- [ ] Integration tests pass with real API
- [ ] Code follows existing patterns and style
- [ ] No hardcoded credentials in code
- [ ] Rate limiting implemented if needed
- [ ] Logging follows Herald's patterns

## File Structure

Your implementation should result in these changes:

```
pkg/output/
├── output.go                    # Add registration line
├── dns_yourprovider.go         # Your implementation
└── dns_provider_template.go    # Template (reference)
```
