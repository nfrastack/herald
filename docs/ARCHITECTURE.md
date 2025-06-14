# DNS Companion - High-Level Architecture Overview

## Overview at a Glance

DNS Companion is a dynamic DNS management system that automatically discovers services and creates/updates DNS records across multiple providers. The application follows a modular architecture with five main component types that work together:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Poll Providers │───▶│   Filters       │───▶│ Domain Config   │
│                 │    │                 │    │                 │
│ • Docker        │    │ • Type-based    │    │ • Provider      │
│ • Traefik       │    │ • Value-based   │    │   Selection     │
│ • Tailscale     │    │ • Pattern       │    │ • Record Config │
│ • ZeroTier      │    │   Matching      │    │ • TTL/Type      │
│ • File/Remote   │    │ • Boolean Logic │    │                 │
│ • Caddy         │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       ▼
         │                       │            ┌─────────────────┐
         │                       │            │  DNS Providers  │
         │                       │            │                 │
         │                       │            │ • Cloudflare    │
         │                       │            │ • Custom        │
         │                       │            │                 │
         │                       │            └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Core Processing Engine                       │
│                                                                 │
│ • Service Discovery → Filtering → Domain Matching → DNS Ops     │
│ • Batch Processing for Efficiency                               │
│ • Change Detection and Logging                                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌─────────────────┐
                    │ Output Providers│
                    │                 │
                    │ • /etc/hosts    │
                    │ • JSON Export   │
                    │ • YAML Export   │
                    │ • Zone Files    │
                    └─────────────────┘
```

## Component Breakdown

### 1. Poll Providers - Service Discovery

Poll providers continuously monitor different systems to discover services that need DNS records:

**Types:**
- **Docker**: Monitors container labels and Traefik routes
- **Traefik**: Polls Traefik API for router configurations
- **Tailscale**: Monitors Tailscale/Headscale networks for devices
- **ZeroTier**: Tracks ZeroTier network members
- **File**: Watches local files for DNS record definitions
- **Remote**: Fetches DNS records from remote HTTP endpoints
- **Caddy**: Monitors Caddy API for configured routes

**Key Features:**
- **Polling Intervals**: Configurable timing for each provider
- **Initial Processing**: Handle existing services on startup
- **Change Detection**: Only process actual changes to reduce load
- **Scoped Logging**: Provider-specific log levels and prefixes

### 2. Filters - Service Selection

Filters determine which discovered services should have DNS records created:

**Filter Types:**
- **online**: Service/device online status
- **name**: Service name pattern matching
- **tag**: Service tags or labels
- **authorized**: Authorization status (VPN providers)
- **Custom**: Provider-specific filters

**Operations:**
- **equals**: Exact matching
- **contains**: Substring matching
- **regex**: Regular expression matching
- **Boolean Logic**: AND/OR combinations with negation

**Examples:**
```yaml
# Only online Tailscale devices
filter_type: online
filter_value: "true"

# Docker containers with specific labels
filter_type: label
filter_value: "traefik.enable=true"
```

### 3. Domain Configuration - DNS Mapping

Domain configurations define how discovered services map to DNS records:

**Components:**
- **Provider Selection**: Which DNS provider handles this domain
- **Record Configuration**: DNS record type (A, AAAA, CNAME), TTL
- **Subdomain Handling**: Include/exclude specific subdomains
- **Target Resolution**: How to determine the DNS record target

**Domain Matching Logic:**
```
Service FQDN: app.production.example.com
Domain Config: example.com
Result: Subdomain = "app.production", Domain = "example.com"
```

### 4. DNS Providers - Record Management

DNS providers handle the actual creation, update, and deletion of DNS records:

**Current Providers:**
- **Cloudflare**: Full API integration with zone management
- **Extensible**: Framework for adding new providers

**Features:**
- **Lazy Initialization**: Connect only when needed
- **Change Detection**: Only update when records actually change
- **Conflict Resolution**: Handle competing record types
- **Error Handling**: Graceful failure and retry logic

### 5. Output Providers - File Export

Output providers export DNS records to various file formats for local consumption:

**Formats:**
- **Hosts**: Traditional hosts file format
- **JSON**: Structured data for APIs
- **YAML**: Human-readable configuration
- **Zone Files**: RFC1035 compliant zone files

**Features:**
- **Selective Export**: Choose which domains to include
- **File Permissions**: Set ownership and permissions
- **Atomic Updates**: Safe file replacement
- **Change-Based Sync**: Only write when data changes

## Data Flow Architecture

### 1. Discovery Phase
```
Poll Provider → Service Discovery → Raw Service Data
```
- Each poll provider discovers services using its specific method
- Services include hostname, IP address, labels/metadata
- Data is normalized into a common `DNSEntry` format

### 2. Filtering Phase
```
Raw Service Data → Filters → Filtered Services
```
- Apply configured filters to determine which services need DNS
- Multiple filters can be combined with AND/OR logic
- Services that don't match filters are ignored

### 3. Domain Mapping Phase
```
Filtered Services → Domain Configuration → DNS Operations
```
- Extract domain from service FQDN using domain configs
- Determine which DNS provider and configuration to use
- Resolve target IP address and record type

### 4. DNS Operations Phase
```
DNS Operations → DNS Provider → Live DNS Records
```
- Create, update, or delete DNS records as needed
- Batch operations for efficiency
- Track changes and provide detailed logging

### 5. Output Phase
```
DNS Operations → Output Providers → Files
```
- Export DNS records to configured file formats
- Only sync files when actual changes occur
- Maintain file permissions and atomic updates

## Configuration Hierarchy

The application supports multiple configuration methods with a clear precedence:

```
Environment Variables > YAML Config > Defaults
```

### Poll Provider Configuration
```yaml
polls:
  docker_prod:
    type: docker
    api_url: "unix:///var/run/docker.sock"
    interval: 30s
    filter_type: label
    filter_value: "traefik.enable=true"
    log_level: debug
```

### DNS Provider Configuration
```yaml
providers:
  cloudflare_main:
    type: cloudflare
    api_token: "your-token"
    zone_id: "optional"
```

### Domain Configuration
```yaml
domains:
  example_com:
    name: "example.com"
    provider: "cloudflare_main"
    record:
      type: "A"
      ttl: 300
    exclude_subdomains:
      - dev
      - staging
```

## Advanced Features

### Batch Processing
- **Efficiency**: Group multiple DNS operations together
- **Atomic Updates**: All changes in a batch succeed or fail together
- **Output Sync**: Only write output files when batches complete with changes

### Change Detection
- **Smart Diffing**: Only process services that have actually changed
- **Target Tracking**: Detect IP address changes for existing services
- **Removal Handling**: Clean up DNS records when services disappear

### Logging Architecture
- **Scoped Loggers**: Each provider has its own logger with configurable levels
- **Structured Messages**: Consistent format with source identification
- **Debug Tracing**: Detailed operation tracking for troubleshooting

### Error Handling
- **Graceful Degradation**: Continue processing other services if one fails
- **Retry Logic**: Built-in retry for transient failures
- **Validation**: Comprehensive input validation and error reporting

## Extensibility

The architecture is designed for easy extension:

### Adding New Poll Providers
1. Implement the `poll.Provider` interface
2. Register with `poll.RegisterProvider()`
3. Follow common patterns for configuration and logging

### Adding New DNS Providers
1. Implement the `dns.Provider` interface
2. Register with `dns.RegisterProvider()`
3. Support common configuration patterns

### Adding New Output Formats
1. Implement output format in the output manager
2. Add configuration options
3. Follow atomic update patterns

This modular design allows DNS Companion to adapt to new services, DNS providers, and use cases while maintaining a consistent and reliable core architecture.