# Herald DNS Companion - Architecture

This document describes the architecture and design principles of Herald DNS Companion.

## Overview

Herald follows a **domain-centric, three-tier architecture** that separates service discovery, record routing, and DNS management into distinct, configurable layers.

## Core Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│  Input Sources  │───▶│   Domains    │───▶│    Outputs      │
└─────────────────┘    └──────────────┘    └─────────────────┘
│                 │    │              │    │                 │
│ • Docker        │    │ • Route      │    │ • DNS Providers │
│ • Traefik       │    │   inputs to  │    │ • File Formats  │
│ • Tailscale     │    │   outputs    │    │ • Remote APIs   │
│ • ZeroTier      │    │ • Filter     │    │                 │
│ • File sources  │    │   records    │    │                 │
│ • Remote APIs   │    │ • Transform  │    │                 │
│                 │    │   hostnames  │    │                 │
└─────────────────┘    └──────────────┘    └─────────────────┘
```

## Components

### 1. Input Sources (Service Discovery)

Input sources are responsible for discovering services that need DNS records. Each input source runs independently and can be configured with filters and polling intervals.

**Supported Input Types:**
- **Docker**: Container labels and Traefik integration
- **Traefik**: Reverse proxy route discovery
- **Tailscale**: VPN mesh network devices
- **ZeroTier**: Virtual network nodes
- **File**: Static YAML/JSON definitions
- **Remote**: HTTP API endpoints
- **Caddy**: Web server route discovery

**Key Features:**
- Independent polling cycles
- Configurable filtering (labels, names, networks, etc.)
- Event-driven updates (Docker events, file watching)
- Authentication support (API keys, basic auth)
- Scoped logging per input

### 2. Domains (Central Routing)

Domains act as the central routing and control layer, determining which input sources can create records and which outputs receive those records.

**Responsibilities:**
- **Input Routing**: Control which inputs can create records for specific domains
- **Output Routing**: Control which outputs receive records from specific domains
- **Record Transformation**: Apply domain-specific configuration (TTL, targets, etc.)
- **Lifecycle Management**: Handle record creation, updates, and deletion
- **Validation**: Ensure record integrity and prevent conflicts

**Configuration Model:**
```yaml
domains:
  production_com:
    name: "production.com"
    input_profiles:      # Which inputs can create records
      - docker_prod
      - traefik_public
    outputs:             # Which outputs receive records
      - cloudflare_dns
      - zone_backup
    record:              # Domain-specific record config
      target: "web.production.com"
      ttl: 300
      update_existing: true
```

### 3. Outputs (DNS Management)

Output destinations handle the final DNS record management, whether updating live DNS providers or generating file exports.

**Output Types:**
- **DNS Providers**: Live DNS updates (Cloudflare, etc.)
- **File Formats**: Local file generation (JSON, YAML, zone files, hosts)
- **Remote APIs**: HTTP POST to aggregation services

**Key Features:**
- Independent operation per output
- File ownership and permissions control
- Template-based path generation
- Multi-domain support with domain filtering
- Metadata preservation and timestamps

## Design Principles

### 1. Separation of Concerns

Each tier has a single, well-defined responsibility:
- **Inputs**: Service discovery only
- **Domains**: Routing and record management only
- **Outputs**: DNS updates and file generation only

### 2. Configuration-Driven

All behavior is controlled through configuration, not code:
- Input sources are configured with filters and options
- Domain routing is explicitly defined in configuration
- Output destinations are independently configurable

### 3. Independent Operation

Components operate independently where possible:
- Inputs poll on their own schedules
- Outputs update on their own triggers
- Domain routing doesn't block input discovery

### 4. Extensibility

New components can be added without affecting existing ones:
- New input types register themselves
- New output formats follow standard interfaces
- Domain routing supports any input/output combination

## Data Flow

### Record Creation Flow

1. **Discovery**: Input source discovers a service (container, route, device)
2. **Record Generation**: Input creates DNS record with hostname, type, target, TTL
3. **Domain Routing**: Domain configuration determines if record is allowed
4. **Output Distribution**: Records sent to all configured outputs for that domain
5. **DNS Updates**: Outputs update DNS providers or generate files

### Record Update Flow

1. **Change Detection**: Input detects service change (IP change, label update)
2. **Record Update**: Input updates existing record with new information
3. **Domain Validation**: Domain validates the update is allowed
4. **Output Propagation**: Updated record sent to all configured outputs
5. **DNS Synchronization**: Outputs sync changes to DNS providers/files

### Record Deletion Flow

1. **Service Removal**: Input detects service removal (container stop, route deletion)
2. **Record Removal**: Input removes record from its tracking
3. **Domain Cleanup**: Domain removes record from its state
4. **Output Cleanup**: Outputs remove record from DNS providers/files

## Configuration Architecture

### Hierarchical Configuration

Herald supports multiple configuration files and includes:

```yaml
# base.yml
include:
  - "/etc/herald/common.yml"
  - "./local-overrides.yml"

general:
  log_level: info

# common.yml gets merged
# local-overrides.yml overrides previous values
```

### Profile-Based Organization

Inputs and outputs are organized into named profiles:

```yaml
inputs:
  docker_prod:     # Profile name
    type: docker   # Implementation type
    # ... config

domains:
  my_domain:
    input_profiles:  # Reference by profile name
      - docker_prod
```

## Extensibility Points

### Adding New Input Sources

1. Implement the `input.Provider` interface
2. Register with `input.RegisterProvider()`
3. Handle configuration parsing and validation
4. Implement polling/event-driven discovery
5. Generate DNS records via the common interface

### Adding New Output Formats

1. Implement the `output.OutputFormat` interface
2. Register with `output.RegisterFormat()`
3. Handle file writing, DNS API calls, or HTTP requests
4. Support multi-domain targeting
5. Implement proper error handling and logging

### Adding New DNS Providers

1. Implement the DNS provider interface in `pkg/dns/providers/`
2. Register the provider in the providers map
3. Handle authentication and API communication
4. Support all DNS record types (A, AAAA, CNAME, etc.)
5. Implement proper rate limiting and error handling

## Performance Considerations

### Polling Optimization

- Independent polling cycles prevent blocking
- Configurable intervals balance freshness vs. load
- Event-driven updates (Docker events) for immediate response
- Filtered discovery reduces unnecessary processing

### Memory Management

- Records stored per-domain to limit memory usage
- Configurable output targeting prevents unnecessary file generation
- Garbage collection of removed records
- Efficient data structures for fast lookups

### Concurrency

- Inputs run in parallel goroutines
- Domain processing is thread-safe with proper locking
- Outputs operate independently without blocking inputs
- Graceful shutdown with proper cleanup

## Security Considerations

### API Security

- API tokens stored securely and never logged
- Basic authentication support where needed
- TLS certificate verification (configurable)
- Rate limiting and timeout handling

### File Security

- Configurable file ownership and permissions
- Secure temporary file creation
- Atomic file updates to prevent corruption
- Path validation to prevent directory traversal

### Network Security

- Optional TLS for all HTTP communications
- Configurable CA certificates for self-signed certs
- No unnecessary network exposure
- Secure handling of credentials in memory

## Monitoring and Observability

### Logging

- Structured logging with configurable levels
- Per-component log level overrides
- Request/response logging for debugging
- Error context preservation

### Metrics

- Record creation/update/deletion counters
- Input source health and timing
- Output success/failure rates
- DNS provider API response times

### Health Checks

- Input source connectivity validation
- DNS provider accessibility checks
- File system permissions verification
- Configuration validation on startup