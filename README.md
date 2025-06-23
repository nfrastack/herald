# Herald

Automate DNS record management for containers and services. Herald monitors Containers from Docker, Reverse Proxies like Caddy and Traefik, VPNs like Tailscale and ZeroTier, and other sources to automatically create and manage DNS records to upstream providers or to local filesystems without manual intervention.

> **Commercial/Enterprise Users:**
>
> This tool is free to use for all users. However, if you are using Herald in a commercial or enterprise environment, please consider purchasing a license to support ongoing development and receive priority support. There is no charge to use the tool and no differences in binaries, but a license purchase helps ensure continued improvements and faster response times for your organization. If this is useful to your organization and you wish to support the project [please reach out](mailto:code+herald@nfrastack.com).

## Disclaimer

Herald is an independent project and is not affiliated with, endorsed by, or sponsored by Docker Inc, Tailscale Inc., Traefik Labs, ZeroTier Inc. Any references to these products are solely for the purpose of describing the functionality of this tool, which is designed to enhance the usage of their applications. This tool is provided as-is and is not an official product of any of their respective plaforms. I'm also not a lawyer, so if you represent commercial interests of companies above and have concerns, let's talk.

## Maintainer

nfrastack <code@nfrastack.com>

## Table of Contents

- [Disclaimer](#disclaimer)
- [Maintainer](#maintainer)
- [Prerequisites and Assumptions](#prerequisites-and-assumptions)
- [Installing](#installing)
  - [From Source](#from-source)
  - [Precompiled Binaries](#precompiled-binaries)
  - [Containers](#containers)
  - [Distributions](#distributions)
- [Configuration](#configuration)
  - [Overview](#overview)
  - [Configuration Examples and Files](#configuration-examples-and-files)
  - [General Options](#general-options)
  - [Default Options](#default-options)
  - [Domain Configuration](#domain-configuration)
  - [Input Providers](#input-providers)
  - [Output Providers](#output-providers)
- [Support](#support)
  - [Implementation](#implementation)
  - [Usage](#usage)
  - [Bugfixes](#bugfixes)
  - [Feature Requests](#feature-requests)
  - [Updates](#updates)
- [License](#license)

## Prerequisites and Assumptions

- Access to a DNS provider to create/update DNS records
- Access to one of the Input providers

## Installing

### From Source

Clone this repository and compile with [GoLang 1.23 or later](https://golang.org):

```bash
go build -o bin/herald ./cmd/herald
```

### Precompiled Binaries

Precompiled binaries are available for download from the [GitHub Releases](https://github.com/nfrastack/herald/releases) page. These binaries are created only for tagged releases.

Visit the [Releases](https://github.com/nfrastack/herald/releases) page and download the binary for your architecture.

#### Supported Architectures

- `x86_64` (64-bit Linux)
- `aarch64` (ARM 64-bit Linux)

#### Running in Background

This tool should be run as a systemd service as it continuously monitors container events. Example systemd units are available in the [contrib/systemd](contrib/systemd) directory of the repository.

### Containers

See [container](container/) for an image that can build and run in your container engine like Docker or Podman.

### Distributions

#### NixOS

See [contrib/nixos](contrib/nixos) for installation instructions and a module that can be used to configure.

## Configuration

### Overview

Herald uses a domain-centric configuration model where domains control which input providers can create records and which output providers receive those records. The configuration is organized into five main sections:

- **General options**: Global settings affecting the whole application
- **Inputs**: Define how services are discovered (Docker, Traefik, Tailscale, etc.)
- **Outputs**: Define where DNS records are sent (Cloudflare, file exports, etc.)
- **Domains**: Central routing that connects inputs to outputs via domain matching
- **API**: Optional HTTP server for receiving records from remote Herald instances

#### Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Input Providers│───▶│    Domains      │───▶│ Output Providers│
│                 │    │                 │    │                 │
│ • Docker        │    │ • Input routing │    │ • DNS providers │
│ • Traefik       │    │ • Output routing│    │ • File exports  │
│ • Tailscale     │    │ • Record config │    │ • Remote APIs   │
│ • ZeroTier      │    │ • Filters       │    │                 │
│ • File/Remote   │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Key Concepts:**

- **Input Providers**: Discover services that need DNS records (containers, VPN devices, etc.)
- **Domains**: Act as routing controllers, determining which inputs can create records and which outputs receive them
- **Output Providers**: Handle DNS record creation (live DNS providers) or export (file formats)
- **Targeting**: Domains can restrict both input sources and output destinations for precise control

#### Precedence Order

1. Container labels (for that container)
2. Environment variables (including those loaded from `.env`)
3. Config file values
4. Application defaults

### Configuration Examples and Files

The repository includes several configuration examples to help you get started:

#### YAML Configuration Examples

Located in [`contrib/config/`](contrib/config/):

- **Complete example**: [`herald.yml.sample`](contrib/config/herald.yml.sample) - Shows all configuration options including inputs, outputs, api, and domains

#### Container Configuration

For container deployments, see [`container/README.md`](container/README.md) which includes:

- Environment variable configuration
- Container-specific examples

#### Multiple File Loading & Includes

You can load and merge multiple configuration files by specifying the `-config` flag multiple times on the command line. Files are loaded in order; later files override earlier ones. The YAML `include` key can also be used to merge in other files.

#### Example: Multiple Config Files

```bash
herald \
  -config /folder1/base.yml \
  -config /folder2/override.yml \
  -config ./extra.yml
```

#### Example: YAML Include

```yaml
include:
  - /somewhere/in/etc/base.yaml
  - /your/filesystem/extra.yaml
```

### General Options

Global settings for the application. These can be set in the `general` section of the YAML config or via environment variables.

**Options:**

- `log_level` (string): Logging level for the application (e.g., `trace`, `debug`, `verbose`, `info`, `warn`, `error`).
- `log_timestamps` (bool): Whether to include timestamps in log output.
- `dry_run` (bool): If true, perform a test run without making DNS changes.

**YAML Example:**

```yaml
general:
  log_level: verbose
  log_timestamps: true
  dry_run: false
```

#### Scoped Logging

Each input/output/domain provider supports individual log level configuration via the `log_level` option, allowing fine-grained control over logging verbosity per provider without affecting global log levels.

### Domain Configuration

Domains define per-domain configuration, including which input/output profiles to use, optional zone ID, and record options. Each domain can override defaults.

**Options:**

- `name` (string): The DNS domain name (e.g., `example.com`).
- `profiles` (object): Structured input and output configuration:
  - `inputs` (list of strings): Which input providers are allowed to create records for this domain.
  - `outputs` (list of strings): Which output profiles should process records for this domain.
- `record` (object): DNS record options for this domain:
  - `type` (string): DNS record type (e.g., `A`, `AAAA`, `CNAME`).
  - `ttl` (integer): Time-to-live for DNS records (in seconds).
  - `target` (string): The value for the DNS record (e.g., IP address or CNAME target).
  - `update_existing` (bool): Whether to update existing records for this domain.
  - `allow_multiple` (bool): Allow multiple A/AAAA records for this domain.
- `include_subdomains` (list of strings): Subdomains to explicitly include for DNS management.
- `exclude_subdomains` (list of strings): Subdomains to exclude from DNS management.

**YAML Example:**

```yaml
domains:
  production_domain:
    name: "example.com"
    profiles:
      inputs:
        - docker_public
        - traefik_routes
      outputs:
        - cloudflare_dns
        - zone_backup
    record:
      target: "web.example.com"
      ttl: 300
      update_existing: true
    include_subdomains:
      - api
      - www
    exclude_subdomains:
      - dev
      - staging

    name: example.com
    provider: cloudflare
    zone_id: your_zone_id_here
    record:
      type: A
      ttl: 60
      target: 192.0.2.1
      update_existing: true
      allow_multiple: true
    include_subdomains:
      - api
      - internal
    exclude_subdomains:
      - dev
      - staging
    profiles:
      inputs:
        - docker_production
        - traefik_prod
      outputs:
        - json_export
        - zone_backup
```

#### Advanced Domain Targeting

The `profiles` field enables sophisticated routing scenarios by controlling which input providers can create DNS records and which output providers receive those records:

**Input Provider Targeting**: Restrict which input providers can create DNS records for specific domains:

```yaml
domains:
  production_com:
    name: "production.com"
    provider: "cloudflare_prod"
    profiles:
      inputs:
        - "docker_production"     # Only production Docker containers
        - "traefik_prod"          # Only production Traefik routes

  staging_com:
    name: "staging.com"
    provider: "none"              # No DNS provider - output only
    profiles:
      inputs:
        - "docker_staging"        # Only staging containers
      outputs:
        - "hosts_export"          # Export to /etc/hosts for local testing
```

**Output Profile Targeting**: Control which output formats receive records from specific domains:

```yaml
domains:
  internal_vpn:
    name: "vpn.internal"
    provider: "none"            # VPN domains don't need public DNS
    profiles:
      inputs:
        - "tailscale_devices"
        - "zerotier_network"
      outputs:
        - "zone_internal"       # Generate internal zone files only
        - "json_backup"         # Keep JSON backups

  public_services:
    name: "company.com"
    provider: "cloudflare"
    profiles:
      inputs:
        - "docker_web"
        - "traefik_public"
      outputs:
        - "zone_backup"         # Backup zone files
        - "api_aggregator"      # Send to central server
```

### Input Providers

Input providers discover services that need DNS records. Each input provider is configured in the `inputs` section and can be selectively targeted via domain `profiles.inputs` configuration.

#### Supported Input Types

- **docker**: Monitors Docker containers and their labels to generate DNS records automatically
- **traefik**: Polls the Traefik API to discover router rules and generate DNS records for services
- **caddy**: Polls the Caddy Admin API to discover routes and generate DNS records
- **tailscale**: Monitors Tailscale devices and creates DNS records for them
- **zerotier**: Monitors ZeroTier networks and creates DNS records for network members
- **file**: Reads DNS records from local files in YAML, JSON, hosts, or zone file formats
- **remote**: Fetches DNS records from remote files over HTTP(S)

#### Caddy Input Provider

The Caddy input provider discovers domain names from Caddy route configurations via the Caddy Admin API. It extracts hostnames from the route match rules in the configuration.

```yaml
inputs:
  caddy_routes:
    type: caddy
    api_url: http://caddy:2019/config/
    api_auth_user: admin
    api_auth_pass: password
    tls:
      verify: true  # Set to false to skip TLS certificate verification
      ca: "/etc/ssl/certs/ca-certificates.crt"  # Custom CA certificate file
      cert: "/etc/ssl/client/client.crt"         # Client certificate for mutual TLS
      key: "/etc/ssl/client/client.key"          # Client private key for mutual TLS
    interval: 60s
    record_remove_on_stop: true
    process_existing: true
    filter:
      - type: host
        conditions:
          - value: "*.localhost"
```

**Filter Options:**

The Caddy provider supports filtering to precisely control which routes to process:

- **host**: Filter by hostname patterns (e.g., `*.localhost`, `api*.example.com`)
- **handler**: Filter by handler type (`reverse_proxy`, `file_server`, `static_response`, `vars`)
- **upstream**: Filter by upstream dial addresses (e.g., `host.docker.internal:*`, `localhost:2019`)
- **server**: Filter by server name (`srv0`, etc.)

**Example Filters:**

```yaml
# Only process hosts ending in .localhost
filter:
  - type: host
    conditions:
      - value: "*.localhost"

# Only process reverse proxy routes
filter:
  - type: handler
    conditions:
      - value: "reverse_proxy"

# Only process routes with Docker upstreams
filter:
  - type: upstream
    conditions:
      - value: "host.docker.internal:*"

# Only process routes from specific server
filter:
  - type: server
    conditions:
      - value: "srv0"

# Complex filtering with multiple conditions
filter:
  - type: host
    conditions:
      - value: "*.localhost"
      - value: "*.internal"
        logic: or
  - type: handler
    operation: AND
    conditions:
      - value: "reverse_proxy"
```

#### Docker Input Provider

**Options for configuring a Docker input provider:**

- `type`: (string) Must be `docker` for Docker input provider.
- `api_url`: (string) Docker API endpoint (default: `unix:///var/run/docker.sock`).
- `api_auth_user`: (string) Username for basic auth to the Docker API (optional).
- `api_auth_pass`: (string) Password for basic auth to the Docker API (optional).
- `process_existing`: (bool) Process existing containers on startup (default: false).
- `expose_containers`: (bool) Expose all containers by default (default: false).
- `swarm_mode`: (bool) Enable Docker Swarm mode (default: false).
- `record_remove_on_stop`: (bool) Remove DNS records when containers stop (default: false).

##### Config File

```yaml
inputs:
  docker_example:
    type: docker
    api_url: unix:///var/run/docker.sock
    api_auth_user: admin
    api_auth_pass: password
    process_existing: false
    expose_containers: true
    swarm_mode: false
    record_remove_on_stop: true
```

##### Usage of Docker Provider

##### Creating Records with Container Labels

Herald supports two methods for specifying DNS records:

1. **Direct DNS Labels**: Using `nfrastack.dns.*` labels
2. **Traefik Host Rules**: Automatically detecting domains from Traefik HTTP router rules

The tool will prioritize explicit DNS labels over Traefik Host rules.

###### Examples

**Using direct DNS labels**:

```bash
docker run -d \
  --label nfrastack.dns.host=myservice \
  --label nfrastack.dns.domain=example.com \
  --label nfrastack.dns.record.type=A \
  --label nfrastack.dns.record.ttl=300 \
  tiredofit/nginx
```

**Using Traefik Host rules**:

```bash
docker run -d \
  --label traefik.http.routers.myservice.rule="Host(`service.example.com`)" \
  tiredofit/nginx
```

**Disabling DNS for a container with Traefik rules**:

```bash
docker run -d \
  --label nfrastack.dns=false \
  --label traefik.http.routers.myservice.rule="Host(`service.example.com`)" \
  nginx
```

###### Docker Label Configuration

The Docker provider supports automatic DNS record creation by using container labels. The following `nfrastack.dns` labels are supported:

####### Core Labels

- `nfrastack.dns.enable`: Enable or disable DNS record creation for a container
  - Values: `true`, `false`, `1`, `0`
  - If omitted, defaults to the value of `expose_containers` in the provider configuration

- `nfrastack.dns.host`: The full hostname to register (e.g., `app.example.com`)
  - This is the primary label used for DNS configuration
  - Format: `<hostname>.<domain>` or just `<domain>` for apex records

##### Optional Record Configuration

You can specify the DNS record type using the `nfrastack.dns.record.type` label or config option. Supported values: `A`, `AAAA`, `CNAME`.

If not specified, the system will auto-detect:

- If the target is a valid IPv4 address, an `A` record is created.
- If the target is a valid IPv6 address, an `AAAA` record is created.
- Otherwise, a `CNAME` record is created.

- `allow_multiple`: Allow multiple A or AAAA records for this domain (default: false). Only applies to A/AAAA records, not CNAME.

###### Examples

**Basic A record for a web application:**

```yaml
labels:
  nfrastack.dns.enable: "true"
  nfrastack.dns.host: "webapp.example.com"
```

**Custom DNS configuration:**

```yaml
labels:
  nfrastack.dns.enable: "true"
  nfrastack.dns.host: "db.example.com"
  nfrastack.dns.record.type: "CNAME"
  nfrastack.dns.target: "database.internal"
  nfrastack.dns.record.ttl: "3600"
  nfrastack.dns.record.overwrite: "false"
```

###### Example: AAAA Record (IPv6)

```yaml
labels:
  nfrastack.dns.enable: "true"
  nfrastack.dns.host: "ipv6host.example.com"
  nfrastack.dns.target: "2001:db8::1"
  nfrastack.dns.record.type: "AAAA"
```

###### Example: Auto-detect AAAA Record

```yaml
labels:
  nfrastack.dns.enable: "true"
  nfrastack.dns.host: "ipv6auto.example.com"
  nfrastack.dns.target: "2001:db8::2"
  # nfrastack.dns.record.type not set, will auto-detect AAAA
```

###### Example: Multiple A/AAAA Record Labels

```yaml
labels:
  nfrastack.dns.enable: "true"
  nfrastack.dns.host: "multi.example.com"
  nfrastack.dns.target: "192.0.2.10"
  allow_multiple: "true"
```

##### Traefik Integration

The Docker provider also automatically detects Traefik Host rules and creates DNS records for them. For example:

```yaml
labels:
  nfrastack.dns.enable: "true"
  traefik.http.routers.myapp.rule: "Host(`app.example.com`)"
```

##### Docker Container Filtering

Docker container filtering allows you to control which containers are managed by the input provider. You can include or exclude containers based on labels, names, networks, or images. This is useful for limiting DNS management to only the containers you want, improving control and security.

**Available filter types:**

- `label`: Filter containers by labels and their values
- `name`: Filter containers by name patterns
- `network`: Filter containers by networks they're connected to
- `image`: Filter containers by the image they use

**How Filtering Works:**

- Filtering is evaluated before any DNS records are created or updated
- Use the filter array format with conditions for precise control
- Only containers that pass all filters are considered for DNS management

**Basic Example:**

```yaml
inputs:
  docker_example:
    type: docker
    filter:
      - type: label
        conditions:
          - key: environment
            value: production
```

**Filter Format**

The filter format supports complex filtering with conditions and boolean logic:

```yaml
inputs:
  docker_internal:
    type: docker
    expose_containers: true
    process_existing: true
    record_remove_on_stop: true
    log_level: trace
    filter:
      - type: label
        conditions:
          - key: traefik.proxy.visibility
            value: internal
          - key: environment
            value: production
            logic: and
```

**Advanced filtering with multiple conditions:**

```yaml
    filter:
      - type: label
        conditions:
          - key: traefik.proxy.visibility
            value: internal
          - key: app.type
            value: web*
            logic: or
      - type: name
        conditions:
          - value: webapp-*
          - value: api-*
            logic: or
```

**Processing Order:**

1. The input provider discovers all containers.
2. Filtering is applied according to the configuration.
3. Only containers passing the filter are considered for DNS management.

**Best Practices:**

- Use label filtering to target only containers that should be managed by Herald.
- Combine multiple filters for fine-grained control.

#### File Input Provider

The file provider allows you to manage DNS records by reading from YAML, JSON, hosts, or zone files. It supports real-time file watching (default) or interval-based polling.

Look in [contrib/config/records](contrib/config/records) for examples of the recognized formats.

**Example configuration:**

```yaml
inputs:
  file_example:
    type: file
    source: ./records/dns-records.yaml
    format: yaml # or json - autodetects based on extension
    interval: -1 # (default: watch mode)
    record_remove_on_stop: true
    process_existing: true
    filter:
      - type: hostname
        conditions:
          - value: "*.example.com"
```

**Supported File Formats:**

The File Input Provider supports multiple file formats for maximum flexibility:

- **YAML**: Structured YAML with metadata and domain organization
- **JSON**: Structured JSON format matching the YAML schema
- **Hosts**: Standard `/etc/hosts` format (hostname-to-IP mappings)
- **Zone**: RFC1035 BIND zone file format

**Sample Files:**

See [`contrib/config/records/`](contrib/config/records/) for complete examples of all supported file formats:

- [`dns-records.yaml`](contrib/config/records/dns-records.yaml) - YAML format example
- [`dns-records.json`](contrib/config/records/dns-records.json) - JSON format example
- [`hosts.example`](contrib/config/records/hosts.example) - Hosts file format example
- [`example.com.zone`](contrib/config/records/example.com.zone) - Zone file format example

**Filter Options:**

The File provider supports filtering to control which records from the file are processed:

- **hostname**: Filter by hostname patterns
- **type**: Filter by DNS record type (A, AAAA, CNAME)
- **target**: Filter by target values

**Example Filters:**

```yaml
# Only process A records
filter:
  - type: type
    conditions:
      - value: "A"

# Only process records for specific domain
filter:
  - type: hostname
    conditions:
      - value: "*.example.com"

# Complex filtering
filter:
  - type: hostname
    conditions:
      - value: "*.example.com"
      - value: "*.test.com"
        logic: or
  - type: type
    operation: AND
    conditions:
      - value: "A"
```

**Options:**

- `source` (required): Path to the file.
- `format`: `yaml` (default), `json`, `hosts`, or `zone` - autodetects based on extension.
- `interval`: `-1` (default, watch mode), or a duration (e.g. `30s`).
- `record_remove_on_stop`: Remove DNS records when removed from file. Default: `false`.
- `process_existing`: Process all records on startup. Default: `false`.

#### Remote Input Provider

The remote provider works just like the File provider but allows you to poll a remote YAML or JSON file over HTTP/HTTPS. It supports HTTP Basic Auth and interval-based polling.

##### Example configuration

```yaml
inputs:
  remote_example:
    type: remote
    name: remote_example
    remote_url: https://example.com/records.yaml
    format: yaml                    # or json (optional, autodetects by extension)
    interval: 30s                   # Poll every 30 seconds
    process_existing: true
    record_remove_on_stop: true
    remote_auth_user: myuser        # Optional HTTP Basic Auth
    remote_auth_pass: mypassword    # Optional HTTP Basic Auth
    tls:
      verify: true                              # Set to false to skip TLS certificate verification
      ca: "/etc/ssl/certs/ca-certificates.crt"  # Custom CA certificate file
      cert: "/etc/ssl/client/client.crt"        # Client certificate for mutual TLS
      key: "/etc/ssl/client/client.key"         # Client private key for mutual TLS
    filter:
      - type: hostname
        conditions:
          - value: "*.example.com"
```

**Filter Options:**

The Remote provider supports filtering to control which records from the remote file are processed:

- **hostname**: Filter by hostname patterns
- **type**: Filter by DNS record type (A, AAAA, CNAME)
- **target**: Filter by target values

**Example Filters:**

```yaml
# Only process CNAME records
filter:
  - type: type
    conditions:
      - value: "CNAME"

# Only process records matching domain patterns
filter:
  - type: hostname
    conditions:
      - value: "api.*"
      - value: "web.*"
        logic: or

# Complex filtering with multiple conditions
filter:
  - type: target
    conditions:
      - value: "192.168.*"
  - type: type
    operation: AND
    conditions:
      - value: "A"
```

##### Options

- `remote_url` (required): URL to the remote YAML or JSON file.
- `format`: `yaml` (default) or `json`.
- `interval`: How often to poll the remote file (e.g., `30s`).
- `process_existing`: Process all records on startup. Default: `false`.
- `record_remove_on_stop`: Remove DNS records when removed from remote. Default: `false`.
- `remote_auth_user`: Username for HTTP Basic Auth (optional).
- `remote_auth_pass`: Password for HTTP Basic Auth (optional).
- `tls`: TLS configuration object (optional):
  - `verify`: Whether to verify TLS certificates (default: true).
  - `ca`: Path to custom CA certificate file (optional).
  - `cert`: Path to client certificate file for mutual TLS (optional).
  - `key`: Path to client private key file for mutual TLS (optional).

#### Tailscale Input Provider

The Tailscale provider monitors Tailscale devices and automatically creates DNS records based on their online status and other configurable filters. It supports both Tailscale Central and Headscale, with OAuth client credentials and personal access tokens.

**Example configuration:**

```yaml
inputs:
  tailscale_example:
    type: tailscale
    api_key: "your_tailscale_api_key_here"
    tailnet: "-"                # Default tailnet, or specify tailnet ID
    domain: "ts.example.com"
    interval: 30s
    hostname_format: "simple"   # "simple", "tailscale", or "full"
    process_existing: true
    record_remove_on_stop: true
    tls:
      verify: true                               # Set to false to skip TLS certificate verification
      ca: "/etc/ssl/certs/ca-certificates.crt"   # Custom CA certificate file
      cert: "/etc/ssl/client/client.crt"         # Client certificate for mutual TLS
      key: "/etc/ssl/client/client.key"          # Client private key for mutual TLS
    #Filtering (defaults to online=true if no filters specified)
    filter:
      - type: online
        conditions:
          - value: "true"
```

**Authentication Methods:**

1. **Personal Access Token** (recommended):

```yaml
api_key: "tskey-api-xxxxx"
```

2. **OAuth Client Credentials**:

```yaml
api_auth_token: "your_oauth_client_secret"
api_auth_id: "your_oauth_client_id"
```

**Hostname Formats:**

- `simple`: Use device name, remove `.tail` suffix (e.g., `laptop` from `laptop.tail12345.ts.net`)
- `tailscale`: Use device name but sanitize for DNS (replace dots/underscores with hyphens)
- `full`: Use complete Tailscale hostname as-is

**Headscale Support:**

For self-hosted Headscale instances:

```yaml
inputs:
  headscale_example:
    type: tailscale
    api_url: "https://headscale.example.com/api/v1"
    api_key: "your_headscale_api_key"
    tailnet: "your-headscale-namespace"
    domain: "vpn.example.com"
```

**Filter Options:**

- `online`: Filter by online status (`true`/`false`) - **default if no filters specified**
- `name`: Filter by device name (substring match)
- `hostname`: Filter by full hostname (substring match)
- `tag`: Filter by device tags
- `id`: Filter by exact device ID
- `address`: Filter by assigned IP address
- `user`: Filter by device user
- `os`: Filter by operating system

**Configuration Options:**

- `type` (required): Must be `tailscale`
- `api_key`: Tailscale API key or access token (required unless using OAuth)
- `api_auth_token`: OAuth client secret (alternative to api_key)
- `api_auth_id`: OAuth client ID (required with api_auth_token)
- `api_url`: API URL (default: Tailscale Central, specify for Headscale)
- `tailnet`: Tailnet ID or namespace (default: "-" for default tailnet)
- `domain`: Domain suffix for DNS records (required)
- `interval`: Polling interval (default: 120s)
- `hostname_format`: How to format hostnames (default: "simple")
- `process_existing`: Process existing devices on startup (default: false)
- `record_remove_on_stop`: Remove DNS records when devices go offline (default: false)
- `tls`: TLS configuration object (optional):
  - `verify`: Whether to verify TLS certificates (default: true)
  - `ca`: Path to custom CA certificate file (optional)
  - `cert`: Path to client certificate file for mutual TLS (optional)
  - `key`: Path to client private key file for mutual TLS (optional)
- `log_level`: Provider-specific log level override

**Advanced Filtering:**

```yaml
# Only process devices with specific tags
filter:
  - type: tag
    conditions:
      - value: production

# Only process devices from specific user
filter:
  - type: user
    conditions:
      - value: admin@company.com

# Only process devices with specific IP
filter:
  - type: address
    conditions:
      - value: 100.64.0.10

# Multiple conditions with logic operators
filter:
  - type: name
    conditions:
      - value: prod-*
      - value: staging-*
        logic: or
  - type: online
    operation: AND
    conditions:
      - value: true
```

#### Traefik Input Provider

The Traefik input provider discovers domain names from Traefik router rules via the Traefik API. It extracts hostnames from the `Host` rules in router configurations.

```yaml
inputs:
  traefik_routers:
    type: traefik
    api_url: https://traefik.example.com/api/http/routers
    api_auth_user: admin
    api_auth_pass: password
    tls:
      verify: true                               # Set to false to skip TLS certificate verification
      ca: "/etc/ssl/certs/ca-certificates.crt"   # Custom CA certificate file
      cert: "/etc/ssl/client/client.crt"         # Client certificate for mutual TLS
      key: "/etc/ssl/client/client.key"          # Client private key for mutual TLS
    interval: 5m
    filter:
      - type: name
        conditions:
          - value: ^websecure-
```

**Options for configuring a Traefik input provider:**

- `type`: (string) Must be `traefik` for Traefik input provider.
- `api_url`: The URL of the Traefik API to poll (e.g., `http://traefik:8080/api/http/routers`).
- `api_auth_user`: Username for basic auth to the Traefik API (optional).
- `api_auth_pass`: Password for basic auth to the Traefik API (optional).
- `interval`: How often to poll the Traefik API for updates (e.g., `15s`, `1m`, `1h`).
- `tls`: TLS configuration object (optional):
  - `verify`: Whether to verify TLS certificates (default: true).
  - `ca`: Path to custom CA certificate file (optional).
  - `cert`: Path to client certificate file for mutual TLS (optional).
  - `key`: Path to client private key file for mutual TLS (optional).
- `record_remove_on_stop`: Remove DNS records when routers are removed (default: false).
- `process_existing`: Process existing routers on startup (default: false).

**Traefik Router Filtering:**

The Traefik provider supports advanced filtering to precisely control which routers to process. Use the filter format with conditions arrays for maximum flexibility:

**Available filter types:**

- `name`: Filter routers by name patterns (e.g., `^websecure-`, `*-internal`)
- `service`: Filter by service name patterns
- `provider`: Filter by provider (e.g., `docker`, `file`, `kubernetes`)
- `entrypoint`: Filter by entrypoints (e.g., `websecure`, `web`)
- `status`: Filter by router status
- `rule`: Filter by router rule patterns

**Basic filtering example:**

```yaml
inputs:
  traefik_example:
    type: traefik
    api_url: http://traefik:8080/api/http/routers
    filter:
      - type: name
        conditions:
          - value: ^webcontainer.*
```

**Advanced filters (multiple conditions):**

```yaml
inputs:
  traefik_advanced:
    type: traefik
    api_url: http://traefik:8080/api/http/routers
    filter:
      - type: name
        conditions:
          - value: ^web-
          - value: ^api-
            logic: or
      - type: provider
        operation: AND
        conditions:
          - value: docker
      - type: status
        operation: AND
        negate: true
        conditions:
          - value: enabled
```

**Filter features:**

- `conditions`: Array of filter conditions with `value` and optional `logic` (and/or)
- `operation`: How to combine multiple filters - `AND`, `OR`, or `NOT` (default is `AND`)
- `negate: true`: Inverts the filter result
- **Regex support**: Use regex patterns like `^websecure-.*` for name matching
- **Wildcard support**: Use `*` and `?` for simple wildcard matching

**Filter examples:**

```yaml
# Only routers starting with "webcontainer"
filter:
  - type: name
    conditions:
      - value: ^webcontainer.*

# Only Docker provider routers with specific names
filter:
  - type: provider
    conditions:
      - value: docker
  - type: name
    operation: AND
    conditions:
      - value: websecure-*

# Exclude internal routers
filter:
  - type: name
    negate: true
    conditions:
      - value: "*-internal"
```

```yaml
inputs:
  traefik_example:
    type: traefik
    api_url: http://traefik:8080/api/http/routers
    interval: 30s  # or 60, 1m, 1h, etc.
    filter:
      - type: name
        conditions:
          - value: ^websecure-.*
```

#### ZeroTier Input Provider

The ZeroTier provider monitors ZeroTier network members and automatically creates DNS records based on their online status and other configurable filters. It supports both ZeroTier Central and self-hosted ZT-Net controllers.

**Basic Configuration:**

```yaml
inputs:
  zerotier_example:
    type: zerotier
    api_token: "your_zerotier_api_token_here"
    network_id: "YOUR_NETWORK_ID"
    domain: "zt.example.com"
    online_timeout_seconds: 300  # Recommended: 300+ seconds
    record_remove_on_stop: true
    use_address_fallback: true
    filter:
      - type: online
        conditions:
          - value: "true"
```

**Configuration Options:**

- `type`: Must be "zerotier"
- `api_token`: ZeroTier API token or ZT-Net auth token (required)
- `network_id`: ZeroTier network ID (required)
- `domain`: Domain suffix for DNS records (e.g., `zt.example.com`)
- `api_url`: API URL (default: `https://my.zerotier.com` for ZeroTier Central)
- `interval`: Polling interval (default: 60s)
- `online_timeout_seconds`: Time to consider member offline (default: 120, recommend: 300+)
- `process_existing`: Process existing members on startup (default: false)
- `record_remove_on_stop`: Remove DNS records when member goes offline (default: false)
- `use_address_fallback`: Use ZeroTier address as hostname when name is empty (default: false)

**Filter Options:**

- `online`: Filter by online status (`true`/`false`)
- `name`: Filter by member name (substring match)
- `authorized`: Filter by authorization status (`true`/`false`)
- `id`: Filter by exact member ID
- `ipAssignments`: Filter by assigned IP address

**ZT-Net Support:**

For self-hosted ZT-Net controllers, set the `api_url` and use the special network ID format:

```yaml
inputs:
  ztnet_example:
    type: zerotier
    api_url: "https://ztnet.company.com"
    api_token: "ztnet_token_here"
    network_id: "org:domain.com:networkid123"
    domain: "dev.company.com"
```

**⚠️ Important**: For ZeroTier Central, set `online_timeout_seconds` to 300+ seconds to prevent erratic add/remove behavior due to inconsistent heartbeat timing.

### Output Providers

Output providers handle where DNS records are sent. This includes live DNS providers (like Cloudflare) and file export formats. Output providers are configured in the `outputs` section and can be selectively targeted via domain `profiles.outputs` configuration.

#### Live DNS Providers

Live DNS providers use `type: dns` and manage records directly with DNS services:

- **cloudflare**: Manage DNS records via Cloudflare API

```yaml
outputs:
  # Live Cloudflare DNS
  cloudflare_dns:
    type: dns
    provider: cloudflare
    token: "your-cloudflare-token"
    log_level: info
```

#### File Export Formats

File export providers use `type: file` and export DNS records to various local file formats for backups, local resolution, or integration with other systems:

- **hosts**: Standard `/etc/hosts` file format (IPv4/IPv6 A records only, CNAMEs flattened)
- **json**: Structured JSON export with metadata and timestamps
- **yaml**: YAML export format with full record details
- **zone**: RFC1035 compliant DNS zone files with SOA and NS records

##### DNS Resolution Control for File Outputs

File output providers support DNS resolution control to handle different network environments and prevent localhost/container IP resolution issues.

When Herald processes CNAME records (like those from Traefik routers), it can automatically resolve them to IP addresses (called "flattening"). However, this can cause issues when running in containers or local environments where hostnames resolve to localhost addresses.

**Available Options:**

```yaml
outputs:
  hosts:
    type: file
    format: hosts
    path: "./domain/%domain%.hosts"
    domains: ["example.com"]
    # DNS Resolution Control Options:
    flatten_cnames: true          # Enable CNAME to A record flattening (default: true)
    dns_server: "1.1.1.1"        # Use external DNS server (Cloudflare)
    resolve_external: true       # Force external DNS resolution
    ip_override: "192.168.1.100" # Override all resolved IPs with this address
```

- **`flatten_cnames: true/false`** - Controls whether CNAME records are resolved to A records
- **`dns_server: "1.1.1.1"`** - Uses external DNS server via nslookup instead of system resolver
- **`resolve_external: true`** - Forces external DNS resolution, defaults to Cloudflare DNS (1.1.1.1)
- **`ip_override: "192.168.1.100"`** - Forces all resolved IPs to this address, bypassing DNS entirely

**Example: Container DNS Issues**

Problem: Herald resolves hostnames to localhost in containers:
```
127.0.0.2    git.example.com
127.0.0.2    mail.example.com
```

Solution: Use external DNS or IP override:
```yaml
hosts:
  dns_server: "1.1.1.1"
  resolve_external: true
```

Result: Correct public IP resolution:
```
148.113.218.18    git.example.com
148.113.218.18    mail.example.com
```

```yaml
outputs:
  # JSON backup files
  json_backup:
    type: file
    format: json
    path: "./backups/%domain%.json"
    user: herald
    group: herald
    mode: 0644

  # Zone files for BIND
  zone_files:
    type: file
    format: zone
    path: "./zones/%domain%.zone"
    soa:
      primary_ns: "ns1.example.com"
      admin_email: "admin@example.com"
      serial: "auto"
    ns_records:
      - "ns1.example.com"
      - "ns2.example.com"
```

#### Remote Output

Remote output providers use `type: remote` for sending records to remote Herald aggregation servers:

```yaml
outputs:
  # Remote aggregation server
  aggregation_server:
    type: remote
    url: "https://dns-aggregator.example.com/api/dns"
    client_id: "server-01"
    token: "aggregation-token"
    timeout: "30s"
    tls:
      verify: true
```

See the detailed configuration sections above for each output type.

### API Server

Herald includes an optional HTTP API server for distributed DNS management scenarios. The API server receives DNS records from remote Herald instances and can route them to different output profiles.

**Use Case**: Multiple servers running Herald → Central aggregator → Master DNS zone files

#### API Server Configuration

```yaml
api:
  enabled: true
  port: "8080"
  listen:                                     # Interface patterns to listen on (optional)
    - "all"                                   # Listen on all interfaces (default)
    - "192.168.1.100"                         # Listen on specific IP address
    - "eth0"                                  # Listen on specific interface
    - "enp*"                                  # Listen on all interfaces matching pattern
    - "!lo"                                   # Exclude loopback interface
    - "!docker*"                              # Exclude all Docker interfaces
  endpoint: "/api/dns"
  client_expiry: "10m"
  log_level: "info"
  profiles:
    server1:
      token: "your_bearer_token_here"
      output_profile: "aggregated_zones"
    server2:
      token: "file:///var/run/secrets/server2_token"  # Load token from file
      output_profile: "special_zones"
  tls:
    cert: "/etc/ssl/certs/herald.crt"
    key: "/etc/ssl/private/herald.key"
    ca: "/etc/ssl/ca/client-ca.pem"  # Optional for mutual TLS
```

#### Security Features

- Bearer token authentication per client
- Failed attempt tracking and rate limiting (20 attempts/hour)
- TLS with optional mutual authentication
- Comprehensive security logging
- Automatic client expiry and cleanup

#### Interface Binding

The `listen` option provides flexible control over which network interfaces the API server binds to:

- **All interfaces**: `"all"` or `"*"` (default if not specified)
- **Specific IP addresses**: `"192.168.1.100"`, `"10.0.0.50"`
- **Interface names**: `"eth0"`, `"enp0s3"`, `"wlan0"`
- **Wildcard patterns**: `"enp*"` (matches `enp0s3`, `enp1s0`, etc.)
- **Exclusion patterns**: `"!docker*"` (exclude all Docker interfaces)
- **Combined patterns**: Mix inclusion and exclusion for precise control

```yaml
api:
  listen:
    - "all"           # Start with all interfaces
    - "!docker*"      # Exclude Docker interfaces
    - "!lo"           # Exclude loopback
    - "192.168.1.100" # Always include this specific IP
```

#### Remote Output Configuration

To send records to a remote Herald API server, configure a `remote` output provider:

```yaml
outputs:
  send_to_api:
    format: remote
    url: "https://dns-master.company.com/api/dns"
    client_id: "server1"
    token: "your_bearer_token_here"
    timeout: "30s"
    data_format: "json"  # or "yaml"
    log_level: "info"
    tls:
      verify: true
      ca: "/etc/ssl/ca/server-ca.pem"    # Optional custom CA
      cert: "/etc/ssl/certs/client.pem"  # Optional client cert for mutual TLS
      key: "/etc/ssl/private/client.key" # Optional client key for mutual TLS
```


## Environment Variables

Herald supports a minimal set of environment variables for global application settings:

| Variable           | Description                                        | Default   |
| ------------------ | -------------------------------------------------- | --------- |
| `DRY_RUN`          | If true, do not perform actual DNS updates         | `false`   |
| `LOG_LEVEL`        | Set log level (`trace` `debug`, `verbose`, `info`) | `verbose` |
| `LOG_TIMESTAMPS`   | Include timestamps in log output (`true`/`false`)  | `true`    |

All other configuration should be done via the YAML configuration file. See the sample [.env](contrib/config/env.sample) file for examples.

## Secret References

Herald supports flexible secret management through special URI-style prefixes in configuration values:

### File References (`file://`)

Load values from files on the filesystem. Useful for Docker secrets, Kubernetes mounted secrets, or any file-based secret management:

```yaml
inputs:
  docker:
    type: docker
    api_auth_user: "file:///run/secrets/docker_user"
    api_auth_pass: "file:///run/secrets/docker_pass"

outputs:
  cloudflare:
    type: dns
    provider: cloudflare
    api_token: "file:///var/secrets/cloudflare_token"
```

### Environment Variable References (`env://`)

Load values from environment variables. Clean and simple for container deployments:

```yaml
inputs:
  tailscale:
    type: tailscale
    api_key: "env://TAILSCALE_API_KEY"
    tailnet: "env://TAILSCALE_TAILNET"

outputs:
  cloudflare:
    type: dns
    provider: cloudflare
    api_token: "env://CLOUDFLARE_API_TOKEN"
```

### Mixed Usage

You can mix file and environment references as needed:

```yaml
api:
  enabled: true
  profiles:
    server1:
      token: "file:///var/secrets/server1_token"  # From Kubernetes secret
    server2:
      token: "env://SERVER2_API_TOKEN"             # From environment
```

**Benefits:**
- **Security**: Keep secrets out of configuration files
- **Flexibility**: Support both file-based and environment-based secret management
- **Container-friendly**: Works seamlessly with Docker secrets, Kubernetes secrets, and environment variables
- **No complex environment variable naming**: Use any environment variable name you want

### Default Options

Default DNS record settings, used unless overridden at the domain or container level. These need to be specifically entered into your configuration to be active; they are not application-level defaults.

**Options:**

- `record` (object): Default DNS record options:
  - `type` (string): Default DNS record type (e.g., `A`, `AAAA`, `CNAME`).
  - `ttl` (integer): Default time-to-live for DNS records (in seconds).
  - `update_existing` (bool): Whether to update existing records by default.
  - `allow_multiple` (bool): Allow multiple A/AAAA records by default.

**YAML Example:**

```yaml
defaults:
  record:
    type: A
    ttl: 300
    update_existing: true
    allow_multiple: false
```

## Support

### Implementation

[Contact us](mailto:code+herald@nfrastack.com) for rates.

### Usage

- The [Discussions board](../../discussions) is a great place for working with the community.

### Bugfixes

- Please submit a [Bug Report](issues/new) if something isn't working as expected. I'll do my best to issue a fix in short order.

### Feature Requests

- Feel free to submit a feature request; however, there is no guarantee that it will be added or at what timeline.  [Contact us](mailto:code+herald@nfrastack.com) for custom development.

### Updates

- Best effort to track upstream dependency changes, with more priority if the tool is actively used on our end.

## License

BSD-3-Clause. See [LICENSE](LICENSE) for more details.
