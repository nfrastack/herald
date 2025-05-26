<!-- vscode-markdown-toc off -->
# DNS Companion

## About

This tool enables automatic DNS record management for containers. It monitors container events (creation, deletion, updates) and creates or removes DNS records accordingly. Whether you're using Docker containers with explicit DNS-related labels or Traefik with Host rules, DNS Companion provides seamless DNS integration, allowing your containers to be easily accessible by domain names without manual DNS configuration.

> **Commercial/Enterprise Users:**
>
> This tool is free to use for all users. However, if you are using DNS Companion in a commercial or enterprise environment, please consider purchasing a license to support ongoing development and receive priority support. There is no charge to use the tool and no differences in binaries, but a license purchase helps ensure continued improvements and faster response times for your organization. If this is useful to your organization and you wish to support the project, [please reach out](mailto:code+cdc@nfrastack.com).

## Disclaimer

DNS Companion is an independent project and is not affiliated with, endorsed by, or sponsored by Docker, Inc. or Traefik Labs. Any references to these products are solely for the purpose of describing the functionality of this tool, which is designed to enhance the usage of container technologies. This tool is provided as-is and is not an official product of any container platform.

## Maintainer

nfrastack <code@nfrastack.com>


## Table of Contents

- [About](#about)
- [Disclaimer](#disclaimer)
- [Maintainer](#maintainer)
- [Table of Contents](#table-of-contents)
- [Prerequisites and Assumptions](#prerequisites-and-assumptions)
- [Installing](#installing)
  - [From Source](#from-source)
  - [Precompiled Binaries](#precompiled-binaries)
    - [Supported Architectures](#supported-architectures)
    - [How to Download](#how-to-download)
    - [How to Use](#how-to-use)
    - [Running in Background](#running-in-background)
  - [Containers](#containers)
  - [Distributions](#distributions)
    - [NixOS](#nixos)
- [Configuration](#configuration)
  - [Overview](#overview)
    - [Precedence Order](#precedence-order)
  - [Example Configuration File](#example-configuration-file)
  - [Configuration Examples and Files](#configuration-examples-and-files)
    - [YAML Configuration Examples](#yaml-configuration-examples)
    - [Container Configuration](#container-configuration)
  - [NixOS Integration](#nixos-integration)
    - [Using the NixOS Module](#using-the-nixos-module)
    - [Multiple File Loading \& Includes](#multiple-file-loading--includes)
    - [Example: Multiple Config Files](#example-multiple-config-files)
    - [Example: YAML Include](#example-yaml-include)
  - [General Options](#general-options)
- [Environment Variables](#environment-variables)
  - [Default Options](#default-options)
  - [Pollers](#pollers)
    - [Docker Poller](#docker-poller)
      - [Config File](#config-file)
      - [Environment Variables](#environment-variables-1)
      - [Usage of Docker Provider](#usage-of-docker-provider)
      - [Creating Records with Container Labels](#creating-records-with-container-labels)
        - [Examples](#examples)
        - [Docker Label Configuration](#docker-label-configuration)
      - [Optional Record Configuration](#optional-record-configuration)
        - [Examples](#examples-1)
        - [Example: AAAA Record (IPv6)](#example-aaaa-record-ipv6)
        - [Example: Auto-detect AAAA Record](#example-auto-detect-aaaa-record)
        - [Example: Multiple A/AAAA Record Labels](#example-multiple-aaaaa-record-labels)
      - [Traefik Integration](#traefik-integration)
      - [Docker Container Filtering](#docker-container-filtering)
    - [Traefik Poller](#traefik-poller)
  - [Simple filter (single filter)](#simple-filter-single-filter)
  - [Advanced filters (multiple, AND/OR/NOT/Negate)](#advanced-filters-multiple-andornotnegate)
      - [Poller Traefik Configuration File](#poller-traefik-configuration-file)
      - [Poller Traefik Environment Variables](#poller-traefik-environment-variables)
  - [Poller File Provider](#poller-file-provider)
  - [Remote Provider](#remote-provider)
    - [Example configuration](#example-configuration)
    - [Options](#options)
  - [Providers](#providers)
    - [Supported Providers](#supported-providers)
    - [Provider Configuration (YAML)](#provider-configuration-yaml)
    - [Provider Environment Variables](#provider-environment-variables)
- [Hosts DNS Provider](#hosts-dns-provider)
  - [Domains](#domains)
    - [Domain Environment Variables](#domain-environment-variables)
- [Support](#support)
  - [Usage](#usage)
  - [Bugfixes](#bugfixes)
  - [Feature Requests](#feature-requests)
  - [Updates](#updates)
- [License](#license)

## Prerequisites and Assumptions

- Access to a DNS provider to create/update DNS records
- Access to one of the Polling providers

## Installing

### From Source

Clone this repository and compile with [GoLang 1.23 or later](https://golang.org):

```bash
go build -o bin/dns-companion ./cmd/dns-companion
```

### Precompiled Binaries

Precompiled binaries are available for download from the [GitHub Releases](https://github.com/nfrastack/dns-companion/releases) page. These binaries are created only for tagged releases.

#### Supported Architectures

- `x86_64` (64-bit Linux)
- `aarch64` (ARM 64-bit Linux)

#### How to Download

1. Visit the [Releases](https://github.com/nfrastack/dns-companion/releases) page.
2. Locate the release you want to download.
3. Download the binary for your architecture.

#### How to Use

1. Make the binary executable:

   ```bash
   chmod +x dns-companion
   ```

2. Move it to a directory in your `PATH` (e.g., `/usr/local/bin`):

   ```bash
   sudo mv dns-companion /usr/local/bin/
   ```

3. Run the binary:

   ```bash
   dns-companion --help
   ```

#### Running in Background

This tool should be run as a systemd service as it continuously monitors container events. Example systemd units are available in the [contrib/systemd](contrib/systemd) directory of the repository.

### Containers

See [container](container/) for an image that can build and run in your container engine like Docker or Podman.

### Distributions

#### NixOS

See [contrib/nixos](contrib/nixos) for installation instructions and a module that can be used to configure.

## Configuration

### Overview

DNS Companion supports flexible configuration via YAML files, environment variables, and container labels. You can load multiple configuration files, use includes, and override settings at various levels. The configuration is organized into general options, defaults, pollers, providers, and domains.

- **General options**: Global settings affecting the whole application.
- **Defaults**: Default DNS record settings.
- **Pollers**: Define how container/service information is discovered (e.g., Docker, Traefik).
- **Providers**: Define how DNS records are managed (e.g., Cloudflare).
- **Domains**: Per-domain configuration and overrides.

#### Precedence Order

1. Container labels (for that container)
2. Environment variables (including those loaded from `.env`)
3. Config file values
4. General/Poller/Provider/domain defaults

### Example Configuration File

See the sample configurations in the [`contrib/config/`](contrib/config/) directory for comprehensive examples:

- [`dns-companion.yaml.sample`](contrib/config/dns-companion.yaml.sample) - Complete configuration example with all options
- [`env.sample`](contrib/config/env.sample) - Environment variable configuration examples

### Configuration Examples and Files

The repository includes several configuration examples to help you get started:

#### YAML Configuration Examples

Located in [`contrib/config/`](contrib/config/):
- **Complete example**: [`dns-companion.yaml.sample`](contrib/config/dns-companion.yaml.sample) - Shows all configuration options including providers, polls, and domains
- **Environment variables**: [`env.sample`](contrib/config/env.sample) - Demonstrates environment-based configuration

#### Container Configuration

For container deployments, see [`container/README.md`](container/README.md) which includes:
- Docker environment variable configuration
- Container-specific examples
- Docker Compose setup examples

### NixOS Integration

DNS Companion provides native NixOS integration through a Nix flake and NixOS module.

#### Using the NixOS Module

The flake provides a comprehensive NixOS module that allows declarative configuration. See [`contrib/nixos/README.md`](contrib/nixos/README.md) for complete documentation including:

- How to add the flake as an input to your configuration
- Full NixOS module options reference
- Example configurations for all supported providers and pollers
- Integration with systemd services

Key NixOS module features:
- Declarative YAML configuration generation
- Systemd service management
- Support for all DNS providers (Cloudflare, hosts file)
- Support for all poll providers (Docker, Traefik, file, remote)
- File includes and multi-file configuration support

Example NixOS configuration snippet:

```nix
{
  imports = [
    inputs.dns-companion.nixosModules.default
  ];

  services.dns-companion = {
    enable = true;
    general.poll_profiles = [ "docker" ];
    providers.cloudflare = {
      type = "cloudflare";
      api_token = "your-token-here";
    };
    providers.hosts = {
      type = "hosts";
      source = "/etc/hosts.dns-companion";
      enable_ipv4 = true;
      enable_ipv6 = false;
    };
    domains.example_com = {
      name = "example.com";
      provider = "cloudflare";
    };
  };
}
```

#### Multiple File Loading & Includes

You can load and merge multiple configuration files by specifying the `-config` flag multiple times on the command line. Files are loaded in order; later files override earlier ones. The YAML `include` key can also be used to merge in other files.

#### Example: Multiple Config Files

```bash
dns-companion \
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
- `poll_profiles` (list of strings): List of poller profiles to use (e.g., `docker`, `traefik`).

**YAML Example:**

```yaml
general:
  log_level: verbose
  log_timestamps: true
  dry_run: false
  poll_profiles:
    - docker
```

## Environment Variables

Provider, poll, and domain-specific environment variables are also supported. See the sample [.env](contrib/config/env.sample) file and documentation for more details.

The following environment variables can be used to configure DNS Companion:

| Variable         | Description                                       | Default |
| ---------------- | ------------------------------------------------- | ------- |
| `DRY_RUN`        | If true, do not perform actual DNS updates        | `false` |
| `LOG_LEVEL`      | Set log level (`trace` `debug`, `verbose`, `info`)           | `verbose`  |
| `LOG_TIMESTAMPS` | Include timestamps in log output (`true`/`false`) | `true`  |

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

**Default Environment Variables:**

| Variable                         | Description                                                |
| -------------------------------- | ---------------------------------------------------------- |
| `DEFAULT_RECORD_TYPE`            | Default DNS record type (maps to defaults.record.type)     |
| `DEFAULT_RECORD_TARGET`          | Default DNS record target (maps to defaults.record.target) |
| `DEFAULT_RECORD_TTL`             | Default DNS record TTL (maps to defaults.record.ttl)       |
| `DEFAULT_RECORD_UPDATE_EXISTING` | Update existing DNS records (`true`/`false`)               |

### Pollers

Pollers are components that discover containers or services to be managed. Each poller has its own configuration section and environment variables. Multiple pollers can be defined and used simultaneously.

**What is a Poller?**

A poller is a module that discovers resources (like containers or routers) to be managed for DNS. Each poller type (e.g., Docker, Traefik) has its own configuration and options.

#### Docker Poller

**Options for configuring a Docker poll provider:**

- `type`: (string) Must be `docker` for Docker poller.
- `api_url`: (string) Docker API endpoint (default: `unix:///var/run/docker.sock`).
- `api_auth_user`: (string) Username for basic auth to the Docker API (optional).
- `api_auth_pass`: (string) Password for basic auth to the Docker API (optional).
- `process_existing`: (bool) Process existing containers on startup (default: false).
- `expose_containers`: (bool) Expose all containers by default (default: false).
- `swarm_mode`: (bool) Enable Docker Swarm mode (default: false).
- `record_remove_on_stop`: (bool) Remove DNS records when containers stop (default: false).

Legacy options like `host` and `docker_host` are no longer supported.

See `contrib/sample-config.yaml` for an example configuration.

##### Config File

```yaml
polls:
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

##### Environment Variables

| Variable                                 | Description                                                      | Default                       |
| ---------------------------------------- | ---------------------------------------------------------------- | ----------------------------- |
| `API_URL`                                | Docker API endpoint (e.g., `tcp://111.222.111.32:2376`)          | `unix:///var/run/docker.sock` |
| `API_AUTH_USER`                          | Username for basic auth to the Docker API                       |                               |
| `API_AUTH_PASS`                          | Password for basic auth to the Docker API                       |                               |
| `PROCESS_EXISTING`                       | Process existing containers on startup                           | `false`                       |
| `EXPOSE_CONTAINERS`                      | Expose all containers without requiring explicit labels           | `false`                       |
| `SWARM_MODE`                             | Enable Docker Swarm Mode                                          | `false`                       |
| `RECORD_REMOVE_ON_STOP`                  | Remove DNS records when container stops                           | `false`                       |

| Variable                                   | Description                                                      | Default                       |
| ------------------------------------------ | ---------------------------------------------------------------- | ----------------------------- |
| `POLL_<PROFILENAME>_TYPE`                  | Poller type (docker, traefik, etc.)                              |                               |
| `POLL_<PROFILENAME>_API_URL`               | Docker API endpoint                                              |                               |
| `POLL_<PROFILENAME>_API_AUTH_USER`         | Username for basic auth to the Docker API                       |                               |
| `POLL_<PROFILENAME>_API_AUTH_PASS`         | Password for basic auth to the Docker API                       |                               |
| `POLL_<PROFILENAME>_PROCESS_EXISTING`      | Process existing containers on startup                           |                               |
| `POLL_<PROFILENAME>_EXPOSE_CONTAINERS`     | Expose containers (true/false)                                   |                               |
| `POLL_<PROFILENAME>_SWARM_MODE`            | Enable Docker Swarm mode                                         |                               |
| `POLL_<PROFILENAME>_RECORD_REMOVE_ON_STOP` | Remove DNS on stop (true/false)                                  |                               |

##### Usage of Docker Provider

##### Creating Records with Container Labels

DNS Companion supports two methods for specifying DNS records:

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

Use filtering to limit DNS management to only the containers you want, improving control and security.
Docker container filtering allows you to control which containers are managed by the poller, so you can include or exclude containers based on labels, names, or other criteria. This is useful for limiting DNS management to only the containers you want, improving control and security.

**Available filter types:**

- `none`: No filtering, all containers are considered.
- `label`: Only containers with specific labels are considered.
- `name`: Only containers with specific names are considered.

**How Filtering Works:**

- The `filter_type` option determines the filtering method. You can specify additional filter options depending on the type.
- Filtering is evaluated before any DNS records are created or updated.

**YAML Example: No Filtering (all containers):**

```yaml
polls:
  docker_example:
    type: docker
    ...
    filter_type: none
```

**YAML Example: Label Filtering**

Only containers with the label `nfrastack.dns.enable=true` will be managed:

```yaml
    filter_type: label
    filter_label: nfrastack.dns.enable
    filter_label_value: "true"
```

You can also filter by multiple labels (AND logic):

```yaml
    filter_type: label
    filter_labels:
      - key: nfrastack.dns.enable
        value: "true"
      - key: environment
        value: "production"
```

**YAML Example: Name Filtering**

Only containers with names matching the given list will be managed:

```yaml
    filter_type: name
    filter_names:
      - webapp
      - db
```

**Advanced Filtering (Boolean/Compound):**

Some advanced setups may support boolean logic or regular expressions for filtering. For example:

```yaml
    filter_type: label
    filter_labels:
      - key: nfrastack.dns.enable
        value: "true"
      - key: environment
        value: ".*prod.*" # regex match
    filter_label_logic: and # or 'or'
```

**Processing Order:**

1. The poller discovers all containers.
2. Filtering is applied according to the configuration.
3. Only containers passing the filter are considered for DNS management.

**Best Practices:**

- Use label filtering to target only containers that should be managed by DNS Companion.
- Combine multiple filters for fine-grained control.
- Use `filter_type: none` for development or testing, but restrict in production.

#### Traefik Poller

The Traefik poll provider discovers domain names from Traefik router rules via the Traefik API. It extracts hostnames from the `Host` rules in router configurations.

```yaml
polls:
  traefik_routers:
    type: traefik
    api_url: https://traefik.example.com/api/http/routers
    api_auth_user: admin
    api_auth_pass: password
    interval: 5m
    filter_type: name
    filter_value: ^websecure-
```

**Options for configuring a Traefik poll provider:**

- `type`: (string) Must be `traefik` for Traefik poller.
- `api_url`: The URL of the Traefik API to poll (e.g., `http://traefik:8080/api/http/routers`).
- `api_auth_user`: Username for basic auth to the Traefik API (optional).
- `api_auth_pass`: Password for basic auth to the Traefik API (optional).
- `interval`: How often to poll the Traefik API for updates (e.g., `15s`, `1m`, `1h`).
- `config_path`: (string) Path to the Traefik configuration file or directory to scan for routes and hostnames (for file-based config reading).

**Filter options:**

The Traefik provider supports filtering to precisely control which routers to process.

### Simple filter (single filter)

```yaml
polls:
  traefik_example:
    type: traefik
    api_url: http://traefik:8080/api/http/routers
    filter_type: name
    filter_value: ^web-
```

This will only process routers whose `name` matches the regex `^web-`.

### Advanced filters (multiple, AND/OR/NOT/Negate)

```yaml
polls:
  traefik_advanced:
    type: traefik
    api_url: http://traefik:8080/api/http/routers
    filter.0.type: name
    filter.0.value: ^web-
    filter.0.operation: AND
    filter.1.type: provider
    filter.1.value: docker
    filter.1.operation: OR
    filter.2.type: status
    filter.2.value: enabled
    filter.2.negate: true
```

- `operation` can be `AND`, `OR`, or `NOT` (default is `AND`).
- `negate: true` inverts the filter result.

You can use either style—**the loader will dynamically handle both**.

**Environment variables:**

Environment variables can also be used for authentication:
- `TRAEFIK_API_AUTH_USER`: Basic auth username
- `TRAEFIK_API_AUTH_PASS`: Basic auth password

##### Poller Traefik Configuration File

```yaml
polls:
  traefik_example:
    type: traefik
    api_url: http://traefik:8080/api/http/routers
    interval: 30s  # or 60, 1m, 1h, etc.
    config_path: /etc/traefik/dynamic
```

##### Poller Traefik Environment Variables

| Variable                                   | Description                                                      |
| ------------------------------------------ | ---------------------------------------------------------------- |
| `POLL_<PROFILENAME>_TYPE`                  | Value should be `traefik`                                        |
| `POLL_<PROFILENAME>_API_URL`               | Traefik API URL                                                  |
| `POLL_<PROFILENAME>_INTERVAL`              | Poll interval (supports units, e.g., `15s`, `1m`, `60` for 60 seconds) |
| `POLL_<PROFILENAME>_CONFIG_PATH`           | Path to Traefik configuration file or directory (file-based)     |

### Poller File Provider

The file provider allows you to manage DNS records by reading from a YAML or JSON file. It supports real-time file watching (default) or interval-based polling.

**Example configuration:**

```yaml
poll:
  - type: file
    name: file_example
    source: ./result/records.yaml
    format: yaml # or json - autodetects based on extension
    interval: -1 # (default: watch mode)
    record_remove_on_stop: true
    process_existing: true
```

**File format (YAML):**
```yaml
records:
  - host: www.example.com
    type: A
    ttl: 300
    target: 192.0.2.10
  - host: api.example.com
    type: CNAME
    target: www.example.com
```

**Options:**
- `source` (required): Path to the file.
- `format`: `yaml` (default) or `json`.
- `interval`: `-1` (default, watch mode), or a duration (e.g. `30s`).
- `record_remove_on_stop`: Remove DNS records when removed from file. Default: `false`.
- `process_existing`: Process all records on startup. Default: `false`.

### Remote Provider

The remote provider works just like the File provider but allows you to poll a remote YAML or JSON file over HTTP/HTTPS. It supports HTTP Basic Auth and interval-based polling.

#### Example configuration

```yaml
polls:
  remote_example:
    type: remote
    name: remote_example
    remote_url: https://example.com/records.yaml
    format: yaml # or json (optional, autodetects by extension)
    interval: 30s # Poll every 30 seconds
    process_existing: true
    record_remove_on_stop: true
    remote_auth_user: myuser # Optional HTTP Basic Auth
    remote_auth_pass: mypassword # Optional HTTP Basic Auth
```

#### Options

- `remote_url` (required): URL to the remote YAML or JSON file.
- `format`: `yaml` (default) or `json`.
- `interval`: How often to poll the remote file (e.g., `30s`).
- `process_existing`: Process all records on startup. Default: `false`.
- `record_remove_on_stop`: Remove DNS records when removed from remote. Default: `false`.
- `remote_auth_user`: Username for HTTP Basic Auth (optional).
- `remote_auth_pass`: Password for HTTP Basic Auth (optional).

See `contrib/file-provider.md` for file format details (same as file provider).

### Providers

Providers are components that manage DNS records. Each provider has its own configuration section and environment variables. Multiple providers can be defined and used for different domains.

#### Supported Providers

- **Cloudflare**: Manage DNS records via Cloudflare API.
- **hosts**: Write A/AAAA records to a hosts file (e.g. /etc/hosts). Supports file ownership and permissions. CNAMEs are flattened to A/AAAA records automatically.

#### Provider Configuration (YAML)

```yaml
providers:
  cloudflare_example:
    type: cloudflare
    api_token: your-api-token      # If using scoped access
    #api_email: your@email.address # If using Global API Key
    #api_key: your-global-api-key  # If using Global API Key
    zone_id: your-zone-id          # (if required)
```

#### Provider Environment Variables

| Variable                                          | Description                      |
| ------------------------------------------------- | -------------------------------- |
| `PROVIDER_<PROFILENAME>_TYPE`                     | Provider type (cloudflare, etc.) |
| `PROVIDER_<PROFILENAME>_API_TOKEN`                | API token                        |
| `PROVIDER_<PROFILENAME>_API_KEY`                  | API key                          |
| `PROVIDER_<PROFILENAME>_API_EMAIL`                | API email                        |
| `PROVIDER_<PROFILENAME>_<PROVIDER-TYPE>_<OPTION>` | Provider-specific options        |


## Hosts DNS Provider

The `hosts` DNS provider writes A/AAAA records to a hosts file (e.g. `dns-companion.hosts`).
CNAMEs are automatically flattened to A/AAAA records. Only A and AAAA records are supported.

**Configuration options:**

- `source` (string): Path to the hosts file to manage. Default: `./hosts`
- `user` (string): Username or UID to own the file. Optional.
- `group` (string): Group name or GID to own the file. Optional.
- `mode` (int): File permissions (e.g., 0644). Optional, default: 0644.
- `enable_ipv4` (bool): Whether to write IPv4 A records. Default: `true`
- `enable_ipv6` (bool): Whether to write IPv6 AAAA records. Default: `true`

**YAML Example:**

```yaml
providers:
  hosts_example:
    type: "hosts"
    source: "./hosts"
    user: nobody
    group: nogroup
    mode: 0644
    enable_ipv4: true
    enable_ipv6: false  # Skip IPv6 records
```

**Environment Variables:**

| Variable                            | Description                      | Default |
| ----------------------------------- | -------------------------------- | ------- |
| `PROVIDER_HOSTS_SOURCE`             | Path to hosts file               | `./hosts` |
| `PROVIDER_HOSTS_USER`               | File owner (user)                |         |
| `PROVIDER_HOSTS_GROUP`              | File owner (group)               |         |
| `PROVIDER_HOSTS_MODE`               | File permissions (octal)         | `0644`  |
| `PROVIDER_HOSTS_ENABLE_IPV4`        | Enable IPv4 A records            | `true`  |
| `PROVIDER_HOSTS_ENABLE_IPV6`        | Enable IPv6 AAAA records         | `true`  |

**Features:**

- The file will be created if it does not exist, and ownership/permissions will be set as configured.
- The hosts provider will flatten CNAME records to A/AAAA records automatically.
- Only A and AAAA records are supported in the hosts file format.
- IPv4/IPv6 filtering allows fine-grained control over which IP types are written.

### Domains

Domains define per-domain configuration, including which provider to use, zone ID, and record options. Each domain can override defaults and specify subdomain filters.

**Options:**

- `name` (string): The DNS domain name (e.g., `example.com`).
- `provider` (string): The provider profile to use for this domain (must match a key in the `providers` section).
- `zone_id` (string): The DNS provider's zone ID for this domain (if required by the provider).
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
  dom_example:
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
```

#### Domain Environment Variables

| Variable                                   | Description                            |
| ------------------------------------------ | -------------------------------------- |
| `DOMAIN_<PROFILENAME>_NAME`                | Domain name                            |
| `DOMAIN_<PROFILENAME>_ZONE_ID`             | Zone ID for the domain                 |
| `DOMAIN_<PROFILENAME>_PROVIDER`            | DNS provider for the domain            |
| `DOMAIN_<PROFILENAME>_TTL`                 | TTL for the domain                     |
| `DOMAIN_<PROFILENAME>_TARGET`              | Target for the domain                  |
| `DOMAIN_<PROFILENAME>_RECORD_TYPE`         | Record type for the domain             |
| `DOMAIN_<PROFILENAME>_PROXIED`             | (Cloudflare) Proxied setting           |
| `DOMAIN_<PROFILENAME>_UPDATE_EXISTING`     | Update existing records for the domain |
| `DOMAIN_<PROFILENAME>_EXCLUDED_SUBDOMAINS` | Excluded subdomains                    |
| `DOMAIN_<PROFILENAME>_OPTION_<key>`        | Custom domain option                   |

## Support

### Usage

- The [Discussions board](../../discussions) is a great place for working with the community.

### Bugfixes

- Please submit a [Bug Report](issues/new) if something isn't working as expected. I'll do my best to issue a fix in short order.

### Feature Requests

- Feel free to submit a feature request; however, there is no guarantee that it will be added or at what timeline.

### Updates

- Best effort to track upstream dependency changes, with more priority if I am actively using the tool.

## License

BSD-3-Clause. See [LICENSE](LICENSE) for more details.
