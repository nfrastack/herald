# github.com/nfrastack/docker-herald

## About

Container file to build a [Herald](https://github.com/nfrastack/herald) container image for monitoring events and writing appropriate records to an upstream DNS server.

[Changelog](../CHANGELOG.md)

## Maintainer

- [Nfrastack](https://github.com/nfrastack/)

## Table of Contents

- [About](#about)
- [Maintainer](#maintainer)
- [Table of Contents](#table-of-contents)
- [Prerequisites and Assumptions](#prerequisites-and-assumptions)
- [Installation](#installation)
  - [Prebuilt Images](#prebuilt-images)
  - [Multi-Architecture Support](#multi-architecture-support)
  - [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Persistent Storage](#persistent-storage)
  - [Environment Variables](#environment-variables)
    - [Container Options](#container-options)
    - [Provider Environment Variables](#provider-environment-variables)
    - [Domain Environment Variables](#domain-environment-variables)
    - [Integration Environment Variables](#integration-environment-variables)
      - [Docker](#docker)
      - [Caddy](#caddy)
      - [Traefik](#traefik)
      - [Cloudflare Environment Variables](#cloudflare-environment-variables)
- [Maintenance](#maintenance)
  - [Shell Access](#shell-access)
- [Support & Maintenance](#support--maintenance)
- [References](#references)
- [License](#license)

## Prerequisites and Assumptions

- You have a Docker environment available to poll container information from
- You have access to your DNS server

## Installation

### Prebuilt Images

Feature limited builds of the image are available on the [Github Container Registry](https://github.com/nfrastack/container-herald/pkgs/container/herald) and [Docker Hub](https://hub.docker.com/r/nfrastack/herald).

To unlock advanced features, one must provide a code to be able to change specific environment variables from defaults. Support the development to gain access to a code.

To get access to the image use your container orchestrator to pull from the following locations:

```
ghcr.io/nfrastack/herald:(image_tag)
docker.io/nfrastack/herald:(image_tag)
```

Image tag syntax is:

`<image>:<optional tag>-<optional_distribution>_<optional_distribution_variant>`

Example:

`ghcr.io/nfrastack/container-herald:latest` or

`ghcr.io/nfrastack/container-herald:1.0` or

- `latest` will be the most recent commit
- An optional `tag` may exist that matches the [CHANGELOG](CHANGELOG.md) - These are the safest
- If it is built for multiple distributions there may exist a value of `alpine` or `debian`
- If there are multiple distribution variations it may include a version - see the registry for availability

Have a look at the container registries and see what tags are available.

#### Multi-Architecture Support

Images are built for `amd64` by default, with optional support for `arm64` and other architectures.

### Quick Start

- The quickest way to get started is using [docker-compose](https://docs.docker.com/compose/). See the [compose.yml](../contrib/compose/compose.yml) for a working example that can be modified for development or production use.
- Set various [environment variables](#environment-variables) to understand the capabilities of this image.
- Map [persistent storage](#persistent-storage) for access to configuration and data files for backup.

This container automatically generates configuration to poll either from a Docker, Traefik, or Caddy Reverse Proxy, and supports writing upstream to Cloudflare DNS. If you wish to perform more functions, disable the automatic configuration generation by setting `HERALD_SETUP_TYPE=manual`. You can then configure based on the upstream packages configuration format.

## Configuration

### Persistent Storage

| Folders                | Description                                                                                            |
| ---------------------- | ------------------------------------------------------------------------------------------------------ |
| `/logs/`               | Optional Log Path                                                                                      |
| `/config/`             | Optional Config File Path                                                                              |
| `/var/run/docker.sock` | (example) You must have access to a docker socket in order to utilize the Docker polling functionality |

### Environment Variables

Below are the main environment variables supported by the image, as reflected in the example compose file. Adjust as needed for your deployment.

#### Container Options

| Variable            | Description                                    | Default      |
| ------------------- | ---------------------------------------------- | ------------ |
| `TIMEZONE`          | Set container timezone                         | `UTC`        |
| `HERALD_SETUP_TYPE` | `auto` to generate config, `manual` for custom | `auto`       |
| `HERALD_USER`       | User to run as (`root` needed for docker.sock) | `herald`     |
| `LOG_TYPE`          | Log to `console`, `file`, or `both` or `none`  | `console`    |
| `LOG_LEVEL`         | Logging level (`info`, `verbose`, etc)         | `info`       |
| `LOG_PATH`          | Log file directory                             | `/logs/`     |
| `LOG_FILE`          | Log file name                                  | `herald.log` |
| `LOG_TIMESTAMPS`    | Show timestamps in logs (`TRUE`/`FALSE`)       | `TRUE`       |
| `CONFIG_PATH`       | Config file directory                          | `/config/`   |
| `CONFIG_FILE`       | Config file name                               | `herald.yml` |

#### Provider Environment Variables

| Variable               | Description                 | Default    |
| ---------------------- | --------------------------- | ---------- |
| `CLOUDFLARE_API_TOKEN` | Global Cloudflare API token | (optional) |
| `CLOUDFLARE_API_EMAIL` | Cloudflare API email        | (optional) |
| `CLOUDFLARE_API_KEY`   | Cloudflare API key          | (optional) |

>> Use either `CLOUDFLARE_API_EMAIL + _KEY` together or `CLOUDFLARE_API_TOKEN` on its own.

#### Domain Environment Variables

| Variable                           | Description                                                                | Default             |
| ---------------------------------- | -------------------------------------------------------------------------- | ------------------- |
| `DOMAIN_01_NAME`                   | Domain name                                                                | `example.com`       |
| `DOMAIN_01_PROVIDER`               | Provider profile to use                                                    | `cloudflare`        |
| `DOMAIN_01_ZONE_ID`                | (optional) Zone ID for the domain                                          | `your_zone_id_here` |
|                                    | Needed with `CLOUDFLARE_API_EMAIL` & `CLOUDFLARE_API_TOKEN`                |                     |
| `DOMAIN_01_INPUTS`                 | Comma-separated list of inputs eg `docker,traefik`                         |                     |
| `DOMAIN_01_OUTPUTS`                | Comma-separated list of outputs eg `cloudflare`                            | `cloudflare`        |
| `DOMAIN_01_RECORD_PROXIED`         | Enable Cloudflare proxying                                                 | `FALSE`             |
| `DOMAIN_01_RECORD_TARGET`          | DNS record target eg `192.0.2.1` for `A` or `host.example.com` for `CNAME` |                     |
| `DOMAIN_01_RECORD_TTL`             | TTL for the domain record                                                  | `300`               |
| `DOMAIN_01_RECORD_TYPE`            | DNS record type eg `A` or `CNAME`                                          | `CNAME`             |
| `DOMAIN_01_RECORD_UPDATE_EXISTING` | Update existing records                                                    | `FALSE`             |

>> If you don't set DOMAIN_XX_INPUTS it will automatically generate the values if you have `TRAEFIK_API_URL`, `CADDY_API_URL`, `DOCKER_API_URL` set

A limit of 3 domains can be configured when the containers advanced mode is disabled.

#### Integration Environment Variables

These variables control integration with Docker, Caddy, and Traefik. Prefixes are used for each integration.

##### Docker

| Variable                       | Description                            | Default                       |
| ------------------------------ | -------------------------------------- | ----------------------------- |
| `DOCKER_API_URL`               | Docker socket path                     | `unix:///var/run/docker.sock` |
| `DOCKER_API_AUTH_USER`         | Docker API auth username               |                               |
| `DOCKER_API_AUTH_PASS`         | Docker API auth password               |                               |
| `DOCKER_EXPOSE_CONTAINERS`     | Expose all Docker containers           | `TRUE`                        |
| `DOCKER_LOG_LEVEL`             | Log level for Docker integration       |                               |
| `DOCKER_PROCESS_EXISTING`      | Process existing containers on startup | `TRUE`                        |
| `DOCKER_RECORD_REMOVE_ON_STOP` | Remove DNS records on container stop   | `FALSE`                       |
| `DOCKER_SWARM_MODE`            | Enable Docker Swarm mode               | `FALSE`                       |
| `DOCKER_TLS_CA_FILE`           | Path to Docker CA cert                 |                               |
| `DOCKER_TLS_CERT_FILE`         | Path to Docker client cert             |                               |
| `DOCKER_TLS_KEY_FILE`          | Path to Docker client key              |                               |
| `DOCKER_TLS_VERIFY`            | Enable Docker TLS verification         | `TRUE`                        |

##### Caddy

| Variable                      | Description                               | Default |
| ----------------------------- | ----------------------------------------- | ------- |
| `CADDY_API_AUTH_PASS`         | Caddy API auth password                   |         |
| `CADDY_API_AUTH_USER`         | Caddy API auth username                   |         |
| `CADDY_API_URL`               | Caddy API URL                             |         |
| `CADDY_INTERVAL`              | Poll interval for Caddy (seconds)         | `60`    |
| `CADDY_LOG_LEVEL`             | Log level for Caddy integration           |         |
| `CADDY_PROCESS_EXISTING`      | Process existing Caddy configs on startup | `TRUE`  |
| `CADDY_RECORD_REMOVE_ON_STOP` | Remove DNS records on config removal      | `FALSE` |
| `CADDY_TLS_CA_FILE`           | Path to Caddy CA cert                     |         |
| `CADDY_TLS_CERT_FILE`         | Path to Caddy client cert                 |         |
| `CADDY_TLS_KEY_FILE`          | Path to Caddy client key                  |         |
| `CADDY_TLS_VERIFY`            | Enable Caddy TLS verification             | `TRUE`  |

##### Traefik

| Variable                        | Description                                 | Default |
| ------------------------------- | ------------------------------------------- | ------- |
| `TRAEFIK_API_AUTH_PASS`         | Traefik API auth password                   |         |
| `TRAEFIK_API_AUTH_USER`         | Traefik API auth username                   |         |
| `TRAEFIK_API_URL`               | Traefik API URL                             |         |
| `TRAEFIK_INTERVAL`              | Poll interval for Traefik (seconds)         | `60`    |
| `TRAEFIK_LOG_LEVEL`             | Log level for Traefik integration           |         |
| `TRAEFIK_PROCESS_EXISTING`      | Process existing Traefik routers on startup | `TRUE`  |
| `TRAEFIK_RECORD_REMOVE_ON_STOP` | Remove DNS records on router removal        | `FALSE` |
| `TRAEFIK_TLS_CA_FILE`           | Path to Traefik CA cert                     |         |
| `TRAEFIK_TLS_CERT_FILE`         | Path to Traefik client cert                 |         |
| `TRAEFIK_TLS_KEY_FILE`          | Path to Traefik client key                  |         |
| `TRAEFIK_TLS_VERIFY`            | Enable Traefik TLS verification             | `TRUE`  |

#### Cloudflare Environment Variables

| Variable               | Description                 | Default/Example |
| ---------------------- | --------------------------- | --------------- |
| `CLOUDFLARE_API_TOKEN` | Global Cloudflare API token | (optional)      |
| `CLOUDFLARE_API_EMAIL` | Cloudflare API email        | (optional)      |
| `CLOUDFLARE_API_KEY`   | Cloudflare API key          | (optional)      |

>> The EMAIL and KEY are only required if using Global API keys. It is recommended to create a scoped token.

## Maintenance

### Shell Access

For debugging and maintenance purposes you may want access the containers shell.

```bash
docker exec -it herald bash
```

## Support & Maintenance

- For community help, tips, and community discussions, visit the [Discussions board](/../../discussions).
- For personalized support or a support agreement, see [Nfrastack Support](https://nfrastack.com/).
- To report bugs, submit a [Bug Report](issues/new). Usage questions will be closed as not-a-bug.
- Feature requests are welcome, but not guaranteed. For prioritized development, consider a support agreement.
- Updates are best-effort, with priority given to active production use and support agreements.

## References

- <https://github.com/tiredofit/docker-traefik-cloudflare-companion>

## License

BSD-3-Clause. See [../LICENSE](LICENSE) for more details.
