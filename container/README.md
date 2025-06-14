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
  - [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Persistent Storage](#persistent-storage)
  - [Environment Variables](#environment-variables)
    - [Container Options](#container-options)
    - [Provider Environment Variables](#provider-environment-variables)
    - [Domain Environment Variables](#domain-environment-variables)
    - [Integration Environment Variables](#integration-environment-variables)
- [Maintenance](#maintenance)
  - [Shell Access](#shell-access)
- [Support](#support)
  - [Usage](#usage)
  - [Bugfixes](#bugfixes)
  - [Feature Requests](#feature-requests)
  - [Updates](#updates)
- [License](#license)
- [References](#references)

## Prerequisites and Assumptions

- You have a Docker environment available to poll container information from
- You have access to your DNS server

## Installation

Automated builds of the image are available on [Docker Hub](https://hub.docker.com/r/nfrastack/herald)

```bash
docker pull nfrastack/herald:(imagetag)
```

Builds of the image are also available on the [Github Container Registry](https://github.com/nfrastack/herald/pkgs/container/herald)

```
docker pull ghcr.io/nfrastack/herald:(imagetag)
```

The following image tags are available along with the repository Releases:

- `latest` - Most recent release of herald w/ Alpine Linux

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
| `LOG_TYPE`          | Log to `console`, `file`, or `both`            | `console`    |
| `LOG_LEVEL`         | Logging level (`info`, `verbose`, etc)         | `info`       |
| `LOG_PATH`          | Log file directory                             | `/logs`      |
| `LOG_FILE`          | Log file name                                  | `herald.log` |
| `LOG_TIMESTAMPS`    | Show timestamps in logs (`TRUE`/`FALSE`)       | `TRUE`       |
| `CONFIG_PATH`       | Config file directory                          | `/config/`   |
| `CONFIG_FILE`       | Config file name                               | `herald.yml` |

#### Provider Environment Variables

| Variable                           | Description                      | Example/Default           |
| ---------------------------------- | -------------------------------- | ------------------------- |
| `PROVIDER_01_TYPE`                 | Provider type (e.g., cloudflare) | `cloudflare`              |
| `PROVIDER_01_CLOUDFLARE_API_TOKEN` | Cloudflare API token             | (required for Cloudflare) |
| `CLOUDFLARE_API_TOKEN`             | Global Cloudflare API token      | (optional)                |
| `CLOUDFLARE_API_EMAIL`             | Cloudflare API email             | (optional)                |
| `CLOUDFLARE_API_KEY`               | Cloudflare API key               | (optional)                |

#### Domain Environment Variables

| Variable                           | Description                           | Example/Default     |
| ---------------------------------- | ------------------------------------- | ------------------- |
| `DOMAIN_NAME`                      | Domain name                           |                     |
| `DOMAIN_01_NAME`                   | Domain name (legacy/compat)           | `example.com`       |
| `DOMAIN_01_PROVIDER`               | Provider profile to use               | `cloudflare`        |
| `DOMAIN_01_ZONE_ID`                | (optional) Zone ID for the domain     | `your_zone_id_here` |
| `DOMAIN_01_RECORD_TYPE`            | DNS record type                       | `A`                 |
| `DOMAIN_01_TTL`                    | TTL for the domain record             | `300`               |
| `DOMAIN_01_TARGET`                 | DNS record target                     | `192.0.2.1`         |
| `DOMAIN_01_UPDATE_EXISTING_RECORD` | Update existing records               | `TRUE` or `FALSE`   |
| `DOMAIN_01_ALLOW_MULTIPLE`         | Allow multiple records                | `TRUE` or `FALSE`   |
| `DOMAIN_01_INPUT`                  | Comma-separated list of inputs        | `docker`            |
| `DOMAIN_01_OUTPUT`                 | Comma-separated list of outputs       | `cloudflare`        |
| `DOMAIN_01_PROXIED`                | Enable Cloudflare proxying            | `FALSE`             |
| `DOMAIN_01_INPUTS`                 | (alt) Comma-separated list of inputs  |                     |
| `DOMAIN_01_OUTPUTS`                | (alt) Comma-separated list of outputs |                     |
| `DOMAIN_01_RECORD_TTL`             | TTL for the domain record (alt)       | `300`               |
| `DOMAIN_01_RECORD_TARGET`          | DNS record target (alt)               |                     |
| `DOMAIN_01_UPDATE_EXISTING`        | Update existing records (alt)         | `TRUE`              |

#### Integration Environment Variables

These variables control integration with Docker, Caddy, and Traefik. Prefixes are used for each integration.

##### Docker

| Variable                       | Description                            | Default/Example               |
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

| Variable                      | Description                               | Default/Example |
| ----------------------------- | ----------------------------------------- | --------------- |
| `CADDY_API_AUTH_PASS`         | Caddy API auth password                   |                 |
| `CADDY_API_AUTH_USER`         | Caddy API auth username                   |                 |
| `CADDY_API_URL`               | Caddy API URL                             |                 |
| `CADDY_INTERVAL`              | Poll interval for Caddy (seconds)         | `60`            |
| `CADDY_LOG_LEVEL`             | Log level for Caddy integration           |                 |
| `CADDY_PROCESS_EXISTING`      | Process existing Caddy configs on startup | `TRUE`          |
| `CADDY_RECORD_REMOVE_ON_STOP` | Remove DNS records on config removal      | `FALSE`         |
| `CADDY_TLS_CA_FILE`           | Path to Caddy CA cert                     |                 |
| `CADDY_TLS_CERT_FILE`         | Path to Caddy client cert                 |                 |
| `CADDY_TLS_KEY_FILE`          | Path to Caddy client key                  |                 |
| `CADDY_TLS_VERIFY`            | Enable Caddy TLS verification             | `TRUE`          |

##### Traefik

| Variable                        | Description                                 | Default/Example |
| ------------------------------- | ------------------------------------------- | --------------- |
| `TRAEFIK_API_AUTH_PASS`         | Traefik API auth password                   |                 |
| `TRAEFIK_API_AUTH_USER`         | Traefik API auth username                   |                 |
| `TRAEFIK_API_URL`               | Traefik API URL                             |                 |
| `TRAEFIK_INTERVAL`              | Poll interval for Traefik (seconds)         | `60`            |
| `TRAEFIK_LOG_LEVEL`             | Log level for Traefik integration           |                 |
| `TRAEFIK_PROCESS_EXISTING`      | Process existing Traefik routers on startup | `TRUE`          |
| `TRAEFIK_RECORD_REMOVE_ON_STOP` | Remove DNS records on router removal        | `FALSE`         |
| `TRAEFIK_TLS_CA_FILE`           | Path to Traefik CA cert                     |                 |
| `TRAEFIK_TLS_CERT_FILE`         | Path to Traefik client cert                 |                 |
| `TRAEFIK_TLS_KEY_FILE`          | Path to Traefik client key                  |                 |
| `TRAEFIK_TLS_VERIFY`            | Enable Traefik TLS verification             | `TRUE`          |

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

## Support

These images were built to serve a specific need in a production environment and gradually have had more functionality added based on requests from the community.

### Usage

- The [Discussions board](../../discussions) is a great place for working with the community on tips and tricks of using this image.
- [Contact](https://nfrastack.com) for personalized support

### Bugfixes

- Please, submit a [Bug Report](issues/new) if something isn't working as expected. I'll do my best to issue a fix in short order.

### Feature Requests

- Feel free to submit a feature request, however there is no guarantee that it will be added, or at what timeline.
- [Contact](https://nfrastack.com) regarding development of features.

### Updates

- Best effort to track upstream changes, More priority if I am actively using the image in a production environment.
- [Contact](https://nfrastack.com) for up to date releases.

## License

BSD-3-Clause. See [../LICENSE](LICENSE) for more details.

## References

- <https://github.com/tiredofit/docker-traefik-cloudflare-companion>
