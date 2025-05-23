# github.com/nfrastack/docker-container-dns-companion

## About

Dockerfile to build an [Container-dns-companion DNS Cache](https://github.com/nfrastack/container-dns-companion) container image for monitoring events and writing appropriate records to an upstream DNS server.

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
    - [Poll Provider Environment Variables](#poll-provider-environment-variables)
      - [Defaults](#defaults)
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

Automated builds of the image are available on [Docker Hub](https://hub.docker.com/r/nfrastack/container-dns-companion)

```bash
docker pull hub.docker.com/nfrastack/container-dns-companion:(imagetag)
```

Builds of the image are also available on the [Github Container Registry](https://github.com/nfrastack/container-dns-companion/pkgs/container/container-dns-companion)

```
docker pull ghcr.io/nfrastack/container-dns-companion:(imagetag)
```

The following image tags are available along with the repository Releases:

- `latest` - Most recent release of container-dns-companion w/ Alpine Linux

### Quick Start

- The quickest way to get started is using [docker-compose](https://docs.docker.com/compose/). See the examples folder for a working [compose.yml](../contrib/container/compose.yml) that can be modified for development or production use.

- Set various [environment variables](#environment-variables) to understand the capabilities of this image.
- Map [persistent storage](#data-volumes) for access to configuration and data files for backup.

## Configuration

### Persistent Storage

| Folders   | Description               |
| --------- | ------------------------- |
| `/logs/`  | Optional Log Path         |
| `config/` | Optional Config File Path |
| `/var/run/docker.sock` | (example) You must have access to a docker socket in order to utilize the Docker polling functionality |

### Environment Variables

- This Container uses a [customized Alpine Linux base](https://hub.docker.com/r/nfrastack/base) that contains advanced functionality for logging, metrics, monitoring and more.

Along with the Environment Variables from the [Base image](https://hub.docker.com/r/nfrastack/base), below are the complete list of available options that can be used to customize your installation.

#### Container Options

| Variable         | Description                                     | Default                               |
| ---------------- | ----------------------------------------------- | ------------------------------------- |
| `CDC_USER`       | User to run as                                  | `cdc`                                   |
| `CDC_GROUP`      | Group to run as                                 | `cdc`                                   |
| `CDC_SETUP_TYPE` | `AUTO` generate config file.                    | `AUTO`                                |
| `CONFIG_FILE`    | Path to config file (alternative to `-config`)  | `/config/container-dns-companion.yml` |
| `LOG_TYPE`       | Display on `console`, write to `file` or `both` | `console`                             |
| `LOG_PATH`       | Log file directory                              | `/logs/`                              |
| `LOG_FILE`       | Log file name                                   | `cdc.log`                             |
| `LOG_LEVEL`      | Logging level `info`, `default`, or `trace`     | `info`                                |
| `LOG_TIMESTAMPS` | Show timestamps in logs (`TRUE`/`FALSE`)        | `TRUE`                                |

#### Provider Environment Variables

Create as many providers as you want under the syntax of `PROVIDER_`<PROFILENAME>`_<OPTION>`

| Variable                           | Description                      | Example/Default           |
| ---------------------------------- | -------------------------------- | ------------------------- |
| `PROVIDER_01_TYPE`                 | Provider type (e.g., cloudflare) | `cloudflare`              |
| `PROVIDER_01_CLOUDFLARE_API_TOKEN` | Cloudflare API token             | (required for Cloudflare) |
| `PROVIDER_01_CLOUDFLARE_API_EMAIL` | Cloudflare API email             | (optional)                |
| `PROVIDER_01_CLOUDFLARE_API_KEY`   | Cloudflare API key               | (optional)                |

#### Domain Environment Variables

Create as many domains as you want under the syntax of `DOMAIN_`<PROFILENAME>`_<OPTION>`

| Variable                           | Description                              | Example              |
| ---------------------------------- | ---------------------------------------- | -------------------- |
| `DOMAIN_01_NAME`                   | Domain name                              | `example.com`        |
| `DOMAIN_01_PROVIDER`               | Provider profile to use                  | `01`                 |
| `DOMAIN_01_ZONE_ID`                | (optional) Zone ID for the domain        | `your_zone_id_here`  |
| `DOMAIN_01_TTL`                    | TTL for the domain record                | `300`                |
| `DOMAIN_01_RECORD_TYPE`            | DNS record type                          | `A`, `AAAA`, `CNAME` |
| `DOMAIN_01_TARGET`                 | DNS record target                        | `192.0.2.1`          |
| `DOMAIN_01_UPDATE_EXISTING_RECORD` | Update existing records                  | `TRUE` or `FALSE`    |
| `DOMAIN_01_ALLOW_MULTIPLE`         | Allow multiple records                   | `TRUE` or `FALSE`    |
| `DOMAIN_01_EXCLUDE_SUBDOMAINS`     | Comma-separated subdomains to exclude eg | `dev,staging`        |
| `DOMAIN_01_INCLUDE_SUBDOMAINS`     | Comma-separated subdomains to include eg | `api,internal`       |

#### Poll Provider Environment Variables

If you don't add anything in the Poll Provider environment variables the following options will be used per provider type.

##### Defaults

| Variable                                     | Description                                   | Default/Example                        |
| -------------------------------------------- | --------------------------------------------- | -------------------------------------- |
| `DEFAULT_POLL_DOCKER_API_URL`                | Docker socket path                            | `unix:///var/run/docker.sock`          |
| `DEFAULT_POLL_DOCKER_API_AUTH_USER`          | Docker API basic auth user                    | (optional)                             |
| `DEFAULT_POLL_DOCKER_API_AUTH_PASS`          | Docker API basic auth password                | (optional)                             |
| `DEFAULT_POLL_DOCKER_EXPOSE_CONTAINERS`      | Expose all Docker containers                  | `TRUE`                                 |
| `DEFAULT_POLL_DOCKER_FILTER_TYPE`            | Docker poll filter type                       | `none`                                 |
| `DEFAULT_POLL_DOCKER_PROCESS_EXISTING`       | Process existing Docker containers on startup | `TRUE`                                 |
| `DEFAULT_POLL_DOCKER_RECORD_REMOVE_ON_STOP`  | Remove DNS records on container stop          | `FALSE`                                |
| `DEFAULT_POLL_DOCKER_SWARM_MODE`             | Enable Docker Swarm mode                      | `FALSE`                                |
| `DEFAULT_POLL_TRAEFIK_API_URL`               | Docker socket path                            | `http://traefik:8080/api/http/routers` |
| `DEFAULT_POLL_TRAEFIK_API_AUTH_USER`         | Docker API basic auth user                    | (optional)                             |
| `DEFAULT_POLL_TRAEFIK_API_AUTH_PASS`         | Docker API basic auth password                | (optional)                             |
| `DEFAULT_POLL_TRAEFIK_FILTER_TYPE`           | Traefik poll filter type                      | `none`                                 |
| `DEFAULT_POLL_TRAEFIK_INTERVAL`              | Traefik poll interval (seconds)               | `60`                                   |
| `DEFAULT_POLL_TRAEFIK_PROCESS_EXISTING`      | Process existing Traefik Routers at startup   | `TRUE`                                 |
| `DEFAULT_POLL_TRAEFIK_RECORD_REMOVE_ON_STOP` | Remove DNS records on container stop          | `FALSE`                                |

Create as many poll providers as you want under the syntax of `POLL_<PROFILENAME>_<OPTION>`

| Variable                        | Description                                   | Example                                |
| ------------------------------- | --------------------------------------------- | -------------------------------------- |
| `POLL_01_TYPE`                  | Poll provider type                            | `docker` `traefik`                     |
| `POLL_01_API_URL`               | API Endpoint (Docker socket or Traefik API)   | `unix:///var/run/docker.sock`          |
|                                 |                                               | `http://traefik:8080/api/http/routers` |
| `POLL_01_API_AUTH_USER`         | Basic Authentication User                     | (optional)                             |
| `POLL_01_API_AUTH_PASS`         | Basic Authentication Pass                     | (optional)                             |
| `POLL_01_EXPOSE_CONTAINERS`     | Expose all Docker containers                  | `TRUE`                                 |
| `POLL_01_FILTER_TYPE`           | Poll filter type                              | `none`                                 |
| `POLL_01_FILTER_VALUE`          | Poll filter value                             | (optional)                             |
| `POLL_01_PROCESS_EXISTING`      | Process existing Docker containers on startup | `TRUE`                                 |
| `POLL_01_RECORD_REMOVE_ON_STOP` | Remove DNS records on container stop          | `FALSE`                                |
| `POLL_01_SWARM_MODE`            | Enable Docker Swarm mode                      | `FALSE`                                |
| `POLL_01_TLS_CA_PATH`           | Path to Docker TLS CA cert                    | (optional)                             |
| `POLL_01_TLS_CERT_PATH`         | Path to Docker TLS cert                       | (optional)                             |
| `POLL_01_TLS_KEY_PATH`          | Path to Docker TLS key                        | (optional)                             |
| `POLL_01_TLS_VERIFY`            | Verify Docker TLS connection                  | `TRUE` or `FALSE`                      |
| `POLL_01_INTERVAL`              | Traefik poll interval (seconds)               | `60`                                   |

## Maintenance

### Shell Access

For debugging and maintenance purposes you may want access the containers shell.

```bash
docker exec -it (whatever your container name is e.g. container-dns-companion) bash
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
