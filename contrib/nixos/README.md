# NixOS

This project provides a Nix flake that allows you to build, run, and configure the Container DNS Companion. Below are instructions on how to use it within Nix and NixOS.

## Adding as an Input

To use this flake as an input in your own flake, add the following to your `flake.nix`:

```nix
{
  inputs.container-dns-companion.url = "github:nfrastack/container-dns-companion";

  outputs = { self, nixpkgs, container-dns-companion }: {
    packages.default = container-dns-companion.packages.${system}.default;
  };
}
```

### NixOS Module

This flake provides a NixOS module that allows you to configure and run the Container DNS Companion as a systemd service. To use it, add the following to your `configuration.nix`:

```nix
{
  imports = [
    inputs.container-dns-companion.nixosModules.default
  ];

  services.container-dns-companion = {
    enable = true;
    configFile = "container-dns-companion.yml";
    general = {
      log_level = "info";
      log_timestamps = true;
      poll_profiles = [ "docker" ];
    };
    defaults = {
      record = {
        type = "A";
        ttl = 300;
        update_existing = true;
        allow_multiple = false;
      };
    };
    polls = {
      docker = {
        type = "docker";
        host = "unix:///var/run/docker.sock";
        expose_containers = true;
        filter_type = "none";
        record_remove_on_stop = false;
      };
      traefik = {
        type = "traefik";
        api_url = "http://traefik:8080/api/http/routers";
        api_auth_user = "admin";
        api_auth_pass = "password";
        interval = "15s";
        process_existing = true;
        record_remove_on_stop = true;
      };
    };
    providers = {
      cloudflare = {
        type = "cloudflare";
        api_token = "your-api-token";
      };
    };
    domains = {
      example_com = {
        name = "example.com";
        provider = "cloudflare";
        zone_id = "your_zone_id_here";
        record = {
          type = "A";
          ttl = 60;
          target = "192.0.2.1";
          update_existing = true;
          allow_multiple = true;
        };
        include_subdomains = [ "api" "internal" ];
        exclude_subdomains = [ "dev" "staging" ];
      };
    };
    include = [
      "/etc/container-dns-companion/extra1.yml"
      "/etc/container-dns-companion/extra2.yml"
    ];
  };
}
```

#### Available Options

Here are the available options for the NixOS module (services.container-dns-companion):

* `enable` (bool): Enable or disable the service.
* `configFile` (str): Path to the YAML configuration file. Default: `container-dns-companion.yml`
* `package` (package): The package to use for the service. Default: the flake's Go build.
* `general` (attrs): General application settings. Example:
  * `log_level` (str): Logging level ("info", "debug", etc.).
  * `log_timestamps` (bool): Show timestamps in logs.
  * `poll_profiles` (list of str): List of poll profiles to use.
* `defaults` (attrs): Default DNS record settings. Example:
  * `record` (attrs):
    * `type` (str): DNS record type ("A", "AAAA", etc.).
    * `ttl` (int): Time to live.
    * `update_existing` (bool): Update existing records.
    * `allow_multiple` (bool): Allow multiple records.
* `polls` (attrs): Poll provider profiles. Example:
  * `docker` (attrs):
    * `type` (str): "docker"
    * `api_url` (str): Docker socket path.
    * `api_auth_user` (str): Username for basic auth to the Docker API.
    * `api_auth_pass` (str): Password for basic auth to the Docker API.
    * `expose_containers` (bool): Expose all containers.
    * `process_existing` (bool): Process existing containers on startup.
    * `filter_type` (str): Filter type.
    * `record_remove_on_stop` (bool): Remove DNS records on stop.
  * `traefik` (attrs):
    * `type` (str): "traefik"
    * `api_url` (str): Traefik API URL.
    * `api_auth_user` (str): Username for basic auth to the Traefik API.
    * `api_auth_pass` (str): Password for basic auth to the Traefik API.
    * `interval` (str): Poll interval (supports units, e.g., "15s", "1m", "1h", or just "60" for 60 seconds).
    * `process_existing` (bool): Process existing routers on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when router is removed.
* `providers` (attrs): DNS provider profiles. Example:
  * `cloudflare` (attrs):
    * `type` (str): "cloudflare"
    * `api_token` (str): Cloudflare API token.
    * `api_email` (str): Cloudflare API email.
    * `api_key` (str): Cloudflare API Global Key
* `domains` (attrs): Domain profiles. Example:
  * `example_com` (attrs):
    * `name` (str): Domain name.
    * `provider` (str): Provider profile to use.
    * `zone_id` (str): Zone ID for the domain.
    * `record` (attrs):
      * `type` (str): DNS record type.
      * `ttl` (int): Time to live.
      * `target` (str): DNS target.
      * `update_existing` (bool): Update existing records.
      * `allow_multiple` (bool): Allow multiple records.
    * `include_subdomains` (list of str): Subdomains to include.
    * `exclude_subdomains` (list of str): Subdomains to exclude.
* `include` (str or list of str): One or more YAML files to include into the main configuration.

This setup allows you to fully configure and manage the Container DNS Companion service declaratively using NixOS.
