# NixOS

This project provides a Nix flake that allows you to build, run, and configure the herald. Below are instructions on how to use it within Nix and NixOS.

## Adding as an Input

To use this flake as an input in your own flake, add the following to your `flake.nix`:

```nix
{
  inputs.herald.url = "github:nfrastack/herald";

  outputs = { self, nixpkgs, herald }: {
    packages.default = herald.packages.${system}.default;
  };
}
```

### NixOS Module

This flake provides a NixOS module that allows you to configure and run the herald as a systemd service. To use it, add the following to your `configuration.nix`. See [example](./configuration.nix)

#### Available Options

Here are the available options for the NixOS module (services.herald):

* `enable` (bool): Enable or disable the service.
* `configFile` (str): Path to the YAML configuration file. Default: `herald.yml`
* `package` (package): The package to use for the service. Default: the flake's Go build.
* `general` (attrs): General application settings.
  * `log_level` (str): Logging level ("info", "debug", "verbose", etc.).
  * `log_timestamps` (bool): Show timestamps in logs.
  * `dry_run` (bool): Enable dry run mode (no actual DNS changes).
* `defaults` (attrs): Default DNS record settings applied to all domains.
  * `record` (attrs):
    * `type` (str): DNS record type ("A", "AAAA", "CNAME", etc.).
    * `ttl` (int): Time to live in seconds.
    * `update_existing` (bool): Update existing records.
    * `allow_multiple` (bool): Allow multiple records for same name.
* `input` (attrs): Input provider configurations for discovering DNS records.
  * `docker_example` (attrs):
    * `type` (str): "docker"
    * `api_url` (str): Docker socket path or API URL.
    * `api_auth_user` (str): Username for Docker API authentication.
    * `api_auth_pass` (str): Password for Docker API authentication.
    * `interval` (str): Poll interval (e.g., "60s").
    * `process_existing` (bool): Process existing containers on startup.
    * `expose_containers` (bool): Expose containers without labels.
    * `swarm_mode` (bool): Enable Docker Swarm mode support.
    * `record_remove_on_stop` (bool): Remove DNS records when containers stop.
    * `filter` (list): Advanced filtering configuration using conditions array.
    * `tls` (attrs): TLS configuration for Docker API.
  * `traefik_example` (attrs):
    * `type` (str): "traefik"
    * `api_url` (str): Traefik API URL.
    * `api_auth_user` (str): Username for Traefik API authentication.
    * `api_auth_pass` (str): Password for Traefik API authentication.
    * `interval` (str): Poll interval (e.g., "60s").
    * `process_existing` (bool): Process existing routers on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when routers are removed.
    * `filter` (list): Advanced filtering configuration.
  * `caddy_example` (attrs):
    * `type` (str): "caddy"
    * `api_url` (str): Caddy Admin API URL.
    * `api_auth_user` (str): Username for Caddy API authentication.
    * `api_auth_pass` (str): Password for Caddy API authentication.
    * `interval` (str): Poll interval (e.g., "60s").
    * `process_existing` (bool): Process existing routes on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when routes are removed.
    * `filter` (list): Advanced filtering configuration.
  * `file_example` (attrs):
    * `type` (str): "file"
    * `source` (str): Path to the file containing DNS records.
    * `format` (str): File format ("yaml", "json", "hosts", "zone").
    * `interval` (str): Poll interval ("-1" for watch mode, "30s" for polling).
    * `process_existing` (bool): Process all records on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when removed from file.
    * `filter` (list): Advanced filtering configuration.
  * `remote_example` (attrs):
    * `type` (str): "remote"
    * `remote_url` (str): URL to fetch remote DNS records.
    * `format` (str): Remote file format ("yaml", "json", "hosts").
    * `interval` (str): Poll interval (e.g., "30s").
    * `process_existing` (bool): Process all records on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when removed from remote.
    * `remote_auth_user` (str): Username for HTTP Basic Auth.
    * `remote_auth_pass` (str): Password for HTTP Basic Auth.
    * `filter` (list): Advanced filtering configuration.
    * `tls` (attrs): TLS configuration for HTTPS requests.
  * `tailscale_example` (attrs):
    * `type` (str): "tailscale"
    * `api_key` (str): Tailscale API key or personal access token.
    * `api_auth_token` (str): OAuth client secret (alternative to api_key).
    * `api_auth_id` (str): OAuth client ID (required with api_auth_token).
    * `api_url` (str): API URL (defaults to Tailscale Central, specify for Headscale).
    * `tailnet` (str): Tailnet ID or namespace (defaults to "-").
    * `domain` (str): Domain suffix for DNS records.
    * `interval` (str): Polling interval (default: "120s").
    * `hostname_format` (str): Hostname format ("simple", "tailscale", "full").
    * `process_existing` (bool): Process existing devices on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when devices go offline.
    * `filter` (list): Advanced filtering configuration.
    * `log_level` (str): Provider-specific log level override.
  * `zerotier_example` (attrs):
    * `type` (str): "zerotier"
    * `api_url` (str): ZeroTier Central or ZT-Net API base URL.
    * `api_token` (str): API token for authentication.
    * `api_type` (str): API type ("zerotier" or "ztnet", autodetects if omitted).
    * `interval` (str): Polling interval (e.g., "60s").
    * `network_id` (str): ZeroTier network ID.
    * `domain` (str): Domain to append to hostnames.
    * `online_timeout_seconds` (int): Seconds to consider a member offline.
    * `process_existing` (bool): Process records on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when node goes offline.
    * `use_address_fallback` (bool): Use ZeroTier address as hostname when name is empty.
    * `filter` (list): Advanced filtering configuration.
    * `log_level` (str): Provider-specific log level override.
* `output` (attrs): Output configurations for exporting DNS records.
  * `hosts_export` (attrs):
    * `format` (str): "hosts"
    * `path` (str): Path to the hosts file output.
    * `domains` (list): List of domains to include (["all"] for all domains).
    * `user` (str): File owner (username or UID).
    * `group` (str): File group (group name or GID).
    * `mode` (int): File permissions (e.g., 420 for 0644).
    * `enable_ipv4` (bool): Write IPv4 A records.
    * `enable_ipv6` (bool): Write IPv6 AAAA records.
    * `header_comment` (str): Custom header comment.
  * `json_export` (attrs):
    * `format` (str): "json"
    * `path` (str): Path to the JSON file output.
    * `domains` (list): List of domains to include.
    * `user` (str): File owner.
    * `group` (str): File group.
    * `mode` (int): File permissions.
    * `generator` (str): Custom generator identifier.
    * `hostname` (str): Hostname identifier for this export.
    * `comment` (str): Global comment for the export.
    * `indent` (bool): Pretty print JSON output.
  * `yaml_export` (attrs):
    * `format` (str): "yaml"
    * `path` (str): Path to the YAML file output.
    * `domains` (list): List of domains to include.
    * `user` (str): File owner.
    * `group` (str): File group.
    * `mode` (int): File permissions.
    * `generator` (str): Custom generator identifier.
    * `hostname` (str): Hostname identifier for this export.
    * `comment` (str): Global comment for the export.
  * `zone_export` (attrs):
    * `format` (str): "zone"
    * `path` (str): Path to the zone file output.
    * `domains` (list): List of domains to include.
    * `user` (str): File owner.
    * `group` (str): File group.
    * `mode` (int): File permissions.
    * `default_ttl` (int): Default TTL for zone records.
    * `soa` (attrs): SOA record configuration.
    * `ns_records` (list): List of authoritative nameservers.
  * `remote_api` (attrs):
    * `format` (str): "remote"
    * `url` (str): Remote aggregator URL.
    * `domains` (list): List of domains to include.
    * `client_id` (str): Unique client identifier.
    * `token` (str): Bearer authentication token.
    * `timeout` (str): HTTP request timeout.
    * `data_format` (str): Data format ("json" or "yaml").
    * `log_level` (str): Output-specific log level override.
    * `tls` (attrs): TLS configuration for HTTPS.
  * `dns_provider` (attrs):
    * `type` (str): "dns"
    * `provider` (str): DNS provider type ("cloudflare").
    * `api_token` (str): API token for Cloudflare/DigitalOcean/Linode.
    * `api_email` (str): Cloudflare API email (for Global API Key method).
    * `api_key` (str): Cloudflare Global API Key.
    * `aws_access_key_id` (str): AWS Access Key ID for Route53.
    * `aws_secret_access_key` (str): AWS Secret Access Key for Route53.
    * `aws_region` (str): AWS region for Route53.
    * `aws_profile` (str): AWS profile name (alternative to keys).
* `domains` (attrs): Domain configurations mapping domain keys to DNS providers.
  * `example_com` (attrs):
    * `name` (str): Actual domain name.
    * `provider` (str): DNS provider profile to use.
    * `zone_id` (str): Zone ID for the domain (provider-specific).
    * `record` (attrs): Default record settings for this domain.
    * `include_subdomains` (list): Specific subdomains to include.
    * `exclude_subdomains` (list): Specific subdomains to exclude.
    * `profiles` (attrs): Input and output profile associations.
      * `inputs` (list): List of input provider names that can create records for this domain.
      * `outputs` (list): List of output profile names that should process records for this domain.
* `api` (attrs): API server configuration for receiving DNS records from remote instances.
  * `enabled` (bool): Enable the API server.
  * `port` (str): Server port (default: "8080").
  * `listen` (list): Interface patterns to listen on.
  * `endpoint` (str): HTTP endpoint path (default: "/api/dns").
  * `client_expiry` (str): How long to keep client data (default: "10m").
  * `log_level` (str): API server log level override.
  * `profiles` (attrs): Client authentication profiles.
  * `tls` (attrs): TLS configuration for HTTPS.
* `include` (str or list): Additional YAML configuration files to include.

This setup allows you to fully configure and manage the herald service declaratively using NixOS.
