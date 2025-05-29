# NixOS

This project provides a Nix flake that allows you to build, run, and configure the DNS Companion. Below are instructions on how to use it within Nix and NixOS.

## Adding as an Input

To use this flake as an input in your own flake, add the following to your `flake.nix`:

```nix
{
  inputs.dns-companion.url = "github:nfrastack/dns-companion";

  outputs = { self, nixpkgs, dns-companion }: {
    packages.default = dns-companion.packages.${system}.default;
  };
}
```

### NixOS Module

This flake provides a NixOS module that allows you to configure and run the DNS Companion as a systemd service. To use it, add the following to your `configuration.nix`. See [example](./configuration.nix)

#### Available Options

Here are the available options for the NixOS module (services.dns-companion):

* `enable` (bool): Enable or disable the service.
* `configFile` (str): Path to the YAML configuration file. Default: `dns-companion.yml`
* `package` (package): The package to use for the service. Default: the flake's Go build.
* `general` (attrs): General application settings. Example:
  * `log_level` (str): Logging level ("info", "debug", "verbose", etc.).
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
  * `caddy` (attrs):
    * `type` (str): "caddy"
    * `api_url` (str): Caddy Admin API URL.
    * `api_auth_user` (str): Username for basic auth to the Caddy API.
    * `api_auth_pass` (str): Password for basic auth to the Caddy API.
    * `interval` (str): Poll interval (supports units, e.g., "15s", "1m", "1h", or just "60" for 60 seconds).
    * `process_existing` (bool): Process existing routes on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when route is removed.
  * `file` (attrs):
    * `type` (str): "file"
    * `source` (str): Path to the YAML or JSON file.
    * `format` (string): File format. Supported: `yaml`, `json`, `hosts`, `zone`.
    * `interval` (str): Poll interval (e.g., "-1" for watch mode, or "30s").
    * `process_existing` (bool): Process all records on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when removed from file.
  * `remote` (attrs):
    * `type` (str): "remote"
    * `remote_url` (str): URL to the remote YAML or JSON file.
    * `format` (str): "yaml" (default) or "json".
    * `interval` (str): Poll interval (e.g., "30s").
    * `process_existing` (bool): Process all records on startup.
    * `record_remove_on_stop` (bool): Remove DNS records when removed from remote.
    * `remote_auth_user` (str): Username for HTTP Basic Auth (optional).
    * `remote_auth_pass` (str): Password for HTTP Basic Auth (optional).
  * `zerotier` (attrs):
    * `type` (str): "zerotier"
    * `api_url` (str): ZeroTier Central or ZT-Net API base URL (optional, defaults to <https://my.zerotier.com>)
    * `api_token` (str): API token for authentication
    * `api_type` (str, optional): "zerotier" or "ztnet". If omitted, will attempt to autodetect
    * `interval` (str, optional): Polling interval (e.g., "60s")
    * `network_id` (str): ZeroTier network ID (for ZT-Net: "org:domain:networkid" or "domain:networkid")
    * `domain` (str): Domain to append to hostnames (e.g., `zt.example.com`)
    * `online_timeout_seconds` (int): Seconds to consider a member offline (default: 60, recommend: 300+)
    * `process_existing` (bool): Process records on startup
    * `record_remove_on_stop` (bool): Remove DNS records when node goes offline
    * `use_address_fallback` (bool): Use ZeroTier address as hostname when name is empty
    * `filter_type` (string): Filter by: `online`, `name`, `authorized`, `tag`, `id`, `address`, `nodeid`, `ipAssignments`, `physicalAddress`
    * `filter_value` (string): Value for filter_type (default: `online=true`)
    * `log_level` (string): Provider-specific log level override (optional)
* `providers` (attrs): DNS provider profiles. Example:
  * `cloudflare` (attrs):
    * `type` (str): "cloudflare"
    * `api_token` (str): Cloudflare API token.
    * `api_email` (str): Cloudflare API email.
    * `api_key` (str): Cloudflare API Global Key
  * `hosts` (attrs):
    * `enable` (bool): Enable or disable the hosts provider.
    * `source` (string): Path to the hosts file to manage.
    * `user` (string): Username or UID to own the file. Optional.
    * `group` (string): Group name or GID to own the file. Optional.
    * `mode` (int): File permissions (e.g., 420 for 0644). Optional, default: 420 (0644).
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
* `outputs` (attrs): Output profile definitions. Example:
  * `hosts_export` (attrs):
    * `format` (str): Output format. One of "hosts", "json", "yaml", "zone".
    * `path` (str): Path to the output file.
    * `domains` (list of str or str): Domains this output applies to. Use "all", "ALL", "any", or "*" for all domains. If omitted, defaults to all domains. Lowercase "all" is preferred for style.
    * `user` (string, optional): File owner (username or UID).
    * `group` (string, optional): File group (group name or GID).
    * `mode` (int, optional): File permissions (e.g., 420 for 0644). Default: 420 (0644).
    * `enable_ipv4` (bool, hosts only): Write IPv4 A records. Default: true.
    * `enable_ipv6` (bool, hosts only): Write IPv6 AAAA records. Default: true.
    * `header_comment` (string, hosts only): Custom header comment.
    * `generator` (string, yaml/json): Custom generator identifier.
    * `hostname` (string, yaml/json): Hostname identifier for this export.
    * `comment` (string, yaml/json): Global comment for the export.
    * `indent` (bool, json only): Pretty print JSON output. Default: true.
    * `default_ttl` (int, zone only): Default TTL for zone records.
    * `soa` (attr, zone only): SOA record configuration.
    * `ns_records` (list, zone only): List of authoritative nameservers.
* `include` (str or list of str): One or more YAML files to include into the main configuration.

This setup allows you to fully configure and manage the DNS Companion service declaratively using NixOS.
