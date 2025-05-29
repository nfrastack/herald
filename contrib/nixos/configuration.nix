{ config, inputs, lib, pkgs, ... }: {
  imports = [
    inputs.dns-companion.nixosModules.default
  ];

  services = {
    dns-companion = {
      enable = true;
      general = {
        log_level = "verbose";
      };
      defaults = {
        record = {
          ttl = 300;
          update_existing = true;
          allow_multiple = true;
        };
      };
      polls = {
        pollprovider01 = {
          type = "docker";
          host = "unix:///var/run/docker.sock";
          api_auth_user = "";
          api_auth_pass = "";
          expose_containers = true;
          swarm = false;
          record_remove_on_stop = false;
        };
        traefikpoller01 = {
          type = "traefik";
          api_url = "http://traefik:8080/api/http/routers";
          api_auth_user = "admin";
          api_auth_pass = "password";
          interval = "60s";
          process_existing = true;
          record_remove_on_stop = true;
        };
        filepoller01 = {
          type = "file";
          source = "/var/lib/dns-companion/records.yaml";
          format = "yaml";
          interval = "-1"; # watch mode (default)
          record_remove_on_stop = true;
          process_existing = true;

          # Supported formats: yaml, json, hosts, zone
          # Example for YAML format (default):
          #   format = "yaml";
          # Example for hosts file:
          #   format = "hosts";
          # Example for zone file:
          #   format = "zone";
        };
        remotepoller01 = {
          type = "remote";
          source = "https://example.com/records.json";
          format = "json";
          interval = "30s";
          process_existing = true;
          record_remove_on_stop = true;
          http_user = "myuser";
          http_pass = "mypassword";
        };
        zerotier_example = {
          type = "zerotier";
          api_url = "https://my.zerotier.com";        # ZeroTier Central or ZT-Net API URL (optional)
          api_token = "your_zerotier_api_token_here"; # Replace with your actual token
          # api_type = "zerotier";                    # "zerotier" or "ztnet" (optional, autodetects)
          interval = "60s";                           # Polling interval (optional, default: 60s)
          network_id = "YOUR_NETWORK_ID";             # For ZT-Net: "org:domain.com:networkid" format
          domain = "zt.example.com";                  # Domain suffix for DNS records
          online_timeout_seconds = 300;               # Time to consider member offline (recommend 300+)
          process_existing = true;                    # Process records on startup (default: false)
          record_remove_on_stop = true;               # Remove DNS records when node goes offline
          use_address_fallback = true;                # Use ZeroTier address as hostname when name empty
          filter_type = "online";                     # Filter: online, name, authorized, tag, etc.
          filter_value = "true";                      # Value for filter_type (default: online=true)
          log_level = "debug";                        # Provider-specific log level override (optional)
        };
      };
      providers = {
        dnsprovider01 = {
          type = "cloudflare";
          api_token = "abcdef1234567890abcdef1234567890abcdef1234";
        };
        zerotier = {
          enable = lib.mkEnableOption "Enable Zerotier poll provider";
          api_url = lib.mkOption {
            type = lib.types.str;
            description = "Zerotier Central or ZT-Net API base URL.";
          };
          api_token = lib.mkOption {
            type = lib.types.str;
            description = "API token for Zerotier or ZT-Net.";
          };
          network_id = lib.mkOption {
            type = lib.types.str;
            description = "Zerotier network ID.";
          };
          domain = lib.mkOption {
            type = lib.types.str;
            description = "Domain to append to Zerotier hostnames.";
          };
          api_type = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "API type: 'zerotier' or 'ztnet'. Optional, autodetects if omitted.";
          };
          interval = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "Polling interval (e.g., '60s'). Optional.";
          };
          process_existing = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Process records on startup.";
          };
          record_remove_on_stop = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Remove DNS records when node is removed or offline.";
          };
          filter_type = lib.mkOption {
            type = lib.types.str;
            default = "online";
            description = "Filter by: online, name, authorized, tag, id, address, nodeid.";
          };
          filter_value = lib.mkOption {
            type = lib.types.str;
            default = "true";
            description = "Value for filter_type (default: online=true).";
          };
        };
      };
      domains = {
        domain01 = {
          name = "example.com";
          provider = "dnsprovider01";
          record = {
            target = "hostname.example.com";
            ttl = 120;
            update_existing = true;
          };
          outputs = {
            zonefile = {
              path = "/var/named/example.com.zone";
              user = "named";
              group = "named";
              mode = 644;
              default_ttl = 300;
              soa = {
                primary_ns = "ns1.example.com";
                admin_email = "admin@example.com";
                serial = "auto";
                refresh = 3600;
                retry = 900;
                expire = 604800;
                minimum = 300;
              };
              ns_records = [ "ns1.example.com" "ns2.example.com" ];
            };
            yaml = {
              path = "/backup/dns/example.com.yaml";
              user = "dns-backup";
              group = "dns-backup";
              mode = 644;
              generator = "dns-companion-prod";
              hostname = "server01.example.com";
              comment = "Production DNS records for example.com";
            };
            json = {
              path = "/var/www/api/dns/example.com.json";
              user = "www-data";
              group = "www-data";
              mode = 644;
              generator = "dns-companion";
              hostname = "api-server.example.com";
              comment = "API-accessible DNS records";
              indent = true;
            };
            hosts_export = {
              format = "hosts";
              path = "/etc/hosts.dns-companion";
              domains = [ "all" ];
              user = "root";
              group = "root";
              mode = 420; # 0644
              enable_ipv4 = true;
              enable_ipv6 = false;
              header_comment = "Managed by DNS Companion";
            };
            json_export = {
              format = "json";
              path = "/var/lib/dns-companion/records.json";
              domains = [ "example.com" "test.com" ];
              user = "dns-companion";
              group = "dns-companion";
              mode = 420;
              generator = "dns-companion-nixos";
              hostname = "nixos-server";
              comment = "Exported DNS records";
              indent = true;
            };
          };
        };
      };
    };
  };
}