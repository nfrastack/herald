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
      };
      providers = {
        dnsprovider01 = {
          type = "cloudflare";
          api_token = "abcdef1234567890abcdef1234567890abcdef1234";
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