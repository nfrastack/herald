{ config, inputs, lib, pkgs, ... }: {
  imports = [
    inputs.herald.nixosModules.default
  ];

  services = {
    herald = {
      enable = true;

      general = {
        log_level = "verbose";
        log_timestamps = true;
        dry_run = false;
      };

      defaults = {
        record = {
          type = "A";
          ttl = 300;
          update_existing = true;
          allow_multiple = false;
        };
      };

      input = {
        # Docker containers with labels
        docker_public = {
          type = "docker";
          api_url = "unix:///var/run/docker.sock";
          expose_containers = true;
          process_existing = true;
          record_remove_on_stop = true;
          log_level = "debug";
          tls = {
            verify = false;
            ca = "";
            cert = "";
            key = "";
          };
          filter = [
            {
              type = "label";
              conditions = [
                {
                  key = "traefik.proxy.visibility";
                  value = "public";
                }
              ];
            }
          ];
        };

        # Caddy reverse proxy routes
        caddy_routes = {
          type = "caddy";
          api_url = "https://caddy.example.com/config/";
          api_auth_user = "admin";
          api_auth_pass = "password";
          interval = "30s";
          process_existing = true;
          record_remove_on_stop = true;
          tls = {
            verify = false;
            ca = "";
            cert = "";
            key = "";
          };
        };

        # Traefik reverse proxy routes
        traefik_routes = {
          type = "traefik";
          api_url = "https://traefik.example.com/api/http/routers";
          api_auth_user = "admin";
          api_auth_pass = "password";
          interval = "30s";
          process_existing = true;
          record_remove_on_stop = true;
          tls = {
            verify = false;
            ca = "";
            cert = "";
            key = "";
          };
        };

        # Tailscale VPN devices
        tailscale_vpn = {
          type = "tailscale";
          api_auth_id = "random_auth_id";
          api_auth_token = "tskey-client-xxxxx";
          domain = "vpn.example.com";
          interval = "60s";
          hostname_format = "simple";
          process_existing = true;
          filter = [
            {
              type = "online";
              conditions = [
                {
                  value = "true";
                }
              ];
            }
          ];
        };

        # ZeroTier network members
        zerotier_network = {
          type = "zerotier";
          api_token = "your-zerotier-token";
          network_id = "F2BD7A9E0CA0B96B";
          domain = "zt.example.com";
          interval = "60s";
          online_timeout_seconds = 300;
          process_existing = true;
          filter = [
            {
              type = "online";
              conditions = [
                {
                  value = "true";
                }
              ];
            }
          ];
        };

        # File-based DNS records
        file_records = {
          type = "file";
          source = "./records/dns-records.yaml";
          format = "yaml";
          interval = "-1"; # Watch for file changes
          process_existing = true;
        };

        # Remote DNS records
        remote_records = {
          type = "remote";
          url = "https://api.example.com/dns/records.json";
          format = "json";
          interval = "300s";
          auth_user = "api_user"; # optional
          auth_pass = "api_password"; # optional
          tls = {
            verify = true;
            ca = "/etc/ssl/certs/ca-bundle.crt";
            cert = "";
            key = "";
          };
        };
      };

      output = {
        # Live Cloudflare DNS
        cloudflare_dns = {
          type = "dns";
          provider = "cloudflare";
          api_token = "your-cloudflare-token";
          log_level = "info";
        };

        # Live PowerDNS API
        powerdns_dns = {
          type = "dns";
          provider = "powerdns";
          api_host = "http://powerdns.example.com:8081/api/v1";
          api_token = "your-powerdns-api-token";
          server_id = "localhost";
          tls = {
            ca = "/path/to/ca.pem";
            cert = "/path/to/client.pem";
            key = "/path/to/client.key";
            skip_verify = false;
          };
          log_level = "info";
        };

        # JSON backup files
        json_backup = {
          type = "file";
          format = "json";
          path = "./backups/%domain%.json";
          user = "herald";
          group = "herald";
          mode = 420; # 0644
        };

        # Zone files for BIND
        zone_files = {
          type = "file";
          format = "zone";
          path = "./zones/%domain%.zone";
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

        # Hosts file for local resolution
        hosts_file = {
          type = "file";
          format = "hosts";
          path = "/etc/hosts.d/herald.hosts";
          enable_ipv4 = true;
          enable_ipv6 = false;
          skip_loopback = true;
          flatten_cnames = true;
        };

        # YAML export
        yaml_export = {
          type = "file";
          format = "yaml";
          path = "./exports/%domain%.yml";
        };

        # Remote aggregation server
        aggregation_server = {
          type = "remote";
          url = "https://dns-aggregator.example.com/api/dns";
          client_id = "server-01";
          token = "aggregation-token";
          timeout = "30s";
          tls = {
            verify = true;
            ca = "/etc/ssl/certs/ca-bundle.crt";
            cert = "";
            key = "";
          };
        };
      };

      domains = {
        # Production domain - live DNS and backups
        example_com = {
          name = "example.com";
          profiles = {
            inputs = [ "docker_public" "caddy_routes" "traefik_routes" ];
            outputs = [ "cloudflare_dns" "json_backup" "zone_files" ];
          };
          record = {
            type = "A";
            target = "server.example.com";
            ttl = 300;
            update_existing = true;
          };
          exclude_subdomains = [ "dev" "staging" ];
        };

        # Test domain - files only, no live DNS
        test_com = {
          name = "test.com";
          profiles = {
            inputs = [ "docker_public" ];
            outputs = [ "json_backup" "yaml_export" ];
          };
          record = {
            type = "CNAME";
            target = "test-server.example.com";
            ttl = 120;
          };
        };

        # VPN domain - internal resolution only
        vpn_internal = {
          name = "vpn.example.com";
          profiles = {
            inputs = [ "tailscale_vpn" ];
            outputs = [ "hosts_file" "zone_files" ];
          };
          record = {
            type = "A";
            ttl = 60;
          };
        };

        # ZeroTier domain - aggregation and local files
        zerotier_internal = {
          name = "zt.example.com";
          profiles = {
            inputs = [ "zerotier_network" ];
            outputs = [ "hosts_file" "aggregation_server" ];
          };
          record = {
            type = "A";
            ttl = 120;
          };
        };

        # File-based records - all outputs
        file_based = {
          name = "api.example.com";
          profiles = {
            inputs = [ "file_records" "remote_records" ];
            outputs = [ "cloudflare_dns" "json_backup" ];
          };
        };
      };

      api = {
        enabled = true;
        port = "8080";
        listen = [ "all" "!docker*" "!lo" ];
        endpoint = "/api/dns";
        client_expiry = "10m";
        log_level = "info";
        profiles = {
          server1 = {
            token = "server1-secret-token";
            output_profile = "zone_files";
          };
          server2 = {
            token = "server2-secret-token";
            output_profile = "json_backup";
          };
        };
        tls = {
          cert = "/etc/ssl/herald/server.crt";
          key = "/etc/ssl/herald/server.key";
        };
      };

      include = [
        "/etc/herald/secrets.yml"
        "./local-overrides.yml"
      ];
    };
  };
}