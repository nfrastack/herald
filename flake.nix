{
  description = "DNS Companion - Dynamic DNS management for Docker, Traefik, Files, Remote sources, Tailscale, and ZeroTier/ZT-Net networks";

  inputs = { nixpkgs.url = "nixpkgs/nixos-unstable"; };

  outputs = { self, nixpkgs }:
    let
      version = "1.2.1";
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
    in {
      packages = forAllSystems (system:
        let pkgs = nixpkgsFor.${system};
        in {
          dns-companion = pkgs.buildGoModule {
            pname = "dns-companion";
            inherit version;
            src = ./.;

            meta = {
              description = "DNS Companion - Dynamic DNS record management for modern infrastructure. Supports Docker, Traefik, File, Remote, Tailscale, and ZeroTier/ZT-Net poll providers.";
              homepage = "https://github.com/nfrastack/dns-companion";
              license = "BSD-3-Clause";
              maintainers = [
                {
                  name = "nfrastack";
                  email = "code@nfrastack.com";
                  github = "nfrastack";
                }
              ];
            };

            preBuild = ''
              export BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
            '';

           ldflags = [
             "-s"
             "-w"
             "-X main.Version=${version}"
             "-X main.BuildTime=$BUILD_DATE"
           ];

            vendorHash = "sha256-XREPZAt2a1ZUgYGR9VfyTIcsCsvCJCpHEC/e607fWok=";
          };
        });

      devShells = forAllSystems (system:
        let pkgs = nixpkgsFor.${system};
        in pkgs.mkShell {
          buildInputs = with pkgs; [
            gnumake
            go
          ];
        });

      devShell = forAllSystems (system: self.devShells.${system});

      defaultPackage = forAllSystems (system: self.packages.${system}.dns-companion);

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.dns-companion;

          # Utility function to get directory part of path
          getDir = path:
            let
              components = builtins.match "(.*)/.*" path;
            in
              if components == null then "." else builtins.head components;

          # Helper to reorder 'type' to the top of each profile
          reorderTypeFirst = profileAttrs: (
            if profileAttrs ? type then { type = profileAttrs.type; } // (builtins.removeAttrs profileAttrs ["type"]) else profileAttrs
          );

          reorderSection = section: builtins.mapAttrs (_: reorderTypeFirst) section;
        in {
          options.services.dns-companion = {
            enable = lib.mkEnableOption {
              default = false;
              description = "Enable the DNS Companion module to configure the tool.";
            };

            service.enable = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Enable the systemd service for DNS Companion.";
            };

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.dns-companion;
              description = "DNS Companion package to use.";
            };

            configFile = lib.mkOption {
              type = lib.types.str;
              default = "dns-companion.yml";
              description = "Path to the YAML configuration file for DNS Companion.";
            };

            defaults = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
              example = {
                record = {
                  type = "A";
                  ttl = 300;
                  update_existing = true;
                  allow_multiple = false;
                };
              };
              description = "Default DNS record settings.";
            };

            general = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {
                log_level = "verbose";
                log_timestamps = false;
              };
              example = {
                log_level = "verbose";
                log_timestamps = true;
                dry_run = false;
                poll_profiles = [ "docker" ];
                output_profiles = [ "hosts_export" "json_export" ];
              };
              description = "General application settings.";
            };

            providers = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              example = {
                cloudflare = {
                  type = "cloudflare";
                  api_token = "EXAMPLE_TOKEN";
                };
              };
              description = "DNS provider profiles.";
            };

            polls = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              example = {
                docker = {
                  type = "docker";
                  api_url = "unix:///var/run/docker.sock";
                  api_auth_user = "";
                  api_auth_pass = "";
                  process_existing = false;
                  expose_containers = false;
                  swarm_mode = false;
                  record_remove_on_stop = false;
                  filter = [
                    {
                      type = "label";
                      conditions = [
                        {
                          key = "environment";
                          value = "production";
                        }
                      ];
                    }
                  ];
                  tls = {
                    verify = true;
                    ca = "/etc/docker/certs/ca.pem";
                    cert = "/etc/docker/certs/cert.pem";
                    key = "/etc/docker/certs/key.pem";
                  };
                };
                traefik = {
                  type = "traefik";
                  api_url = "http://traefik:8080/api/http/routers";
                  api_auth_user = "admin";
                  api_auth_pass = "password";
                  interval = "60s";
                  record_remove_on_stop = true;
                  process_existing = true;
                  filter = [
                    {
                      type = "name";
                      conditions = [
                        {
                          value = "^websecure-.*";
                        }
                      ];
                    }
                  ];
                };
                caddy = {
                  type = "caddy";
                  api_url = "http://caddy:2019/config/";
                  api_auth_user = "";
                  api_auth_pass = "";
                  interval = "60s";
                  record_remove_on_stop = true;
                  process_existing = true;
                  filter = [
                    {
                      type = "host";
                      conditions = [
                        {
                          value = "*.localhost";
                        }
                      ];
                    }
                  ];
                };
                file = {
                  type = "file";
                  source = "/var/lib/dns-companion/records.yaml";
                  format = "yaml";
                  interval = "-1";
                  record_remove_on_stop = true;
                  process_existing = true;
                  filter = [
                    {
                      type = "hostname";
                      conditions = [
                        {
                          value = "*.example.com";
                        }
                      ];
                    }
                  ];
                };
                remote = {
                  type = "remote";
                  remote_url = "https://example.com/records.yaml";
                  format = "yaml";
                  interval = "30s";
                  process_existing = true;
                  record_remove_on_stop = true;
                  remote_auth_user = "myuser";
                  remote_auth_pass = "mypassword";
                  filter = [
                    {
                      type = "hostname";
                      conditions = [
                        {
                          value = "*.example.com";
                        }
                      ];
                    }
                  ];
                };
                tailscale = {
                  type = "tailscale";
                  api_key = "tskey-api-xxxxx";
                  tailnet = "-";
                  domain = "ts.example.com";
                  interval = "120s";
                  hostname_format = "simple";
                  process_existing = true;
                  record_remove_on_stop = true;
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
                zerotier = {
                  enable = lib.mkEnableOption "Enable Zerotier poll provider";
                  api_url = lib.mkOption {
                    type = lib.types.str;
                    description = "Zerotier Central or ZT-Net API base URL.";
                  };

                  api_type = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = "API type: 'zerotier' or 'ztnet'. Optional, autodetects if omitted.";
                  };

                  api_token = lib.mkOption {
                    type = lib.types.str;
                    description = "API token for Zerotier or ZT-Net.";
                  };

                 interval = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = "Polling interval (e.g., '60s'). Optional.";
                  };

                  online_timeout_seconds = lib.mkOption {
                    type = lib.types.nullOr lib.types.int;
                    default = null;
                    description = "Seconds to consider a member offline (default: 60, recommend: 300+).";
                  };

                  use_address_fallback = lib.mkOption {
                    type = lib.types.nullOr lib.types.bool;
                    default = null;
                    description = "Use ZeroTier address as hostname when name is empty.";
                  };

                  log_level = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = "Provider-specific log level override (optional).";
                  };
                  network_id = lib.mkOption {
                    type = lib.types.str;
                    description = "Zerotier network ID.";
                  };
                  domain = lib.mkOption {
                    type = lib.types.str;
                    description = "Domain to append to Zerotier hostnames.";
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
                  filter = lib.mkOption {
                    type = lib.types.listOf (lib.types.attrsOf lib.types.anything);
                    default = [
                      {
                        type = "online";
                        conditions = [
                          {
                            value = "true";
                          }
                        ];
                      }
                    ];
                    description = "Modern filter configuration using conditions array format.";
                  };
                };
              };
              description = "Poll profiles for service/container discovery. Each key is the poller name, and the value is an attribute set of options for that poller. TLS options for Docker are nested under 'tls'.";
            };

            domains = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              example = {
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
                  include_subdomains = [ ];
                  exclude_subdomains = [ "dev" "staging" ];
                };
              };
              description = ''
                Domain profiles. Each key is the domain profile name, and the value is an attribute set of options for that domain.
                Output configuration is now handled separately via the outputs.profiles section.
              '';
            };

            outputs = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              example = {
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
                send_to_api = {
                  format = "remote";
                  url = "https://dns-master.company.com/api/dns";
                  client_id = "server1";
                  token = "your_bearer_token_here";
                  timeout = "30s";
                  data_format = "json";
                  log_level = "info";
                  tls = {
                    verify = true;
                    ca = "/etc/ssl/ca/server-ca.pem";
                    cert = "/etc/ssl/certs/client.pem";
                    key = "/etc/ssl/private/client.key";
                  };
                };
              };
              description = ''
                Output profile system. Configure multiple independent output profiles
                that can target specific domains, multiple domains, or all domains ("all").

                Each profile supports format-specific options like SOA records for zone files,
                metadata for YAML/JSON exports, and file ownership settings.

                The remote_api format allows pushing DNS records to a central aggregation server.
              '';
            };

            api = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
              example = {
                enabled = true;
                port = "8080";
                listen = [ "all" "!docker*" "!lo" ];
                endpoint = "/api/dns";
                client_expiry = "10m";
                log_level = "info";
                profiles = {
                  server1 = {
                    token = "your_bearer_token_here";
                    output_profile = "aggregated_zones";
                  };
                  server2 = {
                    token = "file:///var/run/secrets/server2_token";
                    output_profile = "special_zones";
                  };
                };
                tls = {
                  cert = "/etc/ssl/certs/dns-companion.crt";
                  key = "/etc/ssl/private/dns-companion.key";
                  ca = "/etc/ssl/ca/client-ca.pem";
                };
              };
              description = ''
                API server configuration for receiving DNS records from remote dns-companion instances.

                Features:
                - Bearer token authentication per client
                - Failed attempt tracking and rate limiting
                - TLS with optional mutual authentication
                - Comprehensive security logging
                - Automatic client expiry and cleanup
                - Route client data to different output profiles
              '';
            };

            include = lib.mkOption {
              type = with lib.types; either str (listOf str);
              default = null;
              example = [ "/etc/dns-companion/extra1.yml" "/etc/dns-companion/extra2.yml" ];
              description = ''
                One or more YAML files to include into the main configuration. Can be a string (single file) or a list of file paths.
                Example:
                include = "/etc/dns-companion/extra.yml";
                or
                include = [ "/etc/dns-companion/extra1.yml" "/etc/dns-companion/extra2.yml" ];
                Included files are merged into the main config. Later files override earlier ones.
              '';
            };

            format = lib.mkOption {
              type = lib.types.str;
              default = "yaml";
              description = ''
                File format for DNS records. Supported: "yaml", "json", "hosts", "zone".
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];

            environment.etc."${lib.removePrefix "/etc/" cfg.configFile}".source =
              let
                yaml = pkgs.formats.yaml { };
                configData =
                  (if cfg.general != {} then { general = cfg.general; } else {})
                  // (if cfg.defaults != {} then { defaults = cfg.defaults; } else {})
                  // (if cfg.polls != {} then { polls = reorderSection cfg.polls; } else {})
                  // (if cfg.providers != {} then { providers = reorderSection cfg.providers; } else {})
                  // (if cfg.domains != {} then { domains = cfg.domains; } else {})
                  // (if cfg.outputs != {} then { outputs = cfg.outputs; } else {})
                  // (if cfg.api != {} then { api = cfg.api; } else {})
                  // (if cfg.include != null then { include = cfg.include; } else {});
              in yaml.generate "dns-companion.yml" configData;

            systemd.services.dns-companion = lib.mkIf cfg.service.enable {
              description = "DNS Companion";
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart =
                  let
                    configFileArg = "-config /etc/${cfg.configFile}";
                    args = lib.strings.concatStringsSep " " (lib.lists.filter (s: s != "") [
                      "${cfg.package}/bin/dns-companion"
                      configFileArg
                    ]);
                  in args;
                User = "root";
                Group = "root";
              };
            };
          };
        };
    };
}
