{
  description = "Manage DNS records based on DNS servers based on events from Docker or Traefik";

  inputs = { nixpkgs.url = "nixpkgs/nixos-unstable"; };


  outputs = { self, nixpkgs }:
    let
      version = "dev";
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
              description = "Manage DNS records based on DNS servers based on events from Docker or Traefik";
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
                };
                file = {
                  type = "file";
                  source = "/var/lib/dns-companion/records.yaml";
                  format = "yaml";
                  interval = "-1";
                  record_remove_on_stop = true;
                  process_existing = true;
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
              description = "Domain profiles. Each key is the domain profile name, and the value is an attribute set of options for that domain.";
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

            hosts = {
              enable = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = ''
                  Enable the hosts DNS provider. Writes A/AAAA records to a hosts file. CNAMEs are flattened automatically.
                '';
              };
              source = lib.mkOption {
                type = lib.types.str;
                default = "./dns-companion.hosts";
                description = "Path to the hosts file to manage.";
              };
              user = lib.mkOption {
                type = lib.types.str;
                default = "";
                description = "Username or UID to own the file (optional).";
              };
              group = lib.mkOption {
                type = lib.types.str;
                default = "";
                description = "Group name or GID to own the file (optional).";
              };
              mode = lib.mkOption {
                type = lib.types.int;
                default = 420; # 0644
                description = "File permissions (e.g., 420 for 0644).";
              };
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
