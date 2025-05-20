{
  description = "Manage DNS records based on DNS servers based on events from Docker or Traefik";

  inputs = { nixpkgs.url = "nixpkgs/nixos-unstable"; };


  outputs = { self, nixpkgs }:
    let
      version = "1.0.0";
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
          container-dns-companion = pkgs.buildGoModule {
            pname = "container-dns-companion";
            inherit version;
            src = ./.;

            meta = {
              description = "Manage DNS records based on DNS servers based on events from Docker or Traefik";
              homepage = "https://github.com/nfrastack/container-dns-companion";
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

            vendorHash = "sha256-nN0lt1FLx4KeRKlAEzIDv5ejcQWaIcu/myOtaGwtj0I=";
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

      defaultPackage = forAllSystems (system: self.packages.${system}.container-dns-companion);

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.container-dns-companion;

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
          options.services.container-dns-companion = {
            enable = lib.mkEnableOption {
              default = false;
              description = "Enable the Container DNS Companion module to configure the tool.";
            };

            service.enable = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Enable the systemd service for Container DNS Companion.";
            };

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.container-dns-companion;
              description = "Container DNS Companion package to use.";
            };

            configFile = lib.mkOption {
              type = lib.types.str;
              default = "container-dns-companion.yml";
              description = "Path to the YAML configuration file for Container DNS Companion.";
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
                log_level = "info";
                log_timestamps = false;
              };
              example = {
                log_level = "info";
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
                  host = "unix:///var/run/docker.sock";
                  expose_containers = true;
                  filter_type = "none";
                  process_existing_containers = false;
                  record_remove_on_stop = true;
                  tls = {
                    verify = true;
                    ca = "/etc/docker/certs/ca.pem";
                    cert = "/etc/docker/certs/cert.pem";
                    key = "/etc/docker/certs/key.pem";
                  };
                };
                traefik = {
                  type = "traefik";
                  poll_url = "http://traefik:8080/api/http/routers";
                  poll_interval = 60;
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
              example = [ "/etc/container-dns-companion/extra1.yml" "/etc/container-dns-companion/extra2.yml" ];
              description = ''
                One or more YAML files to include into the main configuration. Can be a string (single file) or a list of file paths.
                Example:
                include = "/etc/container-dns-companion/extra.yml";
                or
                include = [ "/etc/container-dns-companion/extra1.yml" "/etc/container-dns-companion/extra2.yml" ];
                Included files are merged into the main config. Later files override earlier ones.
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
                  // (if cfg.include != null then { include = cfg.include; } else {});
              in yaml.generate "container-dns-companion.yml" configData;

            systemd.services.container-dns-companion = lib.mkIf cfg.service.enable {
              description = "Container DNS Companion";
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart =
                  let
                    configFileArg = "-config /etc/${cfg.configFile}";
                    args = lib.strings.concatStringsSep " " (lib.lists.filter (s: s != "") [
                      "${cfg.package}/bin/container-dns-companion"
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
