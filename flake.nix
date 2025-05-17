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

            ldflags = [
              "-s"
              "-w"
              "-X main.Version=${version}"
            ];

            vendorHash = "sha256-G8WP9nEKwNaRGHjWBlfSZboxw2qSsHcZHjazlMsR2vU=";
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

            configFile = lib.mkOption {
              type = lib.types.str;
              default = "/etc/dns-companion.conf";
              description = "Path to the configuration file for Container DNS Companion.";
            };

            log_level = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "debug";
              description = "Set the logging level (e.g., debug, info).";
            };

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.container-dns-companion;
              description = "Container DNS Companion package to use.";
            };

            log_timestamps = lib.mkOption {
              type = lib.types.nullOr lib.types.bool;
              default = null;
              example = true;
              description = "Enable or disable log timestamps.";
            };

            poll_profiles = lib.mkOption {
              type = lib.types.nullOr (lib.types.listOf lib.types.str);
              default = null;
              example = [ "docker" ];
              description = "List of poll profiles to use.";
            };

            dns_provider = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "cloudflare";
              description = "Default DNS provider profile to use.";
            };

            dns_record_type = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "A";
              description = "Default DNS record type (e.g., A, AAAA, CNAME).";
            };

            dns_record_ttl = lib.mkOption {
              type = lib.types.nullOr lib.types.int;
              default = null;
              example = 300;
              description = "Default DNS record TTL.";
            };

            dns_record_target = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "";
              description = "Default DNS record target.";
            };

            record_update_existing = lib.mkOption {
              type = lib.types.nullOr lib.types.bool;
              default = null;
              example = true;
              description = "Whether to update existing DNS records.";
            };

            record_type_a_multiple = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Allow multiple A records for this domain (default: false).
                When enabled, the system will manage multiple A records for the same hostname.
                Requires record_update_existing = true. Prevents duplicate IPv4 addresses.
              '';
            };

            record_type_aaaa_multiple = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Allow multiple AAAA records for this domain (default: false).
                When enabled, the system will manage multiple AAAA records for the same hostname.
                Requires record_update_existing = true. Prevents duplicate IPv6 addresses.
              '';
            };

            providers = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              example = {
                cloudflare = {
                  type = "cloudflare";
                  api_token = "EXAMPLE_TOKEN";
                };
                route53 = {
                  type = "route53";
                  region = "us-west-2";
                };
              };
              description = ''
                DNS provider profiles. Each attribute key is the provider name, and the value is an attribute set of options for that provider.
                Example:
                  providers.cloudflare = { type = "cloudflare"; api_token = "..."; };
                  providers.route53 = { type = "route53"; region = "us-west-2"; };
              '';
            };

            polls = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = { };
              example = {
                docker = {
                  type = "docker";
                  host = "unix:///var/run/docker.sock";
                  record_remove_on_stop = false;
                  docker_tls_verify = lib.mkOption {
                    type = lib.types.nullOr lib.types.bool;
                    default = null;
                    description = ''
                      Enable TLS verification for Docker API (optional, only used if provided).
                    '';
                  };
                  docker_cert_path = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = ''
                      Directory containing ca.pem, cert.pem, key.pem for Docker TLS (optional).
                    '';
                  };
                  docker_ca = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = ''
                      Path to CA certificate (overrides cert_path, optional).
                    '';
                  };
                  docker_cert = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = ''
                      Path to client certificate (overrides cert_path, optional).
                    '';
                  };
                  docker_key = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = ''
                      Path to client key (overrides cert_path, optional).
                    '';
                  };
                };
                traefik = {
                  type = "traefik";
                  poll_url = "http://traefik:8080/api/http/routers";
                };
              };
              description = ''
                Poll profiles for service/container discovery. Each attribute key is the poller name, and the value is an attribute set of options for that poller.
                Example:
                  polls.docker = { type = "docker"; host = "unix:///var/run/docker.sock"; record_remove_on_stop = false; };
                  polls.traefik = { type = "traefik"; poll_url = "http://traefik:8080/api/http/routers"; };
              '';
            };

            domains = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              example = {
                example_com = {
                  name = "example.com";
                  provider = "cloudflare";
                  ttl = 120;
                  record_type = "CNAME";
                  target = "test.example.com";
                };
              };
              description = ''
                Domain profiles. Each attribute key is the domain profile name, and the value is an attribute set of options for that domain.
                Example:
                  domains.example_com = { name = "example.com"; provider = "cloudflare"; ... };
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];

            # Only write config if user set any global option or has any profiles
            system.activationScripts = lib.mkIf (
              cfg.log_level != null ||
              cfg.log_timestamps != null ||
              cfg.poll_profiles != null ||
              cfg.dns_provider != null ||
              cfg.dns_record_type != null ||
              cfg.dns_record_ttl != null ||
              cfg.dns_record_target != null ||
              cfg.record_update_existing != null ||
              cfg.record_type_a_multiple != null ||
              cfg.record_type_aaaa_multiple != null ||
              cfg.providers != {} ||
              cfg.polls != {} ||
              cfg.domains != {}
            ) {
              container-dns-companion-config = {
                text =
                  let
                    globalOpts = lib.filterAttrs (k: v: v != null) {
                      log_level = cfg.log_level;
                      log_timestamps = cfg.log_timestamps;
                      poll_profiles = cfg.poll_profiles;
                      dns_provider = cfg.dns_provider;
                      dns_record_type = cfg.dns_record_type;
                      dns_record_ttl = cfg.dns_record_ttl;
                      dns_record_target = cfg.dns_record_target;
                      record_update_existing = cfg.record_update_existing;
                      record_type_a_multiple = cfg.record_type_a_multiple;
                      record_type_aaaa_multiple = cfg.record_type_aaaa_multiple;
                    };
                    toConfValue = v:
                      if builtins.isList v then
                        "[" + (lib.concatStringsSep ", " (map (x: toConfValue x) v)) + "]"
                      else if builtins.isBool v then
                        (if v then "true" else "false")
                      else if builtins.isInt v then
                        builtins.toString v
                      else
                        "\"${builtins.toString v}\"";
                    renderSection = name: attrs:
                      if attrs == {} then ""
                      else
                        "[${name}]\n" +
                        (lib.concatStringsSep "\n" (
                          lib.mapAttrsToList (k: v: "${k} = ${toConfValue v}") attrs
                        )) + "\n";
                    globalSection = renderSection "global" globalOpts;
                    providerSections = lib.concatStringsSep "\n" (
                      lib.mapAttrsToList (name: opts: renderSection "provider.${name}" opts) cfg.providers
                    );
                    pollSections = lib.concatStringsSep "\n" (
                      lib.mapAttrsToList (name: opts: renderSection "poll.${name}" opts) cfg.polls
                    );
                    domainSections = lib.concatStringsSep "\n" (
                      lib.mapAttrsToList (name: opts: renderSection "domain.${name}" opts) cfg.domains
                    );
                    configText = lib.concatStringsSep "\n" [
                      globalSection
                      providerSections
                      pollSections
                      domainSections
                    ];
                  in
                    ''
                      if [ ! -e "${getDir cfg.configFile}" ]; then
                        mkdir -p "${getDir cfg.configFile}"
                      fi
                      cat > ${cfg.configFile} <<'EOC'
                      ${configText}
                      EOC
                      chmod 0600 ${cfg.configFile}
                    '';
                deps = [];
              };
            };

            systemd.services.container-dns-companion = lib.mkIf cfg.service.enable {
              description = "Container DNS Companion";
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart =
                  let
                    needsConfigFile =
                      cfg.log_level != null ||
                      cfg.log_timestamps != null ||
                      cfg.poll_profiles != null ||
                      cfg.dns_provider != null ||
                      cfg.dns_record_type != null ||
                      cfg.dns_record_ttl != null ||
                      cfg.dns_record_target != null ||
                      cfg.record_update_existing != null ||
                      cfg.record_type_a_multiple != null ||
                      cfg.record_type_aaaa_multiple != null ||
                      cfg.providers != {} ||
                      cfg.polls != {} ||
                      cfg.domains != {};
                    configFileArg = if needsConfigFile then "-config ${cfg.configFile}" else "";
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
