{
  description = "Herald - Dynamic DNS management for Docker, Traefik, Files, Remote sources, Tailscale, and ZeroTier/ZT-Net networks";

  inputs = { nixpkgs.url = "nixpkgs/nixos-unstable"; };
  outputs = { self, nixpkgs }:
    let
      version = "2.3.2-dev";
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
    in {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
          buildDate = pkgs.runCommand "build-date" {} ''
            date -u +%Y-%m-%dT%H:%M:%SZ > $out
          '';
          buildDateStr = builtins.readFile buildDate;
        in {
          herald = pkgs.buildGoModule {
            pname = "herald";
            version = "${version}";
            src = self;

            meta = {
              description = "Herald - Dynamic DNS record management for modern infrastructure. Supports Docker, Traefik, File, Remote, Tailscale, and ZeroTier/ZT-Net poll providers.";
              homepage = "https://github.com/nfrastack/herald";
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
              "-X main.BuildTime=${buildDateStr}"
            ];

#            vendorHash = "sha256-/F74UUO1GoNEQKzQlz6KHJ6UiAa4lswIju2SvG41Pco=";
            vendorHash = "sha256-zUhjuSrYcTh+kPwYhJ2nZr4n/nptUJjx+hHNtxoImno=";
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

      defaultPackage = forAllSystems (system: self.packages.${system}.herald);

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.herald;
        in {
          options.services.herald = {
            enable = lib.mkEnableOption "Enable the Herald DNS management service";

            service.enable = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Enable the systemd service for Herald";
            };

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.herald;
              description = "Herald package to use";
            };

            configFile = lib.mkOption {
              type = lib.types.str;
              default = "herald.yml";
              description = "Path to the YAML configuration file";
            };

            general = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {
                log_level = "verbose";
                log_timestamps = true;
                dry_run = false;
              };
              description = "Global application settings including log level and dry run mode";
            };

            defaults = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
              description = "Default record settings applied to all domains";
            };

            inputs = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              description = "Input provider configurations for Docker, Traefik, File, Remote, etc.";
            };

            outputs = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
              description = "Output configurations for hosts files, JSON exports, zone files, etc.";
            };

            domains = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
              description = "Domain configurations with input/output profile associations";
            };

            api = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
              description = "API server configuration for receiving DNS records from remote instances";
            };

            include = lib.mkOption {
              type = with lib.types; nullOr (either str (listOf str));
              default = null;
              description = "Additional YAML configuration files to include";
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
                  // (if cfg.inputs != {} then { inputs = cfg.inputs; } else {})
                  // (if cfg.outputs != {} then { outputs = cfg.outputs; } else {})
                  // (if cfg.domains != {} then { domains = cfg.domains; } else {})
                  // (if cfg.api != {} then { api = cfg.api; } else {})
                  // (if cfg.include != null then { include = cfg.include; } else {});
              in yaml.generate "herald.yml" configData;

            systemd.services.herald = lib.mkIf cfg.service.enable {
              description = "Herald DNS Management Service";
              wantedBy = [ "multi-user.target" ];
              restartTriggers = [
                cfg.package
                config.environment.etc."${lib.removePrefix "/etc/" cfg.configFile}".source
                "${cfg.package.outPath}"
              ];
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/herald -config /etc/${cfg.configFile}";
                User = "root";
                Group = "root";
                Restart = "always";
                RestartSec = "10s";
                StandardOutput = "journal";
                StandardError = "journal";
                SyslogIdentifier = "herald";
              };
            };
          };
        };
    };
}
