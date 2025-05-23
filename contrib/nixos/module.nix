{ config, lib, pkgs, ... }:

let
  cfg = config.services.traefik-poller;
  inherit (lib) mkOption mkEnableOption types;
in {
  options = {
    services.traefik-poller = {
      enable = mkEnableOption "Traefik poller";
      process_existing = mkOption {
        type = types.bool;
        default = false;
        description = ''
          If true, process existing routers on startup for Traefik poller.
        '';
      };
      record_remove_on_stop = mkOption {
        type = types.bool;
        default = false;
        description = ''
          If true, remove DNS records when router is removed for Traefik poller.
        '';
      };
      poll_interval = mkOption {
        type = types.unsignedInteger;
        default = 60;
        description = ''
          Poll interval in seconds for Traefik poller.
        '';
      };
      traefik_api_url = mkOption {
        type = types.str;
        default = "http://127.0.0.1:8080";
        description = ''
          URL of the Traefik API.
        '';
      };
      dns_provider = mkOption {
        type = types.str;
        default = "route53";
        description = ''
          DNS provider to use for Traefik poller.
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    systemd.services.traefik-poller = {
      description = "Traefik poller";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.traefik-poller}/bin/traefik-poller";
        Environment = [
          "TRAEFIK_API_URL=${cfg.traefik_api_url}"
          "DNS_PROVIDER=${cfg.dns_provider}"
          "POLL_INTERVAL=${toString cfg.poll_interval}"
          "PROCESS_EXISTING=${toString cfg.process_existing}"
          "RECORD_REMOVE_ON_STOP=${toString cfg.record_remove_on_stop}"
        ];
      };
    };
  };
}