{ config, inputs, lib, pkgs, ... }: {
  imports = [
    inputs.container-dns-companion.nixosModules.default
  ];

  services = {
    container-dns-companion = {
      enable = true;
      general = {
        log_level = "info";
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
        };
      };
    };
  };
}