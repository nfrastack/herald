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
          expose_containers = true;
          swarm = false;
          record_remove_on_stop = false;
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