## 2.0.2beta2 2025-06-24 <code at nfrastack dot com>

   ### Changed
   - (domain) Log that an Input Provider is overriding an IP Address properly
   - (input) Providers with interval (file, remote, caddy, traefik, zerotier, tailscale) all now perform an initial check upon startup. Previously they waited for the first interval to pass - Now it happens on startup, and depending on value of process_existing - either performs record updates, or takes an inventory and bases the next interval execution on the initial inventory for changes. This is a much saner approach.
   - (input/docker) quiet down some INFO log level output
   - (input/zerotier) Cache API type when auto detecting version and try both on intialpoll as opposed to flip-flopping.
   - (input/zerotier) Handle cases where double logprefixes appears
   - (input/zerotier) Set Name feld when calling DNSEntry struct to fix entries without FQDN not to be written
   - (input/zerotier) perform better change detection and quiet log output
   - (output/dns/cloudflare) refine operations
   - (input/docker) remove duplication in logging when nfrastack.dns.enable=true

## 2.0.1 2025-06-21 <code at nfrastack dot com>

   ### Changed
   - (domain) Fixed issue with domains readinfg old hardcoded profile information throwing warnings

## 2.0.0 2025-06-20 <code at nfrastack dot com>

   New project name, Herald.

   **BREAKING CHANGES** As the earlier versions of this tool were built the overall configuration structure started to quickly grow technical debt, so it has been revamped entirely. Please also see   changes in the NixOS configuration.

   The Container image that is available has been simplified. In its "AUTO" generating mode it allows for pulling from Caddy, Traefik, and Docker input providers, and only outputing to Cloudflare. If you wish to have more functionality you can set it to not auto generate the config.

   ### Added
   - New `profiles` structure for domain configuration with `inputs` and `outputs` fields for cleaner, more logical domain configuration grouping
   - (domain) Enhanced poll provider validation in BatchProcessor for better filtering
   - (domain) Poll Provider Targeting - Domain configurations can now specify which poll providers are allowed to use them via `profiles.inputs` field
   - (domain) Output Profile Targeting - Domain configurations can now specify which output profiles should process their records via `profiles.outputs` field
   - (domain) Configuration validation - Application fails fast with clear error messages if domains reference non-existent input providers, output profiles, or DNS providers
   - (domain) Multiple poll providers and output profiles support per domain configuration
   - (inputs/docker) Docker Connection Pooling - Multiple Docker poll providers now share a single connection per API endpoint for improved resource efficiency
   - (inputs/docker) Centralized Event Logging - Docker events are now logged once at the shared connection level with clear provider attribution
   - (inputs/docker) Smart Event Distribution - Container events are intelligently filtered and distributed only to relevant providers based on their filter configuration
   - (outputs/host) When Flattening CNAMEs - name sometimes gets resolved to localhost. New resolver and ip_override options to force proper entries in hosts file.

   ### Changed
   - Filters have consistent naming per input provider

   ### Removed
   - **BREAKING** Environment variables have been removed for the most part. Use the configuration file for better configuration.

   ### Migration Guide

   The entire configuration structure has been simplified and streamlined. The old multi-level structure with separate `poll_providers`, `providers`, and domain fields has been replaced with a cleaner `inputs` and `outputs` approach.

   **Old configuration structure:**
   ```yaml
   # OLD: Separate sections for each component type
   poll_providers:
     docker_services:
       type: docker
       # ... config

   providers:
     cloudflare_dns:
       type: cloudflare
       # ... config

   domains:
     my_domain:
       name: "example.com"
       input_profiles:        # REMOVED
         - docker_services
       outputs:              # REMOVED
         - cloudflare_dns
       poll_providers:        # REMOVED
         - docker_services
       output_profiles:       # REMOVED
         - cloudflare_dns
   ```

   **New configuration structure:**
   ```yaml
   # NEW: Unified inputs and outputs sections
   inputs:
     docker_services:
       type: docker
       # ... config

   outputs:
     cloudflare_dns:
       type: cloudflare
       # ... config

   domains:
     my_domain:
       name: "example.com"
       profiles:             # NEW REQUIRED STRUCTURE
         inputs:
           - docker_services
         outputs:
           - cloudflare_dns
   ```

## 1.2.1 2025-06-13 <code at nfrastack dot com>

   ### Changed
     - (api) Removed log entry relating to upstream DNS provider
     - (api) Removed duplicate log_level override statement
     - (log) Properly create logPrefixes as [function/type/profile_name]
     - (domain) Fix blank log_level output overrides
     - (output) Allow %placeholders% to work within the files, not just filenames
     - (output/zone) Properly provide ERROR statement if outputs options aren't populated
     - Fixed nix flake config generation order
     - Fix build scripts to properly build multi arch outside of GHA

## 1.2.0 2025-06-12 <code at nfrastack dot com>

Exciting news! New API available for receiving entries from 'remote' output provider. Use for sending records from different hosts to a centralized host, for whatever purpose you wish.

   ### Added
     - API Server mode - HTTP API Endpoint with TLS supported, Tokens and connection throttling support
     - Remote Output Provider - Output records to remote API Server
     - Refined all filter operations to use consistent naming and AND/OR operators including negation
     - Add -c shortcut for calling config file
     - Add output_profiles config option in 'general' to choose which output profiles to use if more than one.
     - Code cleanup and optimization


## 1.1.1 2025-05-30 <code at nfrastack dot com>

   ### Changed
     - Cleaned Tailscale Filter compilation warnings to allow nix flake to build.

## 1.1.0 2025-05-30 <code at nfrastack dot com>

Major drop of features for this release including some ways to output records to various file formats, the ability to connect to more reverse proxies, vpn providers like tailscale and zerotier making this into a DNS manager suitable for modern infrastructure.
Reach out if you have DNS servers with API support that I can have access to and I'll start building support for the next release..

   ### Added
     - Add log_level VERBOSE sitting in the middle of debug and info. This is the new default if not explicit in config.
     - Add scoped logging to each poller, dns provider, domain configuration, output provider - log_level will override per provider
     - Add support for all network based pollProviders to supply their own TLS ca,cert, and keys. Also, ability to disable certificate verification.
     - (poll) Added File provider to read YAML/JSON/Hosts/Zonefile from filesystem with customizable interval to poll for changes or ondemand/fsnotify
     - (poll) Added Remote provider to read YAML/JSON/Hosts/Zonefile from a HTTP/HTTPS source with basic authentication supported
     - (poll) Added Zerotier Poll provider to poll for nodes in a Zerotier Central or ZT-Net (Self hosted) network
     - (poll) Added Tailscale Poll provider to poll for devices in a Tailscale tailnet or Headscale network
     - (poll) Added Caddy Poll provider to read host.domains from Caddy Admin API
     - (dns) support multiple providers
     - (output) Add functionality to output records to various files (hosts, json, yaml, zone)
     - (output/hosts) auto flatten cnames to accomodate for deficiencies in host file format
     - (output) implement smart %template% logic for filename writing

   ### Changed
     - Created pollCommonfunctions for poll providers (http, records management, options, processing of parsed,received data, filter logic for easier implementation of future pollers)
     - If docker PollProvider detects that it is Podman running then log it, and also throw errors if Podman is used for Swarm mode
     - Many log entries from DEBUG -> VERBOSE

   ### Fixed
     - Issue where record targets weren't being read correctly with the traefik poll provider


## 1.0.0 2025-05-23 <code at nfrastack dot com>

Inaugral release of the Herald!
This tool will augment the amazing capabilities of working with the various pollers (eg Docker and Traefik) with hostname entries and perform DNS operations on providers such as Cloudflare.
This is an evolution from the tiredofit/docker-traefik-cloudflare-companion tool built and maintained in Python. This Go developed tool hopefully provides a more modular, single binary approach
that can run in a container environment, via the command line or via systemd. It is planned to introduce more polling providers and DNS provider support in the near future.

There has been a large amount of work performed to provide feature parity to the formerly mentioned python based tool, along with some new additions of features and other quality of life improvements.

   ### Added
      - (config) YAML based configuration with include file support
      - (config) Can load multiple config files via the command line
      - (config) Environment based configuration ovverides of config file
      - (poll) 2 polling providers provided (docker,traefik)
      - (poll) multiple poll provider capability
      - (poll/docker) supports reading container labels from traefik.router.host labels (including complex multiple host rules)
      - (poll/docker) support overriding via nfrastack.dns labels to define different targets, records, ttl, or to disable processing
      - (poll/docker) supports tls, http, socket support for connecting to docker host
      - (poll/docker) support docker swarm mode
      - (poll/docker) support for processing existing running containers, or wait until new events occur
      - (poll/docker) option to remove dns records when container/service stops
      - (poll/traefik) reads from Traefik (2.x.x and up - tested up to 3.4.x) API
      - (poll/traefik) supports mutliple host and wildcards
      - (poll/traefik) configurable polling interval
      - (poll/traefik) process existing routers, or wait for new events
      - (poll/traefik) option to remove dns records when router disapepars from configuration
      - Filters (poll/traefik) Ability to filter routers by name, service, provider, entrypoint, status, rule, none
      - Filters (poll/docker) Ability to filter containers by label, name, network, image, service, health, none)
      - Filters can be chained with operators AND, OR, NOT, and negation
      - Filters support wildcard and regular expressions
      - (providers) 1 provider provided (cloudflare)
      - (providers) utilize differnet provider profiles for different config purposes
      - (providers) support A, AAAA, CNAME create, read, update records. Including smart autodetection if not specified.
      - (providers) support checking if record exists and updating as
      - (providers) support multiple A, AAAA records
      - (providers) include/exclude processing certain subdomains
      - (provider/cloudflare) support global api email+key or scoped tokens
      - (provider/cloudflare) support proxied mode
      - Sparse (info) or rich (debug) or TMI (trace) logging
      - Ability to execute without performing changes (dry-run)
      - Support enabling Multicast DNS support
      - Single Binary, runs on amd64 and aarch64
      - Sample configuration files included
      - Docker image included
      - NixOS Module included
