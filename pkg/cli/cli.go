package cli

import (
	"container-dns-companion/pkg/config"
	"flag"
	"fmt"
)

// Options holds all command line options
type Options struct {
	// General options
	ConfigFile  string
	Profile     string
	ShowVersion bool

	// Logging options
	LogLevel      string
	LogTimestamps bool
	LogType       string
	LogFile       string
	DryRun        bool

	// DNS options
	DNSProvider string
	Domains     string

	// Poll options
	PollProfiles string

	// Docker options
	DockerHost string

	// Traefik options
	TraefikPollURL      string
	TraefikPollInterval int
}

// ParseFlags parses command line flags and returns the options
func ParseFlags() *Options {
	opts := &Options{}

	// Parse command line flags
	flag.StringVar(&opts.ConfigFile, "config-file", "", "Path to configuration file")
	flag.StringVar(&opts.Profile, "profile", "", "Configuration profile to use")
	flag.BoolVar(&opts.ShowVersion, "version", false, "Show version information")

	// Add command line options for common settings
	flag.StringVar(&opts.LogLevel, "log-level", "", "Log level (info, debug)")
	flag.BoolVar(&opts.LogTimestamps, "log-timestamps", false, "Show timestamps in logs")
	flag.StringVar(&opts.LogType, "log-type", "", "Log type (console, file, both)")
	flag.StringVar(&opts.LogFile, "log-file", "", "Path to log file (includes directory)")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Enable dry run mode (no changes will be made)")

	// DNS provider settings
	flag.StringVar(&opts.DNSProvider, "dns-provider", "", "DNS provider to use (cloudflare, route53)")
	flag.StringVar(&opts.Domains, "domains", "", "Comma-separated list of domains to manage")

	// Poll provider settings
	flag.StringVar(&opts.PollProfiles, "poll-profiles", "", "Comma-separated list of poll profiles to use")

	// Docker provider settings
	flag.StringVar(&opts.DockerHost, "docker-host", "", "Docker host (unix:///var/run/docker.sock)")

	// Traefik provider settings
	flag.StringVar(&opts.TraefikPollURL, "traefik-poll-url", "", "Traefik API URL")
	flag.IntVar(&opts.TraefikPollInterval, "traefik-poll-interval", 0, "Traefik poll interval in seconds")

	// Parse the flags
	flag.Parse()

	return opts
}

// ApplyOverrides applies command line options to the configuration system
func ApplyOverrides(opts *Options) {
	if opts.LogLevel != "" {
		config.SetEnvVar("LOG_LEVEL", opts.LogLevel)
	}
	if opts.LogTimestamps {
		config.SetEnvVar("LOG_TIMESTAMPS", "true")
	}
	if opts.LogType != "" {
		config.SetEnvVar("LOG_TYPE", opts.LogType)
	}
	if opts.LogFile != "" {
		config.SetEnvVar("LOG_FILE", opts.LogFile)
	}
	if opts.DryRun {
		config.SetEnvVar("DRY_RUN", "true")
	}
	if opts.DNSProvider != "" {
		config.SetEnvVar("DNS_PROVIDER", opts.DNSProvider)
	}
	if opts.Domains != "" {
		config.SetEnvVar("DNS_DOMAINS", opts.Domains)
	}
	if opts.PollProfiles != "" {
		config.SetEnvVar("POLL_PROFILES", opts.PollProfiles)
	}
	if opts.DockerHost != "" {
		config.SetEnvVar("DOCKER_HOST", opts.DockerHost)
	}
	if opts.TraefikPollURL != "" {
		config.SetEnvVar("TRAEFIK_POLL_URL", opts.TraefikPollURL)
	}
	if opts.TraefikPollInterval > 0 {
		config.SetEnvVar("TRAEFIK_POLL_INTERVAL", fmt.Sprintf("%d", opts.TraefikPollInterval))
	}
}
