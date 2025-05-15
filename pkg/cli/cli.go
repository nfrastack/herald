package cli

import (
	"container-dns-companion/pkg/config"
	"flag"
)

// Options holds all command line options
type Options struct {
	// General options
	ConfigFile  string
	ShowVersion bool

	// Logging options
	LogLevel      string
	LogTimestamps bool
	LogType       string
	LogFile       string
	DryRun        bool
}

// ParseFlags parses command line flags and returns the options
func ParseFlags() *Options {
	opts := &Options{}

	// Parse command line flags
	flag.StringVar(&opts.ConfigFile, "config-file", "", "Path to configuration file")
	flag.BoolVar(&opts.ShowVersion, "version", false, "Show version information")

	// Add command line options for common settings
	flag.StringVar(&opts.LogLevel, "log-level", "", "Log level (info, debug)")
	flag.BoolVar(&opts.LogTimestamps, "log-timestamps", false, "Show timestamps in logs")
	flag.StringVar(&opts.LogType, "log-type", "", "Log type (console, file, both)")
	flag.StringVar(&opts.LogFile, "log-file", "", "Path to log file (includes directory)")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Enable dry run mode (no changes will be made)")

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
}
