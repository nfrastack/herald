// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"herald/pkg/config"

	"flag"
)

// Options holds all command line options
type Options struct {
	ConfigFile    string
	DryRun        bool
	LogFile       string
	LogLevel      string
	LogTimestamps bool
	LogType       string
	ShowVersion   bool
}

// ParseFlags parses command line flags and returns the options
func ParseFlags() *Options {
	opts := &Options{}
	flag.StringVar(&opts.ConfigFile, "config-file", "", "Path to configuration file")
	flag.BoolVar(&opts.ShowVersion, "version", false, "Show version information")
	flag.StringVar(&opts.LogLevel, "log-level", "", "Log level (info, debug)")
	flag.BoolVar(&opts.LogTimestamps, "log-timestamps", false, "Show timestamps in logs")
	flag.StringVar(&opts.LogType, "log-type", "", "Log type (console, file, both)")
	flag.StringVar(&opts.LogFile, "log-file", "", "Path to log file (includes directory)")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Enable dry run mode (no changes will be made)")
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

// RegisterConfigFlags registers -config and -config-file flags for config files
func RegisterConfigFlags(fs *flag.FlagSet, configs *config.StringSliceFlag) {
	fs.Var(configs, "config", "Path to config file (can be specified multiple times)")
	fs.Var(configs, "config-file", "Path to config file (can be specified multiple times)")
}
