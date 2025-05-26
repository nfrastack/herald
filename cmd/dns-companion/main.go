// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dns-companion/pkg/config"
	"dns-companion/pkg/dns"
	"dns-companion/pkg/dns/providers"
	"dns-companion/pkg/log"
	"dns-companion/pkg/poll"

	// Import the polling providers to ensure they register
	_ "dns-companion/pkg/poll/providers"
)

// Version information
var (
	// Version is the current version of the application
	Version = "development"

	// BuildTime is when the application was built
	BuildTime = "unknown"
)

// String returns a string representation of the version information
func versionString(showBuild bool) string {
	if showBuild {
		return fmt.Sprintf("%s (built: %s)", Version, BuildTime)
	}
	return Version
}

func IsRunningUnderSystemd() (system, user bool) {
	invocation := os.Getenv("INVOCATION_ID") != ""
	journal := os.Getenv("JOURNAL_STREAM") != ""
	if invocation || journal {
		return true, false
	}
	return false, false
}

var (
	configFilePath = flag.String("config", "", "Path to configuration file")
	showVersion    = flag.Bool("version", false, "Show version and exit")
	logLevelFlag   = flag.String("log-level", "", "Set log level (overrides config/env)")
	dryRunFlag     = flag.Bool("dry-run", false, "Simulate DNS record changes without applying them")
)

func main() {
	flag.Parse()

	// Detect if running under systemd as early as possible
	system, user := IsRunningUnderSystemd()

	// Set default log_timestamps based on systemd detection
	defaultLogTimestamps := true
	if system {
		defaultLogTimestamps = false
	}

	// Initialize logger early to avoid singleton lock-in at wrong level
	log.Initialize("info", true)

	// Show version if requested
	if *showVersion {
		fmt.Println(versionString(true))
		os.Exit(0)
	}

	if !system && !user {
		fmt.Println()
		fmt.Println("             .o88o.                                 .                       oooo")
		fmt.Println("             888 \"\"                                .o8                       888")
		fmt.Println("ooo. .oo.   o888oo  oooo d8b  .oooo.    .oooo.o .o888oo  .oooo.    .ooooo.   888  oooo")
		fmt.Println("`888P\"Y88b   888    `888\"\"8P `P  )88b  d88(  \"8   888   `P  )88b  d88' \"Y8  888 .8P'")
		fmt.Println(" 888   888   888     888      .oP\"888  \"\"Y88b.    888    .oP\"888  888        888888.")
		fmt.Println(" 888   888   888     888     d8(  888  o.  )88b   888 . d8(  888  888   .o8  888 `88b.")
		fmt.Println("o888o o888o o888o   d888b    `Y888\"\"8o 8\"\"888P'   \"888\" `Y888\"\"8o `Y8bod8P' o888o o888o")
		fmt.Println()
	}

	fmt.Printf("Starting DNS Companion version: %s \n", versionString(false))
	fmt.Printf("© 2025 Nfrastack https://nfrastack.com - BSD-3-Clause License\n")
	fmt.Println()

	log.Trace("Built: %s", BuildTime)
	// Determine the config file path
	configFile := "dns-companion.yml"
	if *configFilePath != "" {
		configFile = *configFilePath
	}

	// Find the config file using pkg/config logic
	configFilePath, err := config.FindConfigFile(configFile)
	if err != nil {
		fmt.Printf("[config] Failed to find configuration file: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.LoadConfigFile(configFilePath)
	if err != nil {
		fmt.Printf("[config] Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Set the global config so all packages see the loaded config
	config.GlobalConfig = *cfg

	// Clean up config sections to remove invalid keys after merging includes
	config.CleanConfigSections(cfg)

	// Only override log_timestamps if explicitly set by config/env/flag
	logTimestamps := defaultLogTimestamps
	if *logLevelFlag != "" {
		cfg.General.LogLevel = *logLevelFlag
	} else if os.Getenv("LOG_LEVEL") != "" {
		cfg.General.LogLevel = os.Getenv("LOG_LEVEL")
	}
	cfg.General.DryRun = *dryRunFlag || strings.ToLower(os.Getenv("DRY_RUN")) == "true"

	// Check for explicit log_timestamps in env or config
	if val := os.Getenv("LOG_TIMESTAMPS"); val != "" {
		valLower := strings.ToLower(val)
		if valLower == "false" || valLower == "0" || valLower == "no" {
			logTimestamps = false
		} else if valLower == "true" || valLower == "1" || valLower == "yes" {
			logTimestamps = true
		}
	} else if config.FieldSetInConfigFile(configFilePath, "log_timestamps") {
		logTimestamps = cfg.General.LogTimestamps
	}

	cfg.General.LogTimestamps = logTimestamps

	log.GetLogger().SetLevel(cfg.General.LogLevel)
	log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)

	// Re-initialize logger with the final config value
	//log.Initialize(cfg.General.LogLevel, cfg.General.LogTimestamps)

	log.Info("[config] Using config file: %s", configFilePath)

	// Apply logging configuration
	config.ApplyLoggingConfig(cfg)
	log.Debug("[config] Logger configured with level: %s", cfg.General.LogLevel)

	// Apply configuration to environment variables
	config.ApplyConfigToEnv(cfg, "")

	// Register DNS providers after logging is initialized
	providers.RegisterProviders()

	// Determine DNS provider name (automatic selection if only one, else error if not specified per domain)
	providerNames := make([]string, 0, len(cfg.Providers))
	for name := range cfg.Providers {
		providerNames = append(providerNames, name)
	}
	var dnsProviderName string
	if len(providerNames) == 1 {
		dnsProviderName = providerNames[0]
		log.Debug("[dns/provider] Only one DNS provider defined, using: %s", dnsProviderName)
	} else {
		// If more than one provider, require explicit provider selection per domain
		log.Debug("[dns/provider] Multiple DNS providers defined. Each domain must specify its provider explicitly.")
	}

	// Get the provider configuration (if only one provider, or for each domain as needed)
	var providerConfig config.DNSProviderConfig
	if dnsProviderName != "" {
		var ok bool
		providerConfig, ok = cfg.Providers[dnsProviderName]
		if !ok {
			log.Fatal("[dns/provider] Provider configuration not found for: %s", dnsProviderName)
		}
	}

	// Use DNSProviderConfig fields and Options
	providerOptions := make(map[string]string)
	if dnsProviderName != "" {
		providerOptions = providerConfig.GetOptions()
		log.Debug("[dns/provider] Using providerConfig.GetOptions() for DNS provider options: %v", providerOptions)
	}

	// Initialize DNS provider if only one is defined
	var dnsProvider dns.Provider
	if dnsProviderName != "" {
		log.Info("[dns] Initializing DNS provider: %s", dnsProviderName)
		dnsProvider, err = dns.LoadProviderFromConfig(dnsProviderName, providerOptions)
		if err != nil {
			log.Fatal("[dns/provider] Failed to initialize DNS provider: %v", err)
		}
	}

	// Load domain configurations into a shared data structure
	domainConfigs := make(map[string]map[string]string)
	for domainKey, domainCfg := range cfg.Domains {
		domainMap := make(map[string]string)

		// Convert domain config to string map for easier access
		domainMap["name"] = domainCfg.Name
		domainMap["provider"] = domainCfg.Provider
		if domainCfg.ZoneID != "" {
			domainMap["zone_id"] = domainCfg.ZoneID
		}

		// Map all fields from RecordConfig
		if domainCfg.Record.Type != "" {
			domainMap["record_type"] = domainCfg.Record.Type // Use record_type to avoid conflict
		}
		if domainCfg.Record.TTL > 0 {
			domainMap["ttl"] = fmt.Sprintf("%d", domainCfg.Record.TTL)
		}
		if domainCfg.Record.Target != "" {
			domainMap["target"] = domainCfg.Record.Target
		}
		domainMap["update_existing"] = fmt.Sprintf("%t", domainCfg.Record.UpdateExisting)
		domainMap["allow_multiple"] = fmt.Sprintf("%t", domainCfg.Record.AllowMultiple)

		// Add additional options
		for k, v := range domainCfg.Options {
			domainMap[k] = v
		}

		// IMPORTANT: Include the provider's type field in the domain config
		if providerCfg, exists := cfg.Providers[domainCfg.Provider]; exists {
			if providerCfg.Type != "" {
				domainMap["provider_type"] = providerCfg.Type
			}
			// Merge provider-specific options
			for k, v := range providerCfg.Options {
				if strVal, ok := v.(string); ok {
					domainMap[k] = strVal
				}
			}
		}

		// Store normalized domain name as key (domain keys are already normalized in the config)
		domainConfigs[domainKey] = domainMap

		log.Verbose("[domain] Loaded domain config for '%s'", domainCfg.Name)
		log.Trace("[domain] Settings: %v", domainMap)
	}

	// Store domain configs in a global config location
	config.SetDomainConfigs(domainConfigs)

	// Get poll profiles from config
	pollProfiles := cfg.General.PollProfiles
	if len(pollProfiles) == 0 {
		log.Fatal("[poll] No poll profiles specified in configuration")
	}

	log.Debug("[poll] Using poll profiles: %v", pollProfiles)

	// Initialize poll providers
	pollProviders := []poll.Provider{}
	for _, pollProfileName := range pollProfiles {
		pollProviderConfig, ok := cfg.Polls[pollProfileName]
		if !ok {
			log.Fatal("[poll] Poll profile not found in configuration: %s", pollProfileName)
		}

		pollProviderType := pollProviderConfig.Type
		if pollProviderType == "" {
			pollProviderType = pollProfileName
		}

		log.Verbose("[poll] Initializing poll provider: '%s'", pollProfileName)
		// Create options map for the provider, passing through ALL options from the config
		providerOptions := pollProviderConfig.GetOptions(pollProfileName)

		//log.Debug("[poll] Created provider options map with %d keys", len(providerOptions))

		// For backward compatibility, add expose_containers directly
		if pollProviderConfig.ExposeContainers {
			providerOptions["expose_containers"] = "true"
			log.Debug("[poll] Adding expose_containers=true to provider options")
		}

		// Add or override with any additional options from the options map
		// (This is redundant now since GetOptions already does this, but kept for compatibility)
		for k, v := range pollProviderConfig.Options {
			if strVal, ok := v.(string); ok {
				providerOptions[k] = strVal
			}
		}

		log.Trace("[poll] Provider %s options: %v", pollProfileName, providerOptions)

		pollProvider, err := poll.NewPollProvider(pollProviderType, providerOptions)
		if err != nil {
			log.Fatal("[poll] Failed to initialize poll provider '%s': %v", pollProfileName, err)
		}

		// If the poll provider supports containers, set the DNS provider
		if containerProvider, ok := pollProvider.(poll.ProviderWithContainer); ok {
			containerProvider.SetDNSProvider(dnsProvider)
		}

		// If the poll provider supports domain configs, set them
		if withDomainConfigs, ok := pollProvider.(poll.ProviderWithDomainConfigs); ok {
			withDomainConfigs.SetDomainConfigs(cfg.Domains)
		}

		// Start polling
		if err := pollProvider.StartPolling(); err != nil {
			log.Fatal("[poll] Failed to start polling with provider '%s': %v", pollProfileName, err)
		}

		pollProviders = append(pollProviders, pollProvider)
	}

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	<-sigChan
	fmt.Printf("\nShutting down DNS Companion\n")

	// Stop all poll providers
	for _, provider := range pollProviders {
		provider.StopPolling()
	}

	// Give time for cleanup
	time.Sleep(300 * time.Millisecond)
}
