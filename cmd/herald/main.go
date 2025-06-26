// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"herald/pkg/api"
	"herald/pkg/config"
	"herald/pkg/domain"
	"herald/pkg/input"
	"herald/pkg/log"
	"herald/pkg/output"
	"herald/pkg/util"

	_ "herald/pkg/output/types/dns/providers"

	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
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
	configFilePath  = flag.String("config", "", "Path to configuration file")
	configFilePathC = flag.String("c", "", "") // Hidden shorthand for config
	showVersion     = flag.Bool("version", false, "Show version and exit")
	logLevelFlag    = flag.String("log-level", "", "Set log level (overrides config/env)")
	dryRunFlag      = flag.Bool("dry-run", false, "Simulate DNS record changes without applying them")
	containerFlag   = flag.Bool("container", false, "")
)

func main() {
	// Hide the -c flag from help output
	flag.Lookup("c").Usage = ""

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

	if !system && !user && !*containerFlag {
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

	fmt.Printf("Starting Herald version: %s \n", versionString(false))
	fmt.Printf("© 2025 Nfrastack https://nfrastack.com - BSD-3-Clause License\n")
	fmt.Println()

	log.Trace("Built: %s", BuildTime)

	// Determine the config file path
	configFile := "herald.yml"
	if *configFilePath != "" {
		configFile = *configFilePath
	} else if *configFilePathC != "" {
		configFile = *configFilePathC
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

	// CONFIGURE LOGGER FIRST - before any other initialization
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
		// Use config file setting
		logTimestamps = cfg.General.LogTimestamps
	}

	// Force timestamps on for verbose logging if not explicitly disabled in config
	if cfg.General.LogLevel == "verbose" && cfg.General.LogTimestamps == false {
		log.Debug("[config] Verbose mode detected but timestamps disabled in config - consider enabling log_timestamps: true")
	}

	cfg.General.LogTimestamps = logTimestamps

	// Apply final logger configuration FIRST
	log.GetLogger().SetLevel(cfg.General.LogLevel)
	log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)

	log.Info("[config] Using config file: %s", configFilePath)
	log.Debug("[config] Logger configured with level: %s, timestamps: %t", cfg.General.LogLevel, cfg.General.LogTimestamps)

	// NOW set the global config and continue with initialization
	config.GlobalConfig = *cfg

	// Set up the global config getter for output manager to avoid import cycles
	output.SetGlobalConfigGetter(func() output.GlobalConfigForOutput {
		return &config.GlobalConfig
	})

	// NOW initialize the domain system with validation (after logger is properly configured)
	// Convert config types for domain validation
	domainsInterface := make(map[string]interface{})
	for k, v := range cfg.Domains {
		domainMap := make(map[string]interface{})
		domainMap["name"] = v.Name

		// Handle new profiles structure first
		if v.Profiles != nil && (len(v.Profiles.Inputs) > 0 || len(v.Profiles.Outputs) > 0) {
			profilesMap := make(map[string]interface{})
			if len(v.Profiles.Inputs) > 0 {
				profilesMap["inputs"] = v.Profiles.Inputs
			}
			if len(v.Profiles.Outputs) > 0 {
				profilesMap["outputs"] = v.Profiles.Outputs
			}
			domainMap["profiles"] = profilesMap
		}

		// Handle profiles structure
		inputProfiles := v.GetInputProfiles()
		outputs := v.GetOutputs()

		domainMap["input_profiles"] = inputProfiles
		domainMap["output_profiles"] = outputs

		// Add record configuration
		if v.Record.Type != "" || v.Record.TTL != 0 || v.Record.Target != "" {
			recordMap := make(map[string]interface{})
			recordMap["type"] = v.Record.Type
			recordMap["ttl"] = v.Record.TTL
			recordMap["target"] = v.Record.Target
			recordMap["update_existing"] = v.Record.UpdateExisting
			recordMap["allow_multiple"] = v.Record.AllowMultiple
			domainMap["record"] = recordMap
		}

		domainsInterface[k] = domainMap
		log.Debug("[main] Created domain interface for '%s': input_profiles=%v, outputs=%v",
			k, inputProfiles, outputs)
	}
	inputsInterface := make(map[string]interface{})
	for k, v := range cfg.Inputs {
		inputsInterface[k] = v
	}
	outputsInterface := make(map[string]interface{})
	for k, v := range cfg.Outputs {
		outputsInterface[k] = v
	}

	// Initialize the domain system with validation
	if err := domain.InitializeDomainSystem(domainsInterface, inputsInterface, outputsInterface, map[string]interface{}{}); err != nil {
		log.Fatal("[domain] Failed to initialize domain system: %v", err)
	}

	// Start API server if enabled
	if cfg.API != nil && cfg.API.Enabled {
		apiLogger := log.NewScopedLogger("[api]", cfg.API.LogLevel)
		apiLogger.Info("Starting API server")
		if err := api.StartAPIServer(cfg.API); err != nil {
			log.Fatal("[api] Failed to start API server: %v", err)
		}
		// If API is enabled, allow running with zero input providers
		if len(cfg.Inputs) == 0 {
			apiLogger.Warn("No input providers defined, running in API-only mode.")
		}
	}

	// Initialize output manager - now domain-driven, not general config driven
	// Extract unique output profiles from all domains
	outputProfiles := make(map[string]bool)
	for _, domainConfig := range domain.GlobalDomainManager.GetAllDomains() {
		for _, outputProfile := range domainConfig.GetOutputs() {
			outputProfiles[outputProfile] = true
		}
	}

	// Convert to slice
	activeOutputProfiles := make([]string, 0, len(outputProfiles))
	for profile := range outputProfiles {
		activeOutputProfiles = append(activeOutputProfiles, profile)
	}

	if len(activeOutputProfiles) == 0 {
		// If no domains specify output profiles, use all available (backward compatibility)
		for profileName := range cfg.Outputs {
			activeOutputProfiles = append(activeOutputProfiles, profileName)
		}
		if len(activeOutputProfiles) > 0 {
			log.Debug("[output] No output profiles specified in domains, using all available: %v", activeOutputProfiles)
		}
	} else {
		log.Debug("[output] Using output profiles from domain configurations: %v", activeOutputProfiles)
	}

	if err := output.InitializeOutputManagerWithProfiles(cfg.Outputs, activeOutputProfiles); err != nil {
		log.Fatal("[output] Failed to initialize output manager: %v", err)
	}

	// Ensure timestamps stay enabled after output manager initialization
	log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)

	// Ensure timestamps stay enabled after provider registration
	log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)

	// Input provider logic - now domain-driven, not general config driven
	if !(cfg.API != nil && cfg.API.Enabled && len(cfg.Inputs) == 0) {
		// Extract unique input providers from all domains
		inputProviders := make(map[string]bool)
		for _, domainConfig := range domain.GlobalDomainManager.GetAllDomains() {
			for _, inputProvider := range domainConfig.GetInputProfiles() {
				inputProviders[inputProvider] = true
			}
		}

		// Convert to slice
		activeInputProfiles := make([]string, 0, len(inputProviders))
		for provider := range inputProviders {
			activeInputProfiles = append(activeInputProfiles, provider)
		}

		// Validate that all referenced input providers exist
		if len(activeInputProfiles) == 0 {
			log.Fatal("[input] No input providers specified in domain configurations")
		}

		for _, inputProviderName := range activeInputProfiles {
			if _, exists := cfg.Inputs[inputProviderName]; !exists {
				log.Fatal("[input] Input provider '%s' referenced in domains but not found in configuration", inputProviderName)
			}
		}

		log.Debug("[input] Using input providers from domain configurations: %v", activeInputProfiles)
		// Initialize input providers
		inputProviderInstances := []input.Provider{}
		for _, inputProviderName := range activeInputProfiles {
			inputProviderConfig, ok := cfg.Inputs[inputProviderName]
			if !ok {
				log.Fatal("[input] Input provider not found in configuration: %s", inputProviderName)
			}

			inputProviderType := inputProviderConfig.Type
			if inputProviderType == "" {
				inputProviderType = inputProviderName
			}

			log.Verbose("[input] Initializing input provider: '%s'", inputProviderName)

			// Create options map for the provider
			providerOptions := inputProviderConfig.GetOptions(inputProviderName)

			// For backward compatibility, add expose_containers directly
			if inputProviderConfig.ExposeContainers {
				providerOptions["expose_containers"] = "true"
				log.Debug("[input] Adding expose_containers=true to provider options")
			}

			// Handle filter configuration properly for inputcommon
			if filterConfig, exists := inputProviderConfig.Options["filter"]; exists {
				log.Debug("[input] Found filter configuration for %s: %+v", inputProviderName, filterConfig)
				// The filter should be passed as the original interface{} structure for inputcommon to parse
				// Don't convert it to string
			}

			// Add or override with any additional options from the options map
			for k, v := range inputProviderConfig.Options {
				if strVal, ok := v.(string); ok {
					providerOptions[k] = strVal
				} else {
					// For complex types like filters, convert to string representation
					// But log what we're doing
					if k == "filter" {
						log.Debug("[input] Converting filter to string for provider %s: %+v", inputProviderName, v)
					}
					providerOptions[k] = fmt.Sprintf("%v", v)
				}
			}

			log.Debug("[input] Provider %s raw config: %+v", inputProviderName, inputProviderConfig)
			log.Debug("[input] Provider %s raw config Options field: %+v", inputProviderName, inputProviderConfig.Options)
			log.Debug("[input] Provider %s final options: %v", inputProviderName, providerOptions)

			// Check if GetOptions is even being called and working
			if filterOpt, exists := providerOptions["filter"]; exists {
				log.Debug("[input] Filter found in final options: %s (type: %T)", filterOpt, filterOpt)

				// Force JSON conversion for all filters
				log.Debug("[input] Forcing JSON conversion for filter")
				if filterRaw, exists := inputProviderConfig.Options["filter"]; exists {
					if filterJSON, err := json.Marshal(filterRaw); err == nil {
						providerOptions["filter"] = string(filterJSON)
						log.Debug("[input] Successfully converted filter to JSON: %s", string(filterJSON))
					} else {
						log.Error("[input] Failed to convert filter to JSON: %v", err)
					}
				}
			} else {
				log.Debug("[input] NO filter found in final options")
			}

			// Special debug for filter configuration
			if filterStr, exists := providerOptions["filter"]; exists {
				log.Debug("[input] Provider %s filter option (as string): %s", inputProviderName, filterStr)
			}
			if filterRaw, exists := inputProviderConfig.Options["filter"]; exists {
				log.Debug("[input] Provider %s filter raw (before conversion): %+v", inputProviderName, filterRaw)
				log.Debug("[input] Provider %s filter raw type: %T", inputProviderName, filterRaw)
			}

			log.Trace("[input] Provider %s options: %v", inputProviderName, util.MaskSensitiveOptions(providerOptions))

			// Special handling for providers with filter configuration
			if _, hasFilter := inputProviderConfig.Options["filter"]; hasFilter {
				log.Debug("[input] Provider %s has filter configuration, attempting to apply filters", inputProviderName)
				// DON'T delete the filter - let it pass through to the provider
				// delete(providerOptions, "filter")
			}

			inputProvider, err := input.NewInputProvider(inputProviderType, providerOptions, output.GetOutputManager(), output.GetOutputManager())

			if err != nil {
				log.Fatal("[input] Failed to initialize input provider '%s': %v", inputProviderName, err)
			}

			// Set domain configs on the provider if it supports it
			if providerWithDomains, ok := inputProvider.(interface {
				SetDomainConfigs(map[string]config.DomainConfig)
			}); ok {
				log.Debug("[input] Setting domain configs on provider '%s': %+v", inputProviderName, cfg.Domains)
				providerWithDomains.SetDomainConfigs(cfg.Domains)
			} else {
				log.Debug("[input] Provider '%s' does not support domain configs", inputProviderName)
			}

			// Post-creation filter configuration if needed
			if filterConfig, hasFilter := inputProviderConfig.Options["filter"]; hasFilter {
				log.Debug("[input] Attempting to configure filters for %s after creation: %+v", inputProviderName, filterConfig)
			}

			// For Docker providers, check if we need to set filters differently
			if inputProviderType == "docker" {
				// Try to access the raw filter configuration and apply it directly
				if filterConfig, exists := inputProviderConfig.Options["filter"]; exists {
					log.Debug("[input] Attempting to apply filter configuration for Docker provider %s: %+v", inputProviderName, filterConfig)
				}
			}

			// Start polling
			if err := inputProvider.StartPolling(); err != nil {
				log.Fatal("[input] Failed to start polling with provider '%s': %v", inputProviderName, err)
			}

			inputProviderInstances = append(inputProviderInstances, inputProvider)

			// Re-ensure timestamps after each input provider
			log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)
		}

		// Handle signals for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Wait for signal
		<-sigChan
		fmt.Printf("\nShutting down Herald\n")

		// Stop all input providers
		for _, provider := range inputProviderInstances {
			provider.StopPolling()
		}

		// Give time for cleanup
		time.Sleep(300 * time.Millisecond)
	} else {
		// API-only mode: handle signals for graceful shutdown
		log.Warn("[api] Running in API-only mode: no input providers or input profiles defined.")
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Printf("\nShutting down Herald (API-only mode)\n")
	}
}
