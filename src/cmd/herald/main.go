// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"github.com/nfrastack/herald/internal/api"
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/domain"
	"github.com/nfrastack/herald/internal/input"
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output"
	"github.com/nfrastack/herald/internal/state"
	"github.com/nfrastack/herald/internal/util"

	"github.com/nfrastack/herald/internal/output/types/dns/providers"
	_ "github.com/nfrastack/herald/internal/output/types/remote" // Register remote output provider

	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	Version = "development"

	BuildTime = "unknown"

	buildChannel = "auto"

	buildCommit = "unknown"

	_ = providers.PowerDNSProviderName
)

func versionString(showBuild bool) string {
	if showBuild {
		return fmt.Sprintf("%s-%s-%s (built: %s)", Version, buildChannel, buildCommit, BuildTime)
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
	flag.Lookup("c").Usage = ""

	flag.Parse()

	system, user := IsRunningUnderSystemd()

	defaultLogTimestamps := true
	if system {
		defaultLogTimestamps = false
	}

	log.Initialize("info", true)

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

	configFile := "herald.yml"
	if *configFilePath != "" {
		configFile = *configFilePath
	} else if *configFilePathC != "" {
		configFile = *configFilePathC
	}

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

	logTimestamps := defaultLogTimestamps
	if *logLevelFlag != "" {
		cfg.General.LogLevel = *logLevelFlag
	} else if os.Getenv("LOG_LEVEL") != "" {
		cfg.General.LogLevel = os.Getenv("LOG_LEVEL")
	}
	cfg.General.DryRun = *dryRunFlag || strings.ToLower(os.Getenv("DRY_RUN")) == "true"

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

	if cfg.General.LogLevel == "verbose" && cfg.General.LogTimestamps == false {
		log.Debug("[config] Verbose mode detected but timestamps disabled in config - consider enabling log_timestamps: true")
	}

	cfg.General.LogTimestamps = logTimestamps

	log.GetLogger().SetLevel(cfg.General.LogLevel)
	log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)

	log.Info("[config] Using config file: %s", configFilePath)
	log.Debug("[config] Logger configured with level: %s, timestamps: %t", cfg.General.LogLevel, cfg.General.LogTimestamps)

	config.GlobalConfig = *cfg

	output.SetGlobalConfigGetter(func() output.GlobalConfigForOutput {
		return &config.GlobalConfig
	})

	stateDir := cfg.ResolveStateDir()
	var staleAfter time.Duration
	if cfg.StaleAfter != "" {
		if d, err := time.ParseDuration(cfg.StaleAfter); err == nil {
			staleAfter = d
		} else {
			log.Warn("[state] Invalid stale_after '%s', stale reporting disabled", cfg.StaleAfter)
		}
	}
	state.Init(stateDir, staleAfter)
	if state.Default != nil {
		log.Info("[state] Tracking record presence in %s", stateDir)
	}

	domainsInterface := make(map[string]interface{})
	for k, v := range cfg.Domains {
		domainMap := make(map[string]interface{})
		domainMap["name"] = v.Name

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

		inputProfiles := v.GetInputProfiles()
		outputs := v.GetOutputs()

		domainMap["input_profiles"] = inputProfiles
		domainMap["output_profiles"] = outputs

		if v.Record.Type != "" || v.Record.TTL != 0 || v.Record.Target != "" {
			recordMap := make(map[string]interface{})
			recordMap["type"] = v.Record.Type
			recordMap["ttl"] = v.Record.TTL
			recordMap["target"] = v.Record.Target
			recordMap["update_existing"] = v.Record.UpdateExisting
			recordMap["allow_multiple"] = v.Record.AllowMultiple
			recordMap["proxied"] = v.Record.Proxied
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

	if err := domain.InitializeDomainSystem(domainsInterface, inputsInterface, outputsInterface, map[string]interface{}{}); err != nil {
		log.Fatal("[domain] Failed to initialize domain system: %v", err)
	}

	if cfg.API != nil && cfg.API.Enabled {
		apiLogger := log.NewScopedLogger("[api]", cfg.API.LogLevel)
		apiLogger.Info("Starting API server")
		if err := api.StartAPIServer(cfg.API); err != nil {
			log.Fatal("[api] Failed to start API server: %v", err)
		}
	}

	outputProfiles := make(map[string]bool)
	for _, domainConfig := range domain.GlobalDomainManager.GetAllDomains() {
		for _, outputProfile := range domainConfig.GetOutputs() {
			outputProfiles[outputProfile] = true
		}
	}

	activeOutputProfiles := make([]string, 0, len(outputProfiles))
	for profile := range outputProfiles {
		activeOutputProfiles = append(activeOutputProfiles, profile)
	}

	if len(activeOutputProfiles) == 0 {
		for profileName := range cfg.Outputs {
			activeOutputProfiles = append(activeOutputProfiles, profileName)
		}
	} else {
		log.Debug("[output] Using output profiles from domain configurations: %v", activeOutputProfiles)
	}

	if err := output.InitializeOutputManagerWithProfiles(cfg.Outputs, activeOutputProfiles); err != nil {
		log.Fatal("[output] Failed to initialize output manager: %v", err)
	}

	log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)

	log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)

	if !(cfg.API != nil && cfg.API.Enabled && len(cfg.Inputs) == 0) {
		inputProviders := make(map[string]bool)
		for _, domainConfig := range domain.GlobalDomainManager.GetAllDomains() {
			for _, inputProvider := range domainConfig.GetInputProfiles() {
				inputProviders[inputProvider] = true
			}
		}

		activeInputProfiles := make([]string, 0, len(inputProviders))
		for provider := range inputProviders {
			activeInputProfiles = append(activeInputProfiles, provider)
		}

		if len(activeInputProfiles) == 0 {
			log.Fatal("[input] No input providers specified in domain configurations")
		}

		for _, inputProviderName := range activeInputProfiles {
			if _, exists := cfg.Inputs[inputProviderName]; !exists {
				log.Fatal("[input] Input provider '%s' referenced in domains but not found in configuration", inputProviderName)
			}
		}

		log.Debug("[input] Using input providers from domain configurations: %v", activeInputProfiles)
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

			providerOptions := inputProviderConfig.GetOptions(inputProviderName)

			if inputProviderConfig.ExposeContainers {
				providerOptions["expose_containers"] = "true"
				log.Debug("[input] Adding expose_containers=true to provider options")
			}

			if filterConfig, exists := inputProviderConfig.Options["filter"]; exists {
				log.Debug("[input] Found filter configuration for %s: %+v", inputProviderName, filterConfig)
			}

			for k, v := range inputProviderConfig.Options {
				if strVal, ok := v.(string); ok {
					providerOptions[k] = strVal
				} else {
					if k == "filter" {
						log.Debug("[input] Converting filter to string for provider %s: %+v", inputProviderName, v)
					}
					providerOptions[k] = fmt.Sprintf("%v", v)
				}
			}

			log.Debug("[input] Provider %s raw config: %+v", inputProviderName, inputProviderConfig)
			log.Debug("[input] Provider %s raw config Options field: %+v", inputProviderName, inputProviderConfig.Options)
			log.Debug("[input] Provider %s final options: %v", inputProviderName, providerOptions)

			if filterOpt, exists := providerOptions["filter"]; exists {
				log.Debug("[input] Filter found in final options: %s (type: %T)", filterOpt, filterOpt)

				log.Debug("[input] Forcing JSON conversion for filter")
				if filterRaw, exists := inputProviderConfig.Options["filter"]; exists {
					if filterJSON, err := json.Marshal(filterRaw); err == nil {
						providerOptions["filter"] = string(filterJSON)
						log.Debug("[input] Successfully converted filter to JSON: %s", string(filterJSON))
					} else {
						log.Error("[input] Failed to convert filter to JSON: %v", err)
					}
				}
			}

			if filterStr, exists := providerOptions["filter"]; exists {
				log.Debug("[input] Provider %s filter option (as string): %s", inputProviderName, filterStr)
			}
			if filterRaw, exists := inputProviderConfig.Options["filter"]; exists {
				log.Debug("[input] Provider %s filter raw (before conversion): %+v", inputProviderName, filterRaw)
				log.Debug("[input] Provider %s filter raw type: %T", inputProviderName, filterRaw)
			}

			log.Trace("[input] Provider %s options: %v", inputProviderName, util.MaskSensitiveOptions(providerOptions))

			if _, hasFilter := inputProviderConfig.Options["filter"]; hasFilter {
				log.Debug("[input] Provider %s has filter configuration, attempting to apply filters", inputProviderName)
			}

			inputProvider, err := input.NewInputProvider(inputProviderType, providerOptions, output.GetOutputManager(), output.GetOutputManager())

			if err != nil {
				log.Fatal("[input] Failed to initialize input provider '%s': %v", inputProviderName, err)
			}

			if providerWithDomains, ok := inputProvider.(interface {
				SetDomainConfigs(map[string]config.DomainConfig)
			}); ok {
				log.Debug("[input] Setting domain configs on provider '%s': %+v", inputProviderName, cfg.Domains)
				providerWithDomains.SetDomainConfigs(cfg.Domains)
			} else {
				log.Debug("[input] Provider '%s' does not support domain configs", inputProviderName)
			}

			if filterConfig, hasFilter := inputProviderConfig.Options["filter"]; hasFilter {
				log.Debug("[input] Attempting to configure filters for %s after creation: %+v", inputProviderName, filterConfig)
			}

			if inputProviderType == "docker" {
				if filterConfig, exists := inputProviderConfig.Options["filter"]; exists {
					log.Debug("[input] Attempting to apply filter configuration for Docker provider %s: %+v", inputProviderName, filterConfig)
				}
			}

			if err := inputProvider.StartPolling(); err != nil {
				log.Fatal("[input] Failed to start polling with provider '%s': %v", inputProviderName, err)
			}

			inputProviderInstances = append(inputProviderInstances, inputProvider)

			log.GetLogger().SetShowTimestamps(cfg.General.LogTimestamps)
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		<-sigChan
		fmt.Printf("\nShutting down Herald\n")

		shutdownGracefully(inputProviderInstances)
	} else {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Printf("\nShutting down Herald\n")

		shutdownGracefully(nil)
	}
}

func shutdownGracefully(instances []input.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api.ShutdownAPIServers(ctx)
	state.Default.Stop()
	for _, provider := range instances {
		provider.StopPolling()
	}
}
