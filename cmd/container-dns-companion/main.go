package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"container-dns-companion/pkg/config"
	"container-dns-companion/pkg/dns"
	"container-dns-companion/pkg/dns/providers"
	"container-dns-companion/pkg/log"
	"container-dns-companion/pkg/poll"

	// Import the polling providers to ensure they register
	_ "container-dns-companion/pkg/poll/providers"
)

var (
	configFilePath = flag.String("config", "", "Path to configuration file")
	logLevel       = flag.String("log-level", "", "Log level (info, debug")
	showVersion    = flag.Bool("version", false, "Show version and exit")
)

const (
	Version = "1.0.0"
)

func main() {
	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("Container DNS Companion v%s\n", Version)
		os.Exit(0)
	}

	// Initialize logging
	log.Initialize(*logLevel)
	log.Info("Starting Container DNS Companion")

	// Register DNS providers after logging is initialized
	providers.RegisterProviders()

	// Determine the config file path
	configFile := "dns-companion.conf"
	if *configFilePath != "" {
		configFile = *configFilePath
	}

	// Find the config file
	configFilePath, err := config.FindConfigFile(configFile)
	if err != nil {
		log.Error("Failed to find configuration file: %v", err)
		os.Exit(1)
	}

	log.Info("[config] Using config file: %s", configFilePath)
	cfg, err := config.LoadConfigFile(configFilePath)
	if err != nil {
		log.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Set log level from config if not overridden by flag
	if *logLevel == "" && cfg.Global.LogLevel != "" {
		log.GetLogger().SetLevel(cfg.Global.LogLevel)
	}

	// Set log timestamps from config
	if cfg.Global.LogTimestamp {
		// Set environment variable for timestamps
		os.Setenv("LOG_TIMESTAMPS", "true")
		// Re-initialize the logger to apply the timestamp setting
		currentLevel := log.GetLogger().GetLevel()
		log.Initialize(currentLevel)
	}

	// Apply configuration to environment variables
	config.ApplyConfigToEnv(cfg, "")

	// Initialize DNS provider
	dnsProviderName := cfg.Global.DNSProvider
	if dnsProviderName == "" {
		log.Fatal("[provider] DNS provider not specified in configuration")
	}

	// Get the provider configuration
	providerConfig, ok := cfg.Provider[dnsProviderName]
	if !ok {
		log.Fatal("[provider] Provider configuration not found for: %s", dnsProviderName)
	}

	log.Info("[provider] Initializing DNS provider: %s", dnsProviderName)

	// Create a proper config map with all required fields
	providerOptions := make(map[string]string)

	// Add the API token if present
	if providerConfig.APIToken != "" {
		providerOptions["api_token"] = providerConfig.APIToken
	}

	// Add the default TTL if present
	if providerConfig.DefaultTTL > 0 {
		providerOptions["default_ttl"] = fmt.Sprintf("%d", providerConfig.DefaultTTL)
	}

	// Add any additional options
	for k, v := range providerConfig.Options {
		providerOptions[k] = v
	}

	// Initialize DNS provider with the options
	dnsProvider, err := dns.LoadProviderFromConfig(dnsProviderName, providerOptions)
	if err != nil {
		log.Fatal("[provider] Failed to initialize DNS provider: %v", err)
	}

	// Load domain configurations into a shared data structure
	domainConfigs := make(map[string]map[string]string)
	for domainKey, domainCfg := range cfg.Domain {
		domainMap := make(map[string]string)

		// Convert domain config to string map for easier access
		domainMap["name"] = domainCfg.Name
		domainMap["provider"] = domainCfg.Provider
		domainMap["zone_id"] = domainCfg.ZoneID
		if domainCfg.TTL > 0 {
			domainMap["ttl"] = fmt.Sprintf("%d", domainCfg.TTL)
		}
		domainMap["record_type"] = domainCfg.RecordType
		domainMap["target"] = domainCfg.Target
		domainMap["update_existing_record"] = fmt.Sprintf("%t", domainCfg.UpdateExistingRecord)

		// Add additional options
		for k, v := range domainCfg.Options {
			domainMap[k] = v
		}

		// Store normalized domain name as key (domain keys are already normalized in the config)
		domainConfigs[domainKey] = domainMap

		log.Debug("[domain] Loaded domain config for %s with settings: %v", domainCfg.Name, domainMap)
	}

	// Store domain configs in a global config location
	config.SetDomainConfigs(domainConfigs)

	// Get poll profiles from config
	pollProfiles := cfg.Global.PollProfiles
	if len(pollProfiles) == 0 {
		log.Fatal("[poll] No poll profiles specified in configuration")
	}

	log.Debug("[poll] Using poll profiles: %v", pollProfiles)

	// Initialize poll providers
	pollProviders := []poll.Provider{}
	for _, pollProfileName := range pollProfiles {
		pollProviderConfig, ok := cfg.Poll[pollProfileName]
		if !ok {
			log.Fatal("[poll] Poll profile not found in configuration: %s", pollProfileName)
		}

		pollProviderType := pollProviderConfig.Type
		if pollProviderType == "" {
			pollProviderType = pollProfileName
		}

		log.Info("[poll] Initializing poll provider: %s", pollProfileName)
		pollProvider, err := poll.NewPollProvider(pollProviderType, pollProviderConfig.Options)
		if err != nil {
			log.Fatal("[poll] Failed to initialize poll provider '%s': %v", pollProfileName, err)
		}

		// If the poll provider supports containers, set the DNS provider
		if containerProvider, ok := pollProvider.(poll.ProviderWithContainer); ok {
			containerProvider.SetDNSProvider(dnsProvider)
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
	fmt.Printf("\nShutting down Container DNS Companion\n")

	// Stop all poll providers
	for _, provider := range pollProviders {
		provider.StopPolling()
	}

	// Give time for cleanup
	time.Sleep(300 * time.Millisecond)
}
