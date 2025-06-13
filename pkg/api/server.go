// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package api

import (
	"dns-companion/pkg/config"
	"dns-companion/pkg/log"
	"dns-companion/pkg/output"
	"dns-companion/pkg/utils"

	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ClientData represents data from a single client
type ClientData struct {
	ClientID    string                 `json:"client_id" yaml:"client_id"`
	Received    time.Time              `json:"received" yaml:"received"`
	LastUpdate  time.Time              `json:"last_update" yaml:"last_update"`
	Metadata    *Metadata              `json:"metadata" yaml:"metadata"`
	Domains     map[string]*Domain     `json:"domains" yaml:"domains"`
}

type Metadata struct {
	Generator   string    `json:"generator" yaml:"generator"`
	Hostname    string    `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`
	Comment     string    `json:"comment,omitempty" yaml:"comment,omitempty"`
}

type Domain struct {
	Comment  string    `json:"comment,omitempty" yaml:"comment,omitempty"`
	ZoneID   string    `json:"zone_id,omitempty" yaml:"zone_id,omitempty"`
	Provider string    `json:"provider,omitempty" yaml:"provider,omitempty"`
	Records  []*Record `json:"records" yaml:"records"`
}

type Record struct {
	Hostname  string    `json:"hostname" yaml:"hostname"`
	Type      string    `json:"type" yaml:"type"`
	Target    string    `json:"target" yaml:"target"`
	TTL       uint32    `json:"ttl" yaml:"ttl"`
	Comment   string    `json:"comment,omitempty" yaml:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	Source    string    `json:"source,omitempty" yaml:"source,omitempty"`
}

// APIServer handles DNS record aggregation via HTTP API
type APIServer struct {
	clients        map[string]*ClientData
	mutex          sync.RWMutex
	profiles       map[string]config.APIClientProfile // client_id -> profile config
	clientExpiry   time.Duration
	outputProfiles map[string]interface{}             // Available output profiles from config
	logger         *log.ScopedLogger                  // Scoped logger for API server
	failedAttempts map[string]*FailedAttemptTracker   // Track failed authentication attempts by IP
	attemptsMutex  sync.RWMutex                       // Separate mutex for failed attempts
}

// FailedAttemptTracker tracks failed authentication attempts from an IP
type FailedAttemptTracker struct {
	Count       int
	FirstFailed time.Time
	LastFailed  time.Time
}

// Generate a short connection ID (8 characters)
func generateConnectionID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Connection ID context key
type contextKey string
const connectionIDKey contextKey = "connectionID"

// connectionIDMiddleware adds a unique connection ID to each request
func connectionIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID := generateConnectionID()
		ctx := context.WithValue(r.Context(), connectionIDKey, connID)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

// getConnectionID extracts the connection ID from request context
func getConnectionID(r *http.Request) string {
	if id, ok := r.Context().Value(connectionIDKey).(string); ok {
		return id
	}
	return "unknown"
}

func NewAPIServer(outputProfiles map[string]interface{}, apiConfig *config.APIConfig) *APIServer {
	// Create scoped logger for API server
	logLevel := ""
	if apiConfig != nil && apiConfig.LogLevel != "" {
		logLevel = apiConfig.LogLevel
	}

	scopedLogger := log.NewScopedLogger("[api]", logLevel)
	if logLevel != "" {
		scopedLogger.Info("API server log_level set to: '%s'", logLevel)
	}

	return &APIServer{
		clients:        make(map[string]*ClientData),
		profiles:       make(map[string]config.APIClientProfile),
		clientExpiry:   10 * time.Minute, // Remove clients after 10 minutes of no updates
		outputProfiles: outputProfiles,
		logger:         scopedLogger,
		failedAttempts: make(map[string]*FailedAttemptTracker),
	}
}

// LoadClientProfiles loads client profiles from the API config
func (s *APIServer) LoadClientProfiles(profiles map[string]config.APIClientProfile) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.profiles = profiles
	s.logger.Verbose("Loaded %d client profiles", len(profiles))
	s.logger.Verbose("Client profiles configured: %v", func() []string {
		var names []string
		for name := range profiles {
			names = append(names, name)
		}
		return names
	}())
}

// recordFailedAttempt tracks a failed authentication attempt from an IP
func (s *APIServer) recordFailedAttempt(remoteAddr string, clientID string, reason string) {
	// Extract IP from remote address (remove port)
	ip := strings.Split(remoteAddr, ":")[0]

	s.attemptsMutex.Lock()
	defer s.attemptsMutex.Unlock()

	now := time.Now()
	if tracker, exists := s.failedAttempts[ip]; exists {
		tracker.Count++
		tracker.LastFailed = now
	} else {
		s.failedAttempts[ip] = &FailedAttemptTracker{
			Count:       1,
			FirstFailed: now,
			LastFailed:  now,
		}
	}

	tracker := s.failedAttempts[ip]

	// Log with increasing severity based on attempt count
	if tracker.Count >= 10 {
		s.logger.Error("SECURITY: %d failed auth attempts from %s (client_id: %s, reason: %s)",
			tracker.Count, ip, clientID, reason)
	} else if tracker.Count >= 5 {
		s.logger.Warn("Multiple failed auth attempts from %s: %d attempts (client_id: %s, reason: %s)",
			ip, tracker.Count, clientID, reason)
	} else {
		s.logger.Debug("Failed auth attempt from %s (client_id: %s, reason: %s)", ip, clientID, reason)
	}
}

// isRateLimited checks if an IP should be rate limited based on failed attempts
func (s *APIServer) isRateLimited(remoteAddr string) bool {
	// Extract IP from remote address (remove port)
	ip := strings.Split(remoteAddr, ":")[0]

	s.attemptsMutex.RLock()
	defer s.attemptsMutex.RUnlock()

	tracker, exists := s.failedAttempts[ip]
	if !exists {
		return false
	}

	// Rate limit if more than 20 failed attempts in the last hour
	if tracker.Count >= 20 && time.Since(tracker.FirstFailed) < time.Hour {
		return true
	}

	return false
}

// cleanupFailedAttempts removes old failed attempt records (called periodically)
func (s *APIServer) cleanupFailedAttempts() {
	s.attemptsMutex.Lock()
	defer s.attemptsMutex.Unlock()

	now := time.Now()
	cleanedCount := 0

	for ip, tracker := range s.failedAttempts {
		// Remove records older than 24 hours
		if now.Sub(tracker.FirstFailed) > 24*time.Hour {
			delete(s.failedAttempts, ip)
			cleanedCount++
		}
	}

	if cleanedCount > 0 {
		s.logger.Debug("Cleaned up %d old failed attempt records", cleanedCount)
	}
}

// resetFailedAttempts clears failed attempts for an IP (called on successful auth)
func (s *APIServer) resetFailedAttempts(remoteAddr string) {
	// Extract IP from remote address (remove port)
	ip := strings.Split(remoteAddr, ":")[0]

	s.attemptsMutex.Lock()
	defer s.attemptsMutex.Unlock()

	if tracker, exists := s.failedAttempts[ip]; exists && tracker.Count > 0 {
		s.logger.Debug("Clearing %d failed attempts for %s after successful auth", tracker.Count, ip)
		delete(s.failedAttempts, ip)
	}
}

// authenticateClient validates client authentication
func (s *APIServer) authenticateClient(r *http.Request) (string, bool) {
	connID := getConnectionID(r)

	// Check if this IP is rate limited first
	if s.isRateLimited(r.RemoteAddr) {
		s.logger.Warn("[%s] SECURITY: Rate limited IP attempted connection: %s", connID, r.RemoteAddr)
		return "", false
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		s.recordFailedAttempt(r.RemoteAddr, "unknown", "missing/invalid Authorization header")
		return "", false
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	clientID := r.Header.Get("X-Client-ID")

	if clientID == "" {
		s.recordFailedAttempt(r.RemoteAddr, "unknown", "missing X-Client-ID header")
		return "", false
	}

	s.mutex.RLock()
	profile, exists := s.profiles[clientID]
	s.mutex.RUnlock()

	if !exists {
		s.recordFailedAttempt(r.RemoteAddr, clientID, "unknown client_id")
		return "", false
	}

	if profile.Token != token {
		s.recordFailedAttempt(r.RemoteAddr, clientID, "invalid token")
		return "", false
	}

	// Authentication successful - clear any failed attempts for this IP
	s.resetFailedAttempts(r.RemoteAddr)
	s.logger.Debug("[%s] Authentication successful for client_id: %s from %s", connID, clientID, r.RemoteAddr)
	return clientID, true
}

// HandleDataUpload processes incoming DNS data from clients
func (s *APIServer) HandleDataUpload(w http.ResponseWriter, r *http.Request) {
	connID := getConnectionID(r)

	if r.Method != http.MethodPost {
		s.logger.Debug("[%s] Method not allowed: %s", connID, r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Verbose("[%s] New connection from %s", connID, r.RemoteAddr)

	// Authenticate client
	clientID, authenticated := s.authenticateClient(r)
	if !authenticated {
		s.logger.Warn("[%s] Unauthorized request from %s", connID, r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.logger.Verbose("[%s] Processing upload from client: %s", connID, clientID)

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("[%s] Failed to read body from client %s: %v", connID, clientID, err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	s.logger.Debug("[%s] Received %d bytes from client %s", connID, len(body), clientID)

	// Parse based on content type
	var clientData ClientData
	contentType := r.Header.Get("Content-Type")

	s.logger.Trace("[%s] Content-Type: %s", connID, contentType)

	switch {
	case strings.Contains(contentType, "application/json"):
		if err := json.Unmarshal(body, &clientData); err != nil {
			s.logger.Error("[%s] Failed to parse JSON from client %s: %v", connID, clientID, err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		s.logger.Debug("[%s] Successfully parsed JSON data from client %s", connID, clientID)
	case strings.Contains(contentType, "application/x-yaml"):
		if err := yaml.Unmarshal(body, &clientData); err != nil {
			s.logger.Error("[%s] Failed to parse YAML from client %s: %v", connID, clientID, err)
			http.Error(w, "Invalid YAML", http.StatusBadRequest)
			return
		}
		s.logger.Trace("[%s] Successfully parsed YAML data from client %s", connID, clientID)
	default:
		s.logger.Error("[%s] Unsupported content type from client %s: %s", connID, clientID, contentType)
		http.Error(w, "Unsupported content type", http.StatusBadRequest)
		return
	}

	// Store client data
	s.mutex.Lock()
	defer s.mutex.Unlock()

	clientData.ClientID = clientID
	clientData.Received = time.Now()
	s.clients[clientID] = &clientData

	s.logger.Info("[%s] Received data from client %s with %d domains", connID, clientID, len(clientData.Domains))
	s.logger.Debug("[%s] Client %s metadata: generator=%s, hostname=%s", connID, clientID,
		func() string { if clientData.Metadata != nil { return clientData.Metadata.Generator } else { return "unknown" } }(),
		func() string { if clientData.Metadata != nil { return clientData.Metadata.Hostname } else { return "unknown" } }())

	// Log domain details at trace level
	for domainName, domain := range clientData.Domains {
		s.logger.Trace("[%s] Client %s domain '%s': %d records, provider=%s", connID, clientID, domainName, len(domain.Records), domain.Provider)
	}

	// Trigger aggregation
	go s.aggregateAndWrite(connID)

	s.logger.Debug("[%s] Completed processing for client %s", connID, clientID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// aggregateAndWrite combines all client data and writes to the specified output profile
func (s *APIServer) aggregateAndWrite(connID string) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	s.logger.Trace("[%s] Starting data aggregation and write process", connID)

	// Remove expired clients
	now := time.Now()
	expiredCount := 0
	for clientID, data := range s.clients {
		if now.Sub(data.Received) > s.clientExpiry {
			delete(s.clients, clientID)
			expiredCount++
			s.logger.Info("[%s] Removed expired client: %s", connID, clientID)
		}
	}
	if expiredCount > 0 {
		s.logger.Debug("[%s] Removed %d expired clients", connID, expiredCount)
	}

	s.logger.Debug("[%s] Processing data from %d active clients", connID, len(s.clients))

	// Group clients by their output profiles
	clientsByProfile := make(map[string][]string)
	for clientID := range s.clients {
		if profile, exists := s.profiles[clientID]; exists {
			outputProfile := profile.OutputProfile
			if outputProfile == "" {
				outputProfile = "default"
			}
			clientsByProfile[outputProfile] = append(clientsByProfile[outputProfile], clientID)
		}
	}

	// Aggregate data for each output profile separately
	for outputProfile, clientIDs := range clientsByProfile {
		aggregatedRecords := make(map[string][]map[string]interface{})

		s.logger.Verbose("[%s] Aggregating data for output profile '%s' from %d clients", connID, outputProfile, len(clientIDs))

		for _, clientID := range clientIDs {
			data := s.clients[clientID]
			s.logger.Trace("[%s] Processing client %s data for profile %s", connID, clientID, outputProfile)

			for domainName, domain := range data.Domains {
				if aggregatedRecords[domainName] == nil {
					aggregatedRecords[domainName] = make([]map[string]interface{}, 0)
				}

				// Add all records from this client, prefixing source with client ID
				for _, record := range domain.Records {
					recordMap := map[string]interface{}{
						"hostname":   record.Hostname,
						"type":       record.Type,
						"target":     record.Target,
						"ttl":        record.TTL,
						"comment":    record.Comment,
						"created_at": record.CreatedAt,
						"source":     fmt.Sprintf("%s:%s", clientID, record.Source),
					}
					aggregatedRecords[domainName] = append(aggregatedRecords[domainName], recordMap)
					s.logger.Trace("[%s] Added record from client %s: %s.%s (%s) -> %s",
						connID, clientID, record.Hostname, domainName, record.Type, record.Target)
				}
			}
		}

		// Write aggregated data to the specified output profile if we have data
		if len(aggregatedRecords) > 0 {
			s.logger.Debug("[%s] Writing %d aggregated domains to output profile '%s'", connID, len(aggregatedRecords), outputProfile)

			// Log summary of aggregated data
			for domainName, records := range aggregatedRecords {
				s.logger.Verbose("[%s] Profile '%s' domain '%s': %d records", connID, outputProfile, domainName, len(records))
			}

			// Get the output profile configuration
			if _, exists := s.outputProfiles[outputProfile]; exists {
				s.logger.Trace("[%s] Found output profile configuration for '%s'", connID, outputProfile)

				// Write aggregated records through the output manager
				//s.logger.Info("[%s] Writing %d domains to output profile '%s'", connID, len(aggregatedRecords), outputProfile)

				outputManager := output.GetOutputManager()
				if outputManager != nil {
					// Write each aggregated record through the output manager
					var writeErrors []error
					recordCount := 0
					
					for domainName, records := range aggregatedRecords {
						for _, record := range records {
							hostname, _ := record["hostname"].(string)
							recordType, _ := record["type"].(string)
							target, _ := record["target"].(string)
							ttl, _ := record["ttl"].(uint32)
							source, _ := record["source"].(string)

							err := outputManager.WriteRecordWithSource(domainName, hostname, target, recordType, int(ttl), source)
							if err != nil {
								s.logger.Error("[%s] Failed to write aggregated record %s.%s: %v", connID, hostname, domainName, err)
								writeErrors = append(writeErrors, err)
							} else {
								recordCount++
							}
						}
					}

					// Sync all output formats to flush changes
					syncErr := outputManager.SyncAll()
					if syncErr != nil {
						s.logger.Error("[%s] Failed to sync output formats: %v", connID, syncErr)
						writeErrors = append(writeErrors, syncErr)
					}

					// Only log success if there were no errors
					if len(writeErrors) == 0 && recordCount > 0 {
						s.logger.Info("[%s] Successfully wrote %d records from %d domains (%d clients) to output profile '%s'",
							connID, recordCount, len(aggregatedRecords), len(clientIDs), outputProfile)
					} else if len(writeErrors) > 0 {
						s.logger.Error("[%s] Failed to write data to output profile '%s': %d errors occurred", 
							connID, outputProfile, len(writeErrors))
					} else {
						s.logger.Warn("[%s] No records were written to output profile '%s' (no data to process)", 
							connID, outputProfile)
					}
				} else {
					s.logger.Error("[%s] Output manager not available for profile '%s'", connID, outputProfile)
				}

				s.logger.Debug("[%s] Completed aggregation for profile '%s'", connID, outputProfile)
			} else {
				s.logger.Error("[%s] Output profile '%s' not found in configuration", connID, outputProfile)
				s.logger.Debug("[%s] Available output profiles: %v", connID, func() []string {
					var names []string
					for name := range s.outputProfiles {
						names = append(names, name)
					}
					return names
				}())
			}
		} else {
			s.logger.Debug("[%s] No records to aggregate for output profile '%s'", connID, outputProfile)
		}
	}
}

// StartAPIServer starts the DNS API server
func StartAPIServer(apiConfig *config.APIConfig) error {
	if !apiConfig.Enabled {
		return nil
	}

	// Get output profiles from global config
	globalConfig := config.GetGlobalConfig()
	if globalConfig == nil {
		return fmt.Errorf("no global configuration available for output profiles")
	}

	server := NewAPIServer(globalConfig.Outputs, apiConfig)

	// Load client profiles from config with file support
	if len(apiConfig.Profiles) > 0 {
		resolvedProfiles := make(map[string]config.APIClientProfile)

		for clientID, profile := range apiConfig.Profiles {
			token := profile.Token

			// Support file-based token loading
			if strings.HasPrefix(token, "file://") {
				filePath := token[7:] // Remove "file://" prefix
				server.logger.Debug("Loading token for client '%s' from file: %s", clientID, filePath)

				tokenBytes, err := os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("failed to read token file for client '%s' at '%s': %w", clientID, filePath, err)
				}

				token = strings.TrimSpace(string(tokenBytes))
				if token == "" {
					return fmt.Errorf("token file for client '%s' is empty: %s", clientID, filePath)
				}

				server.logger.Verbose("Successfully loaded token for client '%s' from file", clientID)
			}

			if token == "" {
				return fmt.Errorf("client '%s' has empty token", clientID)
			}

			// Store the resolved token
			resolvedProfiles[clientID] = config.APIClientProfile{
				Token:         token,
				OutputProfile: profile.OutputProfile,
			}

			server.logger.Debug("Registered client profile: %s -> %s", clientID, profile.OutputProfile)
		}

		server.LoadClientProfiles(resolvedProfiles)
	}

	// Load client tokens if token file is specified (for backward compatibility)
	if apiConfig.TokenFile != "" {
		data, err := os.ReadFile(apiConfig.TokenFile)
		if err != nil {
			return fmt.Errorf("failed to read token file: %w", err)
		}

		var tokens map[string]string
		if err := yaml.Unmarshal(data, &tokens); err != nil {
			return fmt.Errorf("failed to parse token file: %w", err)
		}

		// Convert token file format to profiles
		profiles := make(map[string]config.APIClientProfile)
		for clientID, token := range tokens {
			profiles[clientID] = config.APIClientProfile{
				Token:         token,
				OutputProfile: apiConfig.OutputProfile, // Use default output profile
			}
		}
		server.LoadClientProfiles(profiles)
	}

	// Set client expiry if specified
	if apiConfig.ClientExpiry != "" {
		if duration, err := time.ParseDuration(apiConfig.ClientExpiry); err == nil {
			server.clientExpiry = duration
		} else {
			server.logger.Warn("Invalid client_expiry format '%s', using default", apiConfig.ClientExpiry)
		}
	}

	// Set up HTTP handler
	endpoint := apiConfig.Endpoint
	if endpoint == "" {
		endpoint = "/api/dns"
	}
	http.HandleFunc(endpoint, connectionIDMiddleware(server.HandleDataUpload))

	port := apiConfig.Port
	if port == "" {
		port = "8080"
	}

	server.logger.Debug("Endpoint: %s", endpoint)

	if len(apiConfig.Profiles) > 0 {
		server.logger.Verbose("Loaded %d client profiles", len(apiConfig.Profiles))
	}

	// Validate listen patterns before proceeding
	if len(apiConfig.Listen) > 0 {
		if err := utils.ValidateListenPatterns(apiConfig.Listen); err != nil {
			return fmt.Errorf("invalid listen patterns: %w", err)
		}
		server.logger.Trace("Listen patterns validated: %v", apiConfig.Listen)
	}

	// Resolve listen addresses based on patterns with API-specific logging
	addresses, err := utils.ResolveListenAddressesQuiet(apiConfig.Listen, port)
	if err != nil {
		server.logger.Warn("Interface resolution warning: %v", err)
	} else {
		server.logger.Debug("Resolved %d listen addresses from patterns %v", len(addresses), apiConfig.Listen)
	}

	for _, addr := range addresses {
		server.logger.Verbose("Listen address: %s", addr)
	}

	// Configure TLS if enabled
	var serverFuncs []func() error

	if apiConfig.TLS != nil && (apiConfig.TLS.Cert != "" || apiConfig.TLS.Key != "" || apiConfig.TLS.CA != "") {
		if apiConfig.TLS.Cert == "" || apiConfig.TLS.Key == "" {
			return fmt.Errorf("TLS configuration requires both cert and key")
		}

		tlsConfig := &tls.Config{}

		// Set up client certificate verification if CA file is provided
		if apiConfig.TLS.CA != "" {
			caCert, err := os.ReadFile(apiConfig.TLS.CA)
			if err != nil {
				return fmt.Errorf("failed to read CA file: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse CA certificate")
			}

			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			server.logger.Info("TLS client certificate verification enabled")
		}

		server.logger.Info("Starting HTTPS servers with TLS")
		for _, address := range addresses {
			addr := address // capture for closure
			httpServer := &http.Server{
				Addr:      addr,
				TLSConfig: tlsConfig,
			}

			serverFunc := func() error {
				server.logger.Debug("Starting HTTPS server on %s", addr)
				return httpServer.ListenAndServeTLS(apiConfig.TLS.Cert, apiConfig.TLS.Key)
			}
			serverFuncs = append(serverFuncs, serverFunc)
		}
	} else {
		server.logger.Warn("WARNING: Running HTTP servers without TLS - use only on trusted networks!")
		for _, address := range addresses {
			addr := address // capture for closure
			serverFunc := func() error {
				server.logger.Verbose("Starting HTTP server on %s", addr)
				return http.ListenAndServe(addr, nil)
			}
			serverFuncs = append(serverFuncs, serverFunc)
		}
	}

	// Start all servers in goroutines so they don't block
	for i, serverFunc := range serverFuncs {
		go func(index int, fn func() error) {
			if err := fn(); err != nil {
				server.logger.Error("Server %d error: %v", index, err)
			}
		}(i, serverFunc)
	}

	// Start background cleanup routine for failed attempts
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				server.cleanupFailedAttempts()
			}
		}
	}()

	return nil
}