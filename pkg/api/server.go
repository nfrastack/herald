// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package api

import (
	"herald/pkg/config"
	"herald/pkg/log"
	"herald/pkg/output"
	"herald/pkg/util"

	inputtypes "herald/pkg/input/types"

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
	ClientID   string             `json:"client_id" yaml:"client_id"`
	Received   time.Time          `json:"received" yaml:"received"`
	LastUpdate time.Time          `json:"last_update" yaml:"last_update"`
	Metadata   *Metadata          `json:"metadata" yaml:"metadata"`
	Domains    map[string]*Domain `json:"domains" yaml:"domains"`
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

type RemoteActionPayload struct {
	Action  string             `json:"action" yaml:"action"`
	Domains map[string]*Domain `json:"domains" yaml:"domains"`
}

// APIServer handles DNS record aggregation via HTTP API
// Add inputProviderGetter to avoid import cycle
type APIServer struct {
	clients        map[string]*ClientData
	mutex          sync.RWMutex
	profiles       map[string]config.APIClientProfile // client_id -> profile config
	clientExpiry   time.Duration
	outputProfiles map[string]interface{} // Available output profiles from config
	outputManager  *output.OutputManager  // API server's own output manager
	logger         *log.ScopedLogger
	failedAttempts map[string]*FailedAttemptTracker // Track failed authentication attempts by IP
	attemptsMutex  sync.RWMutex                     // Separate mutex for failed attempts

	InputProviderGetter func() []inputtypes.Provider // Function to get input providers (DI)
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
		s.logger.Verbose("Failed auth attempt from %s (client_id: %s, reason: %s)", ip, clientID, reason)
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
	clientIDHeader := r.Header.Get("X-Client-ID")

	// Debug: log what headers we're receiving
	s.logger.Debug("[%s] Auth headers - Authorization: '%s', X-Client-ID: '%s'", connID,
		func() string {
			if authHeader == "" {
				return "(missing)"
			}
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				return "Bearer " + util.MaskSensitiveValue(token)
			}
			return util.MaskSensitiveValue(authHeader)
		}(),
		func() string {
			if clientIDHeader == "" {
				return "(missing)"
			}
			return clientIDHeader
		}())

	if !strings.HasPrefix(authHeader, "Bearer ") {
		s.recordFailedAttempt(r.RemoteAddr, clientIDHeader, "missing/invalid Authorization header")
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
	s.logger.Trace("[%s] Raw request body: %s", connID, string(body))

	// Parse based on content type
	var clientData ClientData
	var remotePayload RemoteActionPayload
	contentType := r.Header.Get("Content-Type")
	s.logger.Trace("[%s] Content-Type: %s", connID, contentType)
	s.logger.Trace("[%s] Payload: %s", connID, string(body))

	// Deep debug: print all in-memory data before removals
	s.mutex.RLock()
	s.logger.Debug("[%s] [DEBUG] In-memory data BEFORE removals: %s", connID, func() string {
		b, _ := json.MarshalIndent(s.clients, "", "  "); return string(b)
	}())
	s.mutex.RUnlock()

	// Refactored: Only remove records from the uploading client's data
	switch {
	default:
		// Try JSON first
		if err := json.Unmarshal(body, &clientData); err == nil {
			// Check for removals map in the raw JSON
			var raw map[string]interface{}
			if err := json.Unmarshal(body, &raw); err == nil {
				if removals, ok := raw["removals"].(map[string]interface{}); ok {
					s.mutex.Lock()
					s.logger.Debug("[DEBUG] In-memory data BEFORE removals: %s", func() string {
						b, _ := json.MarshalIndent(s.clients, "", "  ")
						return string(b)
					}())
					client, ok := s.clients[clientID]
					if ok && client.Domains != nil {
						for domain, recs := range removals {
							recList, ok := recs.([]interface{})
							if !ok {
								continue
							}
							domainObj, ok := client.Domains[domain]
							if !ok || domainObj == nil {
								continue
							}
							newRecords := make([]*Record, 0, len(domainObj.Records))
							for _, record := range domainObj.Records {
								shouldRemove := false
								for _, r := range recList {
									rm, ok := r.(map[string]interface{})
									if !ok {
										continue
									}
									if record.Hostname == rm["hostname"] && record.Type == rm["type"] {
										shouldRemove = true
										s.logger.Debug("[DEBUG] Removing record: domain=%s, client=%s, hostname=%s, type=%s", domain, clientID, record.Hostname, record.Type)
										break
									}
								}
								if !shouldRemove {
									newRecords = append(newRecords, record)
								}
							}
							domainObj.Records = newRecords
						}
					}
					s.logger.Debug("[DEBUG] In-memory data AFTER removals (client only): %s", func() string {
						b, _ := json.MarshalIndent(s.clients, "", "  ")
						return string(b)
					}())
					s.mutex.Unlock()
				}
			} else if err := json.Unmarshal(body, &remotePayload); err == nil && remotePayload.Action == "remove" {
				// Remove records for each domain in remotePayload.Domains
				s.mutex.Lock()
				client, ok := s.clients[clientID]
				if ok && client.Domains != nil {
					for domain, dom := range remotePayload.Domains {
						domainObj, ok := client.Domains[domain]
						if !ok || domainObj == nil {
							continue
						}
						newRecords := make([]*Record, 0, len(domainObj.Records))
						for _, record := range domainObj.Records {
							shouldRemove := false
							for _, r := range dom.Records {
								if record.Hostname == r.Hostname && record.Type == r.Type {
									shouldRemove = true
									s.logger.Debug("[%s] [DEBUG] Removing record (remote, client only): domain=%s, client=%s, hostname=%s, type=%s", connID, domain, clientID, record.Hostname, record.Type)
									break
								}
							}
							if !shouldRemove {
								newRecords = append(newRecords, record)
							}
						}
						domainObj.Records = newRecords
					}
				}
				s.logger.Debug("[%s] [DEBUG] In-memory data AFTER removals (remote, client only): %s", connID, func() string {
					b, _ := json.MarshalIndent(s.clients, "", "  "); return string(b)
				}())
				s.mutex.Unlock()
			}
		}
	}

	// Deep debug: print all in-memory data after removals
	s.mutex.RLock()
	s.logger.Debug("[%s] [DEBUG] In-memory data AFTER removals: %s", connID, func() string {
		b, _ := json.MarshalIndent(s.clients, "", "  "); return string(b)
	}())
	s.mutex.RUnlock()

	// Store client data
	s.mutex.Lock()
	defer s.mutex.Unlock()

	clientData.ClientID = clientID
	clientData.Received = time.Now()
	// Only update the client's state if there are domains/records in the payload
	if len(clientData.Domains) > 0 {
		existing, ok := s.clients[clientID]
		if !ok {
			// New client, just add
			s.clients[clientID] = &clientData
		} else {
			// Update only the domains present in the upload, preserve others
			for domain, dom := range clientData.Domains {
				existing.Domains[domain] = dom
			}
			// Optionally update metadata and timestamps
			existing.Metadata = clientData.Metadata
			existing.Received = clientData.Received
			existing.LastUpdate = time.Now()
		}
	}

	s.logger.Info("[%s] Received data from client %s with %d domains", connID, clientID, len(clientData.Domains))
	s.logger.Debug("[%s] Client %s metadata: generator=%s", connID, clientID,
		func() string {
			if clientData.Metadata != nil {
				return clientData.Metadata.Generator
			} else {
				return "unknown"
			}
		}())

	// Log domain details at trace level
	for domainName, domain := range clientData.Domains {
		s.logger.Trace("[%s] Client %s domain '%s': %d records", connID, clientID, domainName, len(domain.Records))
	}

	// Trigger aggregation
	go s.aggregateAndWrite(connID)

	s.logger.Debug("[%s] Completed processing for client %s", connID, clientID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// aggregateAndWrite combines all sources (API clients + all input providers) and writes to the specified output profile
func (s *APIServer) aggregateAndWrite(connID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.logger.Trace("[%s] Starting data aggregation and write process (multi-source)", connID)

	if s.InputProviderGetter == nil {
		s.logger.Warn("[%s] InputProviderGetter is not set; skipping aggregation from input providers", connID)
		return
	}

	// Remove expired clients (API clients only)
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

	s.logger.Debug("[%s] Processing data from %d active API clients", connID, len(s.clients))

	// --- Refactored: Aggregate records by domain config key ---
	type aggKey struct {
		DomainKey string
		Domain   string
	}
	type aggRecord struct {
		Hostname   string
		Type       string
		Target     string
		TTL        int
		Source     string
		Comment    string
		CreatedAt  time.Time
	}
	// Map: aggKey -> {records, outputs}
	aggregate := make(map[aggKey]struct {
		records []aggRecord
		outputs []string
	})

	cfg := config.GetGlobalConfig()
	if cfg == nil || cfg.Domains == nil {
		s.logger.Error("[%s] No global config or domains available", connID)
		return
	}

	// Helper: contains
	contains := func(list []string, val string) bool {
		for _, v := range list {
			if v == val {
				return true
			}
		}
		return false
	}

	// 1. Aggregate from API clients (use client profile's OutputProfile)
	for clientID, data := range s.clients {
		profile, ok := s.profiles[clientID]
		if !ok || profile.OutputProfile == "" {
			s.logger.Warn("[%s] No output profile configured for API client '%s'", connID, clientID)
			continue
		}
		outputProfile := profile.OutputProfile
		for domainName, domain := range data.Domains {
			agg := aggKey{DomainKey: outputProfile, Domain: domainName}
			aggVal, exists := aggregate[agg]
			if !exists {
				aggVal.outputs = []string{outputProfile}
			}
			for _, record := range domain.Records {
				rec := aggRecord{
					Hostname:  record.Hostname,
					Type:      record.Type,
					Target:    record.Target,
					TTL:       int(record.TTL),
					Source:    fmt.Sprintf("api:%s", clientID),
					Comment:   record.Comment,
					CreatedAt: record.CreatedAt,
				}
				aggVal.records = append(aggVal.records, rec)
			}
			aggregate[agg] = aggVal
		}
	}

	// 2. Aggregate from all input providers
	inputProviders := s.InputProviderGetter()
	for _, provider := range inputProviders {
		if provider == nil {
			s.logger.Error("[%s] Skipping nil input provider in aggregation", connID)
			continue
		}
		entries, err := provider.GetDNSEntries()
		if err != nil {
			s.logger.Warn("[%s] Failed to get DNS entries from provider %s: %v", connID, provider.GetName(), err)
			continue
		}
		for _, entry := range entries {
			// For each domain config, check if this provider is allowed as input
			for _, domCfg := range cfg.Domains {
				if domCfg.Name != entry.Domain {
					continue
				}
				if !contains(domCfg.GetInputProfiles(), provider.GetName()) {
					continue
				}
				outputs := domCfg.GetOutputs()
				for _, outputProfile := range outputs {
					agg := aggKey{DomainKey: outputProfile, Domain: entry.Domain}
					aggVal, exists := aggregate[agg]
					if !exists {
						aggVal.outputs = []string{outputProfile}
					}
					rec := aggRecord{
						Hostname:  entry.Hostname,
						Type:      entry.RecordType,
						Target:    entry.Target,
						TTL:       entry.TTL,
						Source:    provider.GetName(),
						Comment:   "",
						CreatedAt: time.Now(),
					}
					aggVal.records = append(aggVal.records, rec)
					aggregate[agg] = aggVal
				}
			}
		}
	}
	// --- END STRICT OUTPUT PROFILE FILTERING (DEDICATED DOMAIN LOGIC) ---

	// 3. Apply removals (from API clients) to the aggregate, for all outputs that contain the record, not just the client's output profile
	removals := make(map[string][]map[string]string) // domain -> list of {hostname, type}
	for _, client := range s.clients {
		if client.Domains == nil {
			continue
		}
		for domain, dom := range client.Domains {
			for _, record := range dom.Records {
				if record.Comment == "REMOVED" {
					rm := map[string]string{"hostname": record.Hostname, "type": record.Type}
					removals[domain] = append(removals[domain], rm)
				}
			}
		}
	}
	// Remove from all aggregate groups for the domain, not just the client's output profile
	toDelete := []aggKey{}
	for agg, group := range aggregate {
		if rmList, ok := removals[agg.Domain]; ok {
			filtered := make([]aggRecord, 0, len(group.records))
			for _, record := range group.records {
				shouldRemove := false
				for _, rm := range rmList {
					if record.Hostname == rm["hostname"] && record.Type == rm["type"] {
						shouldRemove = true
						break
					}
				}
				if !shouldRemove {
					filtered = append(filtered, record)
				}
			}
			if len(filtered) > 0 {
				group.records = filtered
				aggregate[agg] = group
			} else {
				toDelete = append(toDelete, agg)
			}
		}
	}
	for _, agg := range toDelete {
		delete(aggregate, agg)
	}

	// 4. Write each group of records to its allowed outputs
	// --- DEBUG: Dump aggregate map before writing ---
	s.logger.Debug("[%s] [DEBUG] Aggregate map before write: %d groups", connID, len(aggregate))
	for agg, group := range aggregate {
		recSummaries := make([]string, 0, len(group.records))
		for _, rec := range group.records {
			recSummaries = append(recSummaries, fmt.Sprintf("%s %s %s -> %s (TTL: %d, Source: %s)", rec.Hostname, rec.Type, agg.Domain, rec.Target, rec.TTL, rec.Source))
		}
		s.logger.Debug("[%s]   OutputProfile=%s Domain=%s: %d records: %v", connID, agg.DomainKey, agg.Domain, len(group.records), recSummaries)
	}
	// --- END DEBUG ---
	for agg, group := range aggregate {
		if len(group.outputs) == 0 {
			s.logger.Warn("[%s] No output profiles configured for domain config '%s' (domain '%s')", connID, agg.DomainKey, agg.Domain)
			continue
		}
		for _, outputProfile := range group.outputs {
			if s.outputManager == nil {
				s.logger.Error("[%s] Output manager not available for profile '%s'", connID, outputProfile)
				continue
			}
			profile := s.outputManager.GetProfile(outputProfile)
			if profile == nil {
				s.logger.Error("[%s] Output profile '%s' not found in configuration", connID, outputProfile)
				continue
			}
			if zoneProfile, ok := profile.(interface{ ClearRecords(string) }); ok {
				zoneProfile.ClearRecords(agg.Domain)
			}
			for _, record := range group.records {
				err := s.writeToSpecificProfile(s.outputManager, outputProfile, agg.Domain, record.Hostname, record.Target, record.Type, record.TTL, record.Source)
				if err != nil {
					s.logger.Error("[%s] Failed to write record %s.%s to profile '%s': %v", connID, record.Hostname, agg.Domain, outputProfile, err)
				}
			}
		}
	}
}

// getDomainOutputProfiles returns a map of domain name -> []output profile names from config
func (s *APIServer) getDomainOutputProfiles() map[string][]string {
	result := make(map[string][]string)
	globalConfig := config.GetGlobalConfig()
	if globalConfig == nil {
		return result
	}
	for _, domainCfg := range globalConfig.Domains {
		name := domainCfg.Name
		if name == "" {
			continue
		}
		outputs := domainCfg.Profiles.Outputs
		if len(outputs) > 0 {
			result[name] = outputs
		}
	}
	return result
}

// writeToSpecificProfile writes a record to only the specified output profile
func (s *APIServer) writeToSpecificProfile(outputManager *output.OutputManager, profileName, domain, hostname, target, recordType string, ttl int, source string) error {
	// Get the specific output profile and write directly to it
	profile := outputManager.GetProfile(profileName)
	if profile == nil {
		return fmt.Errorf("output profile '%s' not found", profileName)
	}

	// Write directly to the zone file profile, bypassing domain routing
	err := profile.WriteRecordWithSource(domain, hostname, target, recordType, ttl, source)
	if err != nil {
		return fmt.Errorf("failed to write to profile '%s': %v", profileName, err)
	}

	s.logger.Debug("API record written to zone file: %s.%s (%s) -> %s (TTL: %d)",
		hostname, domain, recordType, target, ttl)

	return nil
}

// initializeAPIOutputProfiles initializes output profiles that the API server needs
func (s *APIServer) initializeAPIOutputProfiles(outputConfigs map[string]interface{}) error {
	// Get list of output profiles that API clients will use
	profilesNeeded := make(map[string]bool)
	for _, profile := range s.profiles {
		if profile.OutputProfile != "" {
			profilesNeeded[profile.OutputProfile] = true
		}
	}

	if len(profilesNeeded) == 0 {
		s.logger.Debug("No API output profiles needed")
		return nil
	}

	// Convert to slice for InitializeOutputManagerWithProfiles
	enabledProfiles := make([]string, 0, len(profilesNeeded))
	for profileName := range profilesNeeded {
		enabledProfiles = append(enabledProfiles, profileName)
	}

	s.logger.Debug("Initializing API output profiles: %v", enabledProfiles)

	// Debug: check if the profile exists in config
	for _, profileName := range enabledProfiles {
		if _, exists := outputConfigs[profileName]; exists {
			s.logger.Debug("Found config for API output profile '%s'", profileName)
		} else {
			s.logger.Error("API output profile '%s' not found in config", profileName)
		}
	}

	// Initialize output manager with only the profiles the API needs
	err := output.InitializeOutputManagerWithProfiles(outputConfigs, enabledProfiles)
	if err != nil {
		s.logger.Error("Failed to initialize API output manager: %v", err)
		return err
	}

	// Store reference to the API server's output manager
	s.outputManager = output.GetOutputManager()
	s.logger.Debug("Successfully initialized API output manager")
	return nil
}

// syncNonRemoteOutputs syncs only non-remote outputs to prevent infinite loops
func (s *APIServer) syncNonRemoteOutputs(outputManager *output.OutputManager) error {
	s.logger.Debug("API server syncing non-remote outputs only to prevent loops")

	// For now, just skip sync entirely for API aggregation to prevent loops
	// The zone files and other file outputs will be synced by the normal input providers
	s.logger.Debug("Skipping sync for API aggregation to prevent infinite loops with remote outputs")
	return nil
}

// StartAPIServerInstance starts the DNS API server using a provided APIServer instance
func StartAPIServerInstance(server *APIServer, apiConfig *config.APIConfig) error {
	if !apiConfig.Enabled {
		return nil
	}

	// Get output profiles from global config
	globalConfig := config.GetGlobalConfig()
	if globalConfig == nil {
		return fmt.Errorf("no global configuration available for output profiles")
	}

	// Load client profiles from config with file support
	if len(apiConfig.Profiles) > 0 {
		resolvedProfiles := make(map[string]config.APIClientProfile)

		for clientID, profile := range apiConfig.Profiles {
			// Use utils function for reading file:// and env:// values
			token := util.ReadSecretValue(profile.Token)

			if token == "" {
				return fmt.Errorf("client '%s' has empty token", clientID)
			}
			// Store the resolved token
			resolvedProfiles[clientID] = config.APIClientProfile{
				Token:         token,
				OutputProfile: profile.OutputProfile,
			}

			server.logger.Debug("Registered client profile: %s -> %s (token: %s)", clientID, profile.OutputProfile, util.MaskSensitiveValue(token))
		}

		server.LoadClientProfiles(resolvedProfiles)

		// Initialize API server's output manager after loading client profiles
		if err := server.initializeAPIOutputProfiles(globalConfig.Outputs); err != nil {
			return fmt.Errorf("failed to initialize API output profiles: %w", err)
		}
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

	// Validate listen patterns before proceeding
	if len(apiConfig.Listen) > 0 {
		if err := util.ValidateListenPatterns(apiConfig.Listen); err != nil {
			return fmt.Errorf("invalid listen patterns: %w", err)
		}
	}

	// Resolve listen addresses based on patterns
	var resolvedAddresses []string
	for _, pattern := range apiConfig.Listen {
		if strings.Contains(pattern, ":") {
			// Address already contains port, use as-is
			resolvedAddresses = append(resolvedAddresses, pattern)
		} else {
			// Pattern needs port resolution
			addresses, err := util.ResolveListenAddressesQuiet([]string{pattern}, port)
			if err != nil {
				server.logger.Warn("Interface resolution warning for '%s': %v", pattern, err)
			} else {
				resolvedAddresses = append(resolvedAddresses, addresses...)
			}
		}
	}

	if len(resolvedAddresses) == 0 {
		resolvedAddresses = []string{fmt.Sprintf(":%s", port)}
	}

	for _, addr := range resolvedAddresses {
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
		for _, address := range resolvedAddresses {
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
		for _, address := range resolvedAddresses {
			addr := address // capture for closure
			serverFunc := func() error {
				server.logger.Verbose("Starting HTTP server on %s", addr)
				return http.ListenAndServe(addr, nil)
			}
			serverFuncs = append(serverFuncs, serverFunc)
		}
	}

	for i, serverFunc := range serverFuncs {
		go func(index int, fn func() error) {
			if err := fn(); err != nil {
				server.logger.Error("Server %d error: %v", index, err)
			}
		}(i, serverFunc)
	}

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

// Deprecated: use StartAPIServerInstance instead
func StartAPIServer(apiConfig *config.APIConfig) error {
	globalConfig := config.GetGlobalConfig()
	if globalConfig == nil {
		return fmt.Errorf("no global configuration available for output profiles")
	}
	server := NewAPIServer(globalConfig.Outputs, apiConfig)
	return StartAPIServerInstance(server, apiConfig)
}

// AggregationDNSRecord is a minimal struct for aggregation from input providers
// (You may want to use your existing DNSEntry type instead)
type AggregationDNSRecord struct {
	Domain     string
	Hostname   string
	RecordType string
	Target     string
	TTL        int
}

// TriggerAggregation triggers aggregation and write from outside the API server
func (s *APIServer) TriggerAggregation(reason string) {
	go s.aggregateAndWrite(reason)
}
