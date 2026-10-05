// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package api

import (
	"github.com/nfrastack/herald/internal/config"
	"github.com/nfrastack/herald/internal/log"
	"github.com/nfrastack/herald/internal/output"
	"github.com/nfrastack/herald/internal/state"
	"github.com/nfrastack/herald/internal/util"

	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ClientData represents data from a single client
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
	stopCleanup    chan struct{}                    // Closed on shutdown to stop the cleanup loop
	ownedMu        sync.RWMutex
	owned          map[string]string // domain:host:type -> owning clientID
}

// FailedAttemptTracker tracks failed authentication attempts from an IP
type FailedAttemptTracker struct {
	Count       int
	FirstFailed time.Time
	LastFailed  time.Time
}

// aggregateAndWriteWithRemovals combines all client data and writes to the specified output profile, processing explicit removals
func (s *APIServer) aggregateAndWriteWithRemovals(connID, uploadClientID string, removals map[string][][2]string) {
	s.mutex.Lock()
	aggLog := s.logger.With("conn", connID)
	aggLog.Trace("Starting data aggregation and write process")

	// Remove expired clients
	now := time.Now()
	expiredCount := 0
	for clientID, data := range s.clients {
		if now.Sub(data.Received) > s.clientExpiry {
			delete(s.clients, clientID)
			expiredCount++
			aggLog.With("client", clientID).Info("Removed expired client")
		}
	}
	if expiredCount > 0 {
		aggLog.Debug("Removed %d expired clients", expiredCount)
	}

	aggLog.Debug("Processing data from %d active clients", len(s.clients))

	// Snapshot client state
	type snapshotRecord struct {
		domain   string
		hostname string
		target   string
		rtype    string
		ttl      int
		source   string
		clientID string
	}
	snapshotsByProfile := make(map[string][]snapshotRecord)
	skippedByClient := make(map[string]map[string]int) // client -> domain -> count
	hostPatterns := make(map[string][]string)          // client -> hostname globs
	sharedWrites := make(map[string]bool)              // client -> may touch others' records
	for clientID, data := range s.clients {
		prof, exists := s.profiles[clientID]
		if !exists {
			continue
		}
		outputProfile := prof.OutputProfile
		if outputProfile == "" {
			outputProfile = "default"
		}
		hostPatterns[clientID] = prof.Hostnames
		sharedWrites[clientID] = prof.SharedWrites
		allowed := make(map[string]bool, len(prof.Domains))
		for _, d := range prof.Domains {
			allowed[d] = true
		}
		for domainName, domain := range data.Domains {
			if domain == nil {
				continue
			}
			if len(allowed) > 0 && !allowed[domainName] {
				if skippedByClient[clientID] == nil {
					skippedByClient[clientID] = make(map[string]int)
				}
				skippedByClient[clientID][domainName] += len(domain.Records)
				continue
			}
			for _, record := range domain.Records {
				if record == nil {
					continue
				}
				snapshotsByProfile[outputProfile] = append(snapshotsByProfile[outputProfile], snapshotRecord{
					domain:   domainName,
					hostname: record.Hostname,
					target:   record.Target,
					rtype:    record.Type,
					ttl:      int(record.TTL),
					source:   record.Source,
					clientID: clientID,
				})
			}
		}
	}
	removalsSnapshot := removals
	outputManager := s.outputManager
	s.mutex.Unlock()

	for clientID, domains := range skippedByClient {
		for domainName, n := range domains {
			s.logger.With("conn", connID, "client", clientID).Warn("Attempted %d record(s) for domain '%s' outside allowed list - rejected", n, domainName)
		}
	}

	// Aggregate data for each output profile separately
	for outputProfile, records := range snapshotsByProfile {
		if outputManager == nil {
			aggLog.Error("Output manager not available for profile '%s'", outputProfile)
			continue
		}
		profile := outputManager.GetProfile(outputProfile)
		if profile == nil {
			aggLog.Error("Output profile '%s' not found in configuration", outputProfile)
			continue
		}

		// --- Process explicit removals for this output profile ---
		// Scoped to the uploading client's allowlists (fail-closed when set)
		// and to records it owns.
		var uploadAllowed map[string]bool
		var uploadHosts []string
		var uploadShared bool
		s.mutex.RLock()
		if prof, exists := s.profiles[uploadClientID]; exists {
			if len(prof.Domains) > 0 {
				uploadAllowed = make(map[string]bool, len(prof.Domains))
				for _, d := range prof.Domains {
					uploadAllowed[d] = true
				}
			}
			uploadHosts = prof.Hostnames
			uploadShared = prof.SharedWrites
		}
		s.mutex.RUnlock()
		if removalsSnapshot != nil {
			for domain, recs := range removalsSnapshot {
				if uploadAllowed != nil && !uploadAllowed[domain] {
					s.logger.With("conn", connID, "client", uploadClientID).Warn("Attempted removal(s) for domain '%s' outside allowed list - rejected", domain)
					continue
				}
				for _, pair := range recs {
					hostname := pair[0]
					recordType := pair[1]
					if !hostAllowed(uploadHosts, hostname) {
						s.logger.With("conn", connID, "client", uploadClientID).Warn("Attempted removal of %s.%s outside hostname scope - rejected", hostname, domain)
						continue
					}
					if !uploadShared && s.ownedByOther(domain, hostname, recordType, uploadClientID) {
						s.logger.With("conn", connID, "client", uploadClientID).Warn("Attempted removal of %s.%s owned by another client - rejected", hostname, domain)
						continue
					}
					_ = profile.RemoveRecord(domain, hostname, recordType)
					state.Remove(domain, hostname, recordType)
					s.unown(domain, hostname, recordType)
				}
			}
		}

		var writeErrors []string
		var recordsWritten int
		// Track all records seen for this profile (domain, hostname, type) by all clients
		seenRecords := make(map[string]map[string]map[string]bool) // domain -> hostname -> type -> true
		for _, record := range records {
			domainName := record.domain
			if !hostAllowed(hostPatterns[record.clientID], record.hostname) {
				s.logger.With("conn", connID, "client", record.clientID).Warn("Attempted %s.%s outside hostname scope - rejected", record.hostname, domainName)
				continue
			}
			if !sharedWrites[record.clientID] && s.ownedByOther(domainName, record.hostname, record.rtype, record.clientID) {
				s.logger.With("conn", connID, "client", record.clientID).Warn("Attempted overwrite of %s.%s owned by another client - rejected", record.hostname, domainName)
				continue
			}
			if seenRecords[domainName] == nil {
				seenRecords[domainName] = make(map[string]map[string]bool)
			}
			if seenRecords[domainName][record.hostname] == nil {
				seenRecords[domainName][record.hostname] = make(map[string]bool)
			}
			seenRecords[domainName][record.hostname][record.rtype] = true
			// Preserve reporting client alongside original input source
			// so zone comments read e.g. "atlas/docker_int".
			source := record.source
			if record.clientID != "" {
				if source != "" {
					source = record.clientID + "/" + source
				} else {
					source = record.clientID
				}
			}
			// Add or update each record individually
			err := profile.WriteRecordWithSource(domainName, record.hostname, record.target, record.rtype, record.ttl, source)
			if err != nil {
				writeErrors = append(writeErrors, fmt.Sprintf("add %s.%s: %v", record.hostname, domainName, err))
				s.logger.With("conn", connID, "client", record.clientID).Error("Failed to add record %s.%s to profile '%s': %v", record.hostname, domainName, outputProfile, err)
				continue
			}
			recordsWritten++
			s.claim(domainName, record.hostname, record.rtype, record.clientID)
			state.Touch(domainName, record.hostname, record.rtype, record.target, record.source, record.clientID)
		}
		// To remove records, we need to know what is currently present in the output profile.
		// Since OutputFormat does not expose a method to list all records, we cannot do this generically.
		// For file-based outputs, removals are handled by not rewriting records that are not present in seenRecords.
		// For remote or other outputs, implementers should ensure removals are handled as needed.
		// Sync after all adds
		err := profile.Sync()
		if err != nil {
			writeErrors = append(writeErrors, fmt.Sprintf("sync: %v", err))
			aggLog.Error("Failed to sync profile '%s': %v", outputProfile, err)
		}
		if len(writeErrors) == 0 {
			aggLog.Verbose("Successfully wrote and synced %d records to profile '%s'", recordsWritten, outputProfile)
		} else {
			aggLog.Error("Failed to write data to output profile '%s': %d errors occurred", outputProfile, len(writeErrors))
		}
		aggLog.Debug("Completed aggregation for profile '%s'", outputProfile)
	}
}

type contextKey string

const connectionIDKey contextKey = "connectionID"

// authenticateClient validates client authentication
func (s *APIServer) authenticateClient(r *http.Request) (string, bool) {
	connID := getConnectionID(r)
	reqLog := s.logger.With("conn", connID)

	// Check if this IP is rate limited first
	if s.isRateLimited(r.RemoteAddr) {
		reqLog.Warn("SECURITY: Rate limited IP attempted connection: %s", r.RemoteAddr)
		return "", false
	}

	authHeader := r.Header.Get("Authorization")
	clientIDHeader := r.Header.Get("X-Client-ID")

	// Debug: log what headers we're receiving
	reqLog.Debug("Auth headers - Authorization: '%s', X-Client-ID: '%s'",
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
	reqLog = reqLog.With("client", clientID)

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

	if subtle.ConstantTimeCompare([]byte(profile.Token), []byte(token)) != 1 {
		s.recordFailedAttempt(r.RemoteAddr, clientID, "invalid token")
		return "", false
	}

	// Authentication successful - clear any failed attempts for this IP
	s.resetFailedAttempts(r.RemoteAddr)
	reqLog.Debug("Authentication successful from %s", r.RemoteAddr)
	return clientID, true
}

// claim records client ownership of a record. First writer keeps it;
// shared writers borrow without stealing.
func (s *APIServer) claim(domain, hostname, recordType, clientID string) {
	if clientID == "" {
		return
	}
	s.ownedMu.Lock()
	defer s.ownedMu.Unlock()
	if s.owned == nil {
		s.owned = make(map[string]string)
	}
	k := ownedKey(domain, hostname, recordType)
	if _, ok := s.owned[k]; !ok {
		s.owned[k] = clientID
	}
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

// clientIP extracts the host IP from a RemoteAddr
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	if host := strings.Trim(remoteAddr, "[]"); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			return host
		}
	}
	return remoteAddr
}

// connectionIDMiddleware adds a unique connection ID to each request
func connectionIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID := generateConnectionID()
		ctx := context.WithValue(r.Context(), connectionIDKey, connID)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

// expandSecretList resolves file:// and env:// references
func expandSecretList(values []string) []string {
	var out []string
	for _, v := range values {
		resolved := util.ReadSecretValue(v)
		for _, part := range strings.FieldsFunc(resolved, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// Generate a short connection ID (8 characters)
func generateConnectionID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// getConnectionID extracts the connection ID from request context
func getConnectionID(r *http.Request) string {
	if id, ok := r.Context().Value(connectionIDKey).(string); ok {
		return id
	}
	return "unknown"
}

// HandleDataUpload processes incoming DNS data from clients
func (s *APIServer) HandleDataUpload(w http.ResponseWriter, r *http.Request) {
	connID := getConnectionID(r)

	if r.Method != http.MethodPost {
		s.logger.With("conn", connID).Debug("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.logger.With("conn", connID).Verbose("New connection from %s", r.RemoteAddr)

	// Authenticate client
	clientID, authenticated := s.authenticateClient(r)
	if !authenticated {
		s.logger.With("conn", connID).Warn("Unauthorized request from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	reqLog := s.logger.With("conn", connID, "client", clientID)
	reqLog.Verbose("Processing upload")

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		reqLog.Error("Failed to read body: %v", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	reqLog.Debug("Received %d bytes", len(body))
	reqLog.Trace("Raw request body: %s", string(body))

	// Parse based on content type
	var clientData ClientData
	var remotePayload RemoteActionPayload
	var removalsFromPayload map[string][][2]string // domain -> list of [hostname, type]
	contentType := r.Header.Get("Content-Type")
	reqLog.Trace("Content-Type: %s", contentType)
	reqLog.Trace("Payload: %s", string(body))
	switch {
	default:
		// Try JSON first
		if err := json.Unmarshal(body, &clientData); err == nil {
			// Check for removals map in the raw JSON
			var raw map[string]interface{}
			if err := json.Unmarshal(body, &raw); err == nil {
				if removals, ok := raw["removals"].(map[string]interface{}); ok {
					removalsFromPayload = make(map[string][][2]string)
					for domain, recs := range removals {
						recList, ok := recs.([]interface{})
						if !ok {
							continue
						}
						for _, r := range recList {
							rec, ok := r.(map[string]interface{})
							if !ok {
								continue
							}
							hostname, _ := rec["hostname"].(string)
							recordType, _ := rec["type"].(string)
							if hostname != "" && recordType != "" {
								removalsFromPayload[domain] = append(removalsFromPayload[domain], [2]string{hostname, recordType})
							}
						}
					}
				}
			}
		} else if err := json.Unmarshal(body, &remotePayload); err == nil && remotePayload.Action == "remove" {
			// Remove records for each domain in remotePayload.Domains
			for domain, dom := range remotePayload.Domains {
				if clientData.Domains == nil {
					continue
				}
				domainObj, ok := clientData.Domains[domain]
				if !ok || domainObj == nil {
					continue
				}
				// Remove all records in dom.Records from domainObj.Records
				newRecords := make([]*Record, 0, len(domainObj.Records))
				for _, record := range domainObj.Records {
					shouldRemove := false
					for _, r := range dom.Records {
						if record.Hostname == r.Hostname && record.Type == r.Type {
							shouldRemove = true
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
	}

	// After parsing the payload and before storing clientData, process removals globally
	// (REMOVED: old code that referenced undefined 'profile' variable)

	// Store client data
	s.mutex.Lock()
	defer s.mutex.Unlock()

	clientData.ClientID = clientID
	clientData.Received = time.Now()
	// Only update the client's state if there are domains/records in the payload
	if len(clientData.Domains) > 0 {
		s.clients[clientID] = &clientData
	}

	reqLog.Info("Received data with %d domains", len(clientData.Domains))
	reqLog.Debug("Metadata generator=%s",
		func() string {
			if clientData.Metadata != nil {
				return clientData.Metadata.Generator
			} else {
				return "unknown"
			}
		}())

	// Log domain details at trace level
	for domainName, domain := range clientData.Domains {
		reqLog.Trace("Domain '%s': %d records", domainName, len(domain.Records))
	}

	// Trigger aggregation, passing removals
	go s.aggregateAndWriteWithRemovals(connID, clientID, removalsFromPayload)

	reqLog.Debug("Completed processing")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// hostAllowed reports whether hostname matches any glob pattern.
func hostAllowed(patterns []string, hostname string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, err := path.Match(p, hostname); err == nil && ok {
			return true
		}
	}
	return false
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

// isRateLimited checks if an IP should be rate limited based on failed attempts
func (s *APIServer) isRateLimited(remoteAddr string) bool {
	ip := clientIP(remoteAddr)

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
		stopCleanup:    make(chan struct{}),
	}
}

// ownedByOther reports whether a record is owned by a different client.
func (s *APIServer) ownedByOther(domain, hostname, recordType, clientID string) bool {
	s.ownedMu.RLock()
	defer s.ownedMu.RUnlock()
	if s.owned == nil {
		return false
	}
	owner, ok := s.owned[ownedKey(domain, hostname, recordType)]
	return ok && owner != "" && owner != clientID
}

// ownedKey identifies a record for ownership tracking.
func ownedKey(domain, hostname, recordType string) string {
	return domain + "\x00" + hostname + "\x00" + recordType
}

// recordFailedAttempt tracks a failed authentication attempt from an IP
func (s *APIServer) recordFailedAttempt(remoteAddr string, clientID string, reason string) {
	// Extract IP from remote address (IPv6-safe)
	ip := clientIP(remoteAddr)

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

// registerActiveServers records listeners and their cleanup stop channels.
func registerActiveServers(servers []*http.Server, stopCleanup chan struct{}) {
	activeServersMu.Lock()
	defer activeServersMu.Unlock()
	activeServers = append(activeServers, servers...)
	stopCleanups = append(stopCleanups, stopCleanup)
}

// resetFailedAttempts clears failed attempts for an IP (called on successful auth)
func (s *APIServer) resetFailedAttempts(remoteAddr string) {
	ip := clientIP(remoteAddr)

	s.attemptsMutex.Lock()
	defer s.attemptsMutex.Unlock()

	if tracker, exists := s.failedAttempts[ip]; exists && tracker.Count > 0 {
		s.logger.Debug("Clearing %d failed attempts for %s after successful auth", tracker.Count, ip)
		delete(s.failedAttempts, ip)
	}
}

// ShutdownAPIServers gracefully stops all API listeners and cleanup loops.
func ShutdownAPIServers(ctx context.Context) {
	activeServersMu.Lock()
	servers := activeServers
	activeServers = nil
	stops := stopCleanups
	stopCleanups = nil
	activeServersMu.Unlock()

	for _, stop := range stops {
		select {
		case <-stop:
		default:
			close(stop)
		}
	}
	for _, s := range servers {
		_ = s.Shutdown(ctx)
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
			// Use utils function for reading file:// and env:// values
			token := util.ReadSecretValue(profile.Token)

			if token == "" {
				return fmt.Errorf("client '%s' has empty token", clientID)
			}
			// Store the resolved token
			resolvedProfiles[clientID] = config.APIClientProfile{
				Token:         token,
				OutputProfile: profile.OutputProfile,
				Domains:       expandSecretList(profile.Domains),
				Hostnames:     expandSecretList(profile.Hostnames),
				SharedWrites:  profile.SharedWrites,
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

	// Set up HTTP handler on a local mux so repeated starts cannot collide and shutdown stays scoped
	endpoint := apiConfig.Endpoint
	if endpoint == "" {
		endpoint = "/api/dns"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(endpoint, connectionIDMiddleware(server.HandleDataUpload))

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
	var servers []*http.Server

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
			httpServer := &http.Server{
				Addr:      address,
				Handler:   mux,
				TLSConfig: tlsConfig,
			}
			servers = append(servers, httpServer)

			go func(s *http.Server, addr string) {
				server.logger.Debug("Starting HTTPS server on %s", addr)
				if err := s.ListenAndServeTLS(apiConfig.TLS.Cert, apiConfig.TLS.Key); err != nil && err != http.ErrServerClosed {
					server.logger.Error("HTTPS server on %s error: %v", addr, err)
				}
			}(httpServer, address)
		}
	} else {
		server.logger.Warn("WARNING: Running HTTP servers without TLS - use only on trusted networks!")
		for _, address := range resolvedAddresses {
			httpServer := &http.Server{
				Addr:    address,
				Handler: mux,
			}
			servers = append(servers, httpServer)

			go func(s *http.Server, addr string) {
				server.logger.Verbose("Starting HTTP server on %s", addr)
				if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					server.logger.Error("HTTP server on %s error: %v", addr, err)
				}
			}(httpServer, address)
		}
	}

	registerActiveServers(servers, server.stopCleanup)

	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				server.cleanupFailedAttempts()
			case <-server.stopCleanup:
				return
			}
		}
	}()

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

// activeServers tracks running API listeners for graceful shutdown.
var (
	activeServersMu sync.RWMutex
	activeServers   []*http.Server
	stopCleanups    []chan struct{}
)

// unown releases ownership of a record.
func (s *APIServer) unown(domain, hostname, recordType string) {
	s.ownedMu.Lock()
	defer s.ownedMu.Unlock()
	delete(s.owned, ownedKey(domain, hostname, recordType))
}

// VerifyZoneRecord checks if a DNS record exists in the zone file.
func VerifyZoneRecord(zoneFilePath, hostname, recordType, target string) (bool, error) {
	data, err := os.ReadFile(zoneFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to read zone file: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	pattern := fmt.Sprintf(`^\s*%s\s+\d+\s+IN\s+%s\s+%s`, regexp.QuoteMeta(hostname), regexp.QuoteMeta(recordType), regexp.QuoteMeta(target))
	re := regexp.MustCompile(pattern)
	for _, line := range lines {
		if re.MatchString(line) {
			return true, nil // Record exists
		}
	}
	return false, nil // Record not found
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
