// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package docker

import (
	"context"
	"fmt"
	"herald/pkg/log"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	dfilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// SharedConnection represents a shared Docker client connection
type SharedConnection struct {
	client      *client.Client
	apiURL      string
	subscribers map[string]*DockerProvider // providers sharing this connection
	eventChan   chan events.Message
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
	mutex       sync.RWMutex
	logPrefix   string
}

// ConnectionManager manages shared Docker connections
type ConnectionManager struct {
	connections map[string]*SharedConnection // keyed by API URL + auth hash
	mutex       sync.RWMutex
}

var (
	globalConnectionManager *ConnectionManager
	connectionManagerOnce   sync.Once
)

// GetConnectionManager returns the global connection manager singleton
func GetConnectionManager() *ConnectionManager {
	connectionManagerOnce.Do(func() {
		globalConnectionManager = &ConnectionManager{
			connections: make(map[string]*SharedConnection),
		}
	})
	return globalConnectionManager
}

// getConnectionKey creates a unique key for connection sharing based on API URL and auth
func (cm *ConnectionManager) getConnectionKey(apiURL, authUser, authPass string) string {
	// Include auth in key so different auth configs don't share connections
	return fmt.Sprintf("%s|%s|%s", apiURL, authUser, authPass)
}

// GetOrCreateConnection gets an existing shared connection or creates a new one
func (cm *ConnectionManager) GetOrCreateConnection(provider *DockerProvider) (*SharedConnection, error) {
	connKey := cm.getConnectionKey(provider.config.APIURL, provider.config.APIAuthUser, provider.config.APIAuthPass)

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Check if connection already exists
	if conn, exists := cm.connections[connKey]; exists {
		log.Debug("[docker/connection-manager] Reusing existing connection for %s (key: %s)", provider.profileName, connKey)

		// Add this provider as a subscriber
		conn.mutex.Lock()
		conn.subscribers[provider.profileName] = provider
		subscriberCount := len(conn.subscribers)
		conn.mutex.Unlock()

		log.Info("[docker/connection-manager] Provider '%s' joined shared connection to %s (%d total subscribers)",
			provider.profileName, provider.config.APIURL, subscriberCount)

		return conn, nil
	}

	// Create new shared connection
	log.Debug("[docker/connection-manager] Creating new shared connection for %s (key: %s)", provider.profileName, connKey)

	ctx, cancel := context.WithCancel(context.Background())

	conn := &SharedConnection{
		client:      provider.client, // Use the provider's already-configured client
		apiURL:      provider.config.APIURL,
		subscribers: make(map[string]*DockerProvider),
		eventChan:   make(chan events.Message, 100), // Buffered channel for events
		ctx:         ctx,
		cancel:      cancel,
		logPrefix:   fmt.Sprintf("[docker/connection-manager/%s]", provider.config.APIURL),
	}

	// Add the initial provider as a subscriber
	conn.subscribers[provider.profileName] = provider

	// Store the connection
	cm.connections[connKey] = conn

	log.Info("[docker/connection-manager] Created shared connection to %s with initial subscriber '%s'",
		provider.config.APIURL, provider.profileName)

	return conn, nil
}

// RemoveProvider removes a provider from a shared connection
func (cm *ConnectionManager) RemoveProvider(provider *DockerProvider) {
	connKey := cm.getConnectionKey(provider.config.APIURL, provider.config.APIAuthUser, provider.config.APIAuthPass)

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	conn, exists := cm.connections[connKey]
	if !exists {
		return
	}

	conn.mutex.Lock()
	delete(conn.subscribers, provider.profileName)
	subscriberCount := len(conn.subscribers)
	conn.mutex.Unlock()

	log.Debug("[docker/connection-manager] Provider '%s' left shared connection to %s (%d remaining subscribers)",
		provider.profileName, provider.config.APIURL, subscriberCount)

	// If no more subscribers, clean up the connection
	if subscriberCount == 0 {
		log.Debug("[docker/connection-manager] No more subscribers, cleaning up shared connection to %s", provider.config.APIURL)
		conn.Stop()
		delete(cm.connections, connKey)
	}
}

// StartEventStreaming starts the event streaming for this shared connection
func (sc *SharedConnection) StartEventStreaming() error {
	if sc.running {
		return nil
	}

	sc.running = true

	// Set up filters for events
	f := dfilters.NewArgs()
	f.Add("type", "container")
	f.Add("event", "start")
	f.Add("event", "stop")
	f.Add("event", "die")

	// Check if any subscriber needs swarm mode
	needsSwarm := false
	sc.mutex.RLock()
	for _, provider := range sc.subscribers {
		if provider.swarmMode {
			needsSwarm = true
			break
		}
	}
	sc.mutex.RUnlock()

	if needsSwarm {
		f.Add("type", "service")
		f.Add("event", "create")
		f.Add("event", "update")
		f.Add("event", "remove")
		log.Debug("%s Added service events to filter (swarm mode needed)", sc.logPrefix)
	}

	// Get event stream
	eventChan, errChan := sc.client.Events(sc.ctx, types.EventsOptions{
		Filters: f,
	})

	log.Info("%s Started shared event streaming", sc.logPrefix)

	// Start goroutine to distribute events to subscribers
	go func() {
		for {
			select {
			case <-sc.ctx.Done():
				log.Debug("%s Event streaming stopped (context cancelled)", sc.logPrefix)
				return

			case err := <-errChan:
				if err != nil {
					log.Error("%s Docker event stream error: %v", sc.logPrefix, err)
					// Log error for all subscribers - they'll handle reconnection in their own polling loops
					sc.mutex.RLock()
					for profileName := range sc.subscribers {
						log.Error("%s Event stream error affects subscriber '%s'", sc.logPrefix, profileName)
					}
					sc.mutex.RUnlock()
				}
				return

			case event := <-eventChan:
				// Distribute event to all subscribers
				sc.distributeEvent(event)
			}
		}
	}()

	return nil
}

// distributeEvent sends an event to all subscribers, which then filter it themselves.
func (sc *SharedConnection) distributeEvent(event events.Message) {
	sc.mutex.RLock()
	// Create a snapshot of subscribers to avoid holding the lock during event processing
	subscribers := make([]*DockerProvider, 0, len(sc.subscribers))
	for _, provider := range sc.subscribers {
		subscribers = append(subscribers, provider)
	}
	sc.mutex.RUnlock()

	containerName := event.Actor.Attributes["name"]
	containerName = strings.TrimPrefix(containerName, "/")

	// Log the event once at the connection level
	log.Verbose("[docker/shared] Container event: '%s' - name: '%s' - id: '%s'",
		event.Action, containerName, event.Actor.ID[:12])

	// Distribute the event to all subscribers. Each provider is responsible for its own filtering.
	for _, provider := range subscribers {
		go func(p *DockerProvider) {
			ctx := context.Background()
			if event.Type == "container" {
				// Use the filtered handler, which will decide if the event is relevant
				p.handleContainerEventFiltered(ctx, event)
			} else if event.Type == "service" && p.swarmMode {
				// For services, only swarm-enabled providers should process
				p.handleServiceEventFiltered(ctx, event)
			}
		}(provider)
	}
}

// Stop stops the shared connection
func (sc *SharedConnection) Stop() {
	if !sc.running {
		return
	}

	log.Debug("%s Stopping shared connection", sc.logPrefix)
	sc.running = false
	sc.cancel()
}

// GetSubscriberCount returns the number of subscribers to this connection
func (sc *SharedConnection) GetSubscriberCount() int {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	return len(sc.subscribers)
}
