// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package docker

import (
	"context"
	"fmt"
	"github.com/nfrastack/herald/internal/log"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/events"
	dfilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

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

type ConnectionManager struct {
	connections map[string]*SharedConnection // keyed by API URL + auth hash
	mutex       sync.RWMutex
}

var (
	globalConnectionManager *ConnectionManager
	connectionManagerOnce   sync.Once
)

func GetConnectionManager() *ConnectionManager {
	connectionManagerOnce.Do(func() {
		globalConnectionManager = &ConnectionManager{
			connections: make(map[string]*SharedConnection),
		}
	})
	return globalConnectionManager
}

func (cm *ConnectionManager) getConnectionKey(apiURL, authUser, authPass string) string {
	return fmt.Sprintf("%s|%s|%s", apiURL, authUser, authPass)
}

func (cm *ConnectionManager) GetOrCreateConnection(provider *DockerProvider) (*SharedConnection, error) {
	connKey := cm.getConnectionKey(provider.config.APIURL, provider.config.APIAuthUser, provider.config.APIAuthPass)

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if conn, exists := cm.connections[connKey]; exists {
		log.NewScopedLogger("", "").With("action", "provider.init", "component", "docker/connection-manager", "provider", provider.profileName).Debug("existing connection (key: %s)", connKey)

		conn.mutex.Lock()
		conn.subscribers[provider.profileName] = provider
		subscriberCount := len(conn.subscribers)
		conn.mutex.Unlock()

		log.NewScopedLogger("", "").With("action", "provider.init", "component", "docker/connection-manager", "provider", provider.profileName).Info("shared connection to %s (%d total subscribers)", provider.config.APIURL, subscriberCount)

		return conn, nil
	}

	log.NewScopedLogger("", "").With("action", "provider.init", "component", "docker/connection-manager", "provider", provider.profileName).Debug("new shared connection (key: %s)", connKey)

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

	conn.subscribers[provider.profileName] = provider

	cm.connections[connKey] = conn

	log.NewScopedLogger("", "").With("action", "provider.init", "component", "docker/connection-manager", "provider", provider.profileName).Info("shared connection to %s", provider.config.APIURL)

	return conn, nil
}

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

	log.NewScopedLogger("", "").With("action", "provider.shutdown", "component", "docker/connection-manager", "provider", provider.profileName).Debug("shared connection to %s (%d remaining subscribers)", provider.config.APIURL, subscriberCount)

	if subscriberCount == 0 {
		log.NewScopedLogger("", "").With("action", "provider.shutdown", "component", "docker/connection-manager").Debug("no more subscribers, cleaning up shared connection to %s", provider.config.APIURL)
		conn.Stop()
		delete(cm.connections, connKey)
	}
}

func (sc *SharedConnection) StartEventStreaming() error {
	if sc.running {
		return nil
	}

	sc.running = true

	f := dfilters.NewArgs()
	f.Add("type", "container")
	f.Add("event", "start")
	f.Add("event", "stop")
	f.Add("event", "die")

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
		log.NewScopedLogger("", "").With("action", "sync.start").Debug("added service events to filter (swarm mode needed)")
	}

	eventChan, errChan := sc.client.Events(sc.ctx, events.ListOptions{
		Filters: f,
	})

	log.NewScopedLogger("", "").With("action", "sync.start").Info("shared event streaming started")

	go func() {
		for {
			select {
			case <-sc.ctx.Done():
				log.NewScopedLogger("", "").With("action", "provider.shutdown").Debug("event streaming stopped (context cancelled)")
				return

			case err := <-errChan:
				if err != nil {
					log.NewScopedLogger("", "").With("action", "provider.reconnect", "component", "docker/shared").Error("event stream error: %v", err)
					sc.mutex.RLock()
					for profileName := range sc.subscribers {
						log.NewScopedLogger("", "").With("action", "provider.reconnect", "component", "docker/shared").Error("stream error affects subscriber '%s'", profileName)
					}
					sc.mutex.RUnlock()
				}
				return

			case event := <-eventChan:
				sc.distributeEvent(event)
			}
		}
	}()

	return nil
}

func (sc *SharedConnection) distributeEvent(event events.Message) {
	sc.mutex.RLock()
	subscribers := make([]*DockerProvider, 0, len(sc.subscribers))
	for _, provider := range sc.subscribers {
		subscribers = append(subscribers, provider)
	}
	sc.mutex.RUnlock()

	containerName := event.Actor.Attributes["name"]
	containerName = strings.TrimPrefix(containerName, "/")

	log.NewScopedLogger("", "").With("action", "provider.event", "component", "docker/shared", "container", containerName, "id", event.Actor.ID[:12]).Verbose("event: '%s'", event.Action)

	for _, provider := range subscribers {
		go func(p *DockerProvider) {
			ctx := context.Background()
			if event.Type == "container" {
				p.handleContainerEventFiltered(ctx, event)
			} else if event.Type == "service" && p.swarmMode {
				p.handleServiceEventFiltered(ctx, event)
			}
		}(provider)
	}
}

func (sc *SharedConnection) Stop() {
	if !sc.running {
		return
	}

	log.NewScopedLogger("", "").With("action", "provider.shutdown").Debug("shared connection stopping")
	sc.running = false
	sc.cancel()
}

func (sc *SharedConnection) GetSubscriberCount() int {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	return len(sc.subscribers)
}
