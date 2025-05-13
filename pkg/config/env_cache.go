package config

import (
	"os"
	"sync"
)

var (
	// envCacheLock protects the environment variable cache
	envCacheLock sync.RWMutex

	// EnvCache is a cache of environment variables
	EnvCache = make(map[string]string)
)

// CacheEnvVar adds or updates a value in the environment variable cache
func CacheEnvVar(key, value string) {
	envCacheLock.Lock()
	defer envCacheLock.Unlock()
	EnvCache[key] = value
}

// GetCachedEnvVar retrieves a value from the cache, or if not present,
// reads it from the environment and adds it to the cache
func GetCachedEnvVar(key, defaultValue string) string {
	// First try to get from cache
	envCacheLock.RLock()
	value, exists := EnvCache[key]
	envCacheLock.RUnlock()

	if exists {
		return value
	}

	// If not in cache, get from environment
	value = os.Getenv(key)
	if value == "" {
		value = defaultValue
	}

	// Cache the value for future use
	CacheEnvVar(key, value)

	return value
}

// ClearEnvCache empties the environment variable cache
func ClearEnvCache() {
	envCacheLock.Lock()
	defer envCacheLock.Unlock()
	EnvCache = make(map[string]string)
}
