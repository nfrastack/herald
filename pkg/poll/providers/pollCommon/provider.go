// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"dns-companion/pkg/log"

	"context"
	"time"
)

// ProviderOptions contains common configuration options for all providers
type ProviderOptions struct {
	Name               string
	Interval           time.Duration
	ProcessExisting    bool
	RecordRemoveOnStop bool
	LogLevel           string
	FilterConfig       FilterConfig
	TLS                TLSConfig
}

// ParseProviderOptions parses common provider options from a map
func ParseProviderOptions(options map[string]string, defaults PollProviderOptions) ProviderOptions {
	parsed := ParsePollProviderOptions(options, defaults)

	// Parse filter configuration
	filterConfig, err := NewFilterFromOptions(options)
	if err != nil {
		log.Warn("Failed to parse filter configuration: %v", err)
		filterConfig = DefaultFilterConfig()
	}

	// Parse TLS configuration
	tlsConfig := ParseTLSConfigFromOptions(options)

	return ProviderOptions{
		Name:               parsed.Name,
		Interval:           parsed.Interval,
		ProcessExisting:    parsed.ProcessExisting,
		RecordRemoveOnStop: parsed.RecordRemoveOnStop,
		LogLevel:           options["log_level"],
		FilterConfig:       filterConfig,
		TLS:                tlsConfig,
	}
}

// BaseProvider provides common functionality for all poll providers
type BaseProvider struct {
	name               string
	interval           time.Duration
	processExisting    bool
	recordRemoveOnStop bool
	filterConfig       FilterConfig
	tlsConfig          TLSConfig
	ctx                context.Context
	cancel             context.CancelFunc
	running            bool
	logPrefix          string
	logger             *log.ScopedLogger
	lastKnownRecords   map[string]string // hostname:recordType -> target
}

// NewBaseProvider creates a new base provider with common functionality
func NewBaseProvider(providerType string, options ProviderOptions) *BaseProvider {
	ctx, cancel := context.WithCancel(context.Background())

	logPrefix := BuildLogPrefix(providerType, options.Name)
	logger := log.NewScopedLogger(logPrefix, options.LogLevel)

	if options.LogLevel != "" {
		logger.Info("Provider log_level set to: '%s'", options.LogLevel)
	}

	return &BaseProvider{
		name:               options.Name,
		interval:           options.Interval,
		processExisting:    options.ProcessExisting,
		recordRemoveOnStop: options.RecordRemoveOnStop,
		filterConfig:       options.FilterConfig,
		tlsConfig:          options.TLS,
		ctx:                ctx,
		cancel:             cancel,
		logPrefix:          logPrefix,
		logger:             logger,
		lastKnownRecords:   make(map[string]string),
	}
}

// Common provider methods
func (bp *BaseProvider) GetContext() context.Context  { return bp.ctx }
func (bp *BaseProvider) GetLogger() *log.ScopedLogger { return bp.logger }
func (bp *BaseProvider) GetLogPrefix() string         { return bp.logPrefix }
func (bp *BaseProvider) IsRunning() bool              { return bp.running }
func (bp *BaseProvider) SetRunning(running bool)      { bp.running = running }
func (bp *BaseProvider) GetTLSConfig() TLSConfig      { return bp.tlsConfig }

func (bp *BaseProvider) StopPolling() error {
	bp.running = false
	bp.cancel()
	return nil
}
