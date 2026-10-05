// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Log levels
const (
	LevelTrace   = "trace"
	LevelDebug   = "debug"
	LevelVerbose = "verbose"
	LevelInfo    = "info"
	LevelWarn    = "warn"
	LevelError   = "error"
)

const (
	slogTrace   = slog.Level(-8)
	slogDebug   = slog.LevelDebug
	slogVerbose = slog.Level(-2)
	slogInfo    = slog.LevelInfo
	slogWarn    = slog.LevelWarn
	slogError   = slog.LevelError
)

// LogLevel represents the log level as an enum-like type
type LogLevel int

const (
	LogLevelError   LogLevel = iota // 0 - Least verbose (only errors)
	LogLevelWarn                    // 1
	LogLevelInfo                    // 2
	LogLevelVerbose                 // 3
	LogLevelDebug                   // 4
	LogLevelTrace                   // 5 - Most verbose (everything)
	LogLevelNone                    // 6 - For invalid levels
)

// ParseLogLevel converts a string to LogLevel
func ParseLogLevel(levelStr string) LogLevel {
	switch strings.ToLower(levelStr) {
	case LevelError:
		return LogLevelError
	case LevelWarn:
		return LogLevelWarn
	case LevelInfo:
		return LogLevelInfo
	case LevelVerbose:
		return LogLevelVerbose
	case LevelDebug:
		return LogLevelDebug
	case LevelTrace:
		return LogLevelTrace
	default:
		return LogLevelNone
	}
}

func toSlogLevel(level LogLevel) slog.Level {
	switch level {
	case LogLevelError:
		return slogError
	case LogLevelWarn:
		return slogWarn
	case LogLevelInfo:
		return slogInfo
	case LogLevelVerbose:
		return slogVerbose
	case LogLevelDebug:
		return slogDebug
	case LogLevelTrace:
		return slogTrace
	default:
		return slogVerbose
	}
}

// ScopedLogger provides provider-specific logging with optional level override
type ScopedLogger struct {
	prefix string
	level  *slog.LevelVar
	logger *slog.Logger
}

var globalLevel = new(slog.LevelVar)

// NewScopedLogger creates a new scoped logger with an optional log level override
func NewScopedLogger(prefix, logLevel string) *ScopedLogger {
	if logLevel == "" {
		return &ScopedLogger{prefix: prefix, level: globalLevel, logger: scopeLogger(prefix, globalLevel)}
	}
	parsed := ParseLogLevel(logLevel)
	if parsed == LogLevelNone {
		return &ScopedLogger{prefix: prefix, level: globalLevel, logger: scopeLogger(prefix, globalLevel)}
	}
	own := new(slog.LevelVar)
	own.Set(toSlogLevel(parsed))
	return &ScopedLogger{prefix: prefix, level: own, logger: scopeLogger(prefix, own)}
}

func scopeLogger(prefix string, level *slog.LevelVar) *slog.Logger {
	logger := GetLogger().slogLogger()
	if prefix != "" {
		return logger.With("scope", prefix)
	}
	return logger
}

// With returns a child logger carrying structured fields.
func (sl *ScopedLogger) With(keyvals ...interface{}) *ScopedLogger {
	if sl == nil {
		return NewScopedLogger("", "")
	}
	return &ScopedLogger{prefix: sl.prefix, level: sl.level, logger: sl.logger.With(keyvals...)}
}

func (sl *ScopedLogger) log(level slog.Level, format string, args ...interface{}) {
	if sl == nil {
		return
	}
	if !sl.logger.Enabled(context.Background(), level) {
		return
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	sl.logger.Log(context.Background(), level, msg)
}

// Debug logs a debug message through the scoped logger
func (sl *ScopedLogger) Debug(format string, args ...interface{}) {
	sl.log(slogDebug, format, args...)
}

// Trace logs a trace message through the scoped logger
func (sl *ScopedLogger) Trace(format string, args ...interface{}) {
	sl.log(slogTrace, format, args...)
}

// Verbose logs a verbose message through the scoped logger
func (sl *ScopedLogger) Verbose(format string, args ...interface{}) {
	sl.log(slogVerbose, format, args...)
}

// Info logs an info message through the scoped logger
func (sl *ScopedLogger) Info(format string, args ...interface{}) {
	sl.log(slogInfo, format, args...)
}

// Warn logs a warning message through the scoped logger
func (sl *ScopedLogger) Warn(format string, args ...interface{}) {
	sl.log(slogWarn, format, args...)
}

// Error logs an error message through the scoped logger
func (sl *ScopedLogger) Error(format string, args ...interface{}) {
	sl.log(slogError, format, args...)
}

// shouldLog checks if a message should be logged based on the scoped logger's level
func (sl *ScopedLogger) shouldLog(messageLevel LogLevel) bool {
	if sl == nil {
		return false
	}
	return sl.logger.Enabled(context.Background(), toSlogLevel(messageLevel))
}

// splitHandler routes records below Error to stdout and errors to stderr, preserving the historical stream split. An optional file receives both.
type splitHandler struct {
	out     slog.Handler
	err     slog.Handler
	minErr  slog.Level
	logFile string
}

func (h *splitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.out.Enabled(ctx, level) || h.err.Enabled(ctx, level)
}

func (h *splitHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= h.minErr {
		return h.err.Handle(ctx, record)
	}
	return h.out.Handle(ctx, record)
}

func (h *splitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &splitHandler{out: h.out.WithAttrs(attrs), err: h.err.WithAttrs(attrs), minErr: h.minErr}
}

func (h *splitHandler) WithGroup(name string) slog.Handler {
	return &splitHandler{out: h.out.WithGroup(name), err: h.err.WithGroup(name), minErr: h.minErr}
}

// Logger provides logging functionality for the application
type Logger struct {
	mu             sync.Mutex
	level          string
	showTimestamps bool
	format         string
	handler        *splitHandler
	logger         *slog.Logger
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Initialize creates the default logger with the specified level and timestamp visibility
func Initialize(level string, showTimestamps bool) {
	once.Do(func() {
		defaultLogger = NewLogger(level, showTimestamps)
		globalLevel.Set(toSlogLevel(ParseLogLevel(orDefault(level, LevelVerbose))))
	})
}

func orDefault(level, fallback string) string {
	if level == "" {
		return fallback
	}
	return level
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger(os.Getenv("LOG_LEVEL"), true)
		globalLevel.Set(toSlogLevel(ParseLogLevel(orDefault(os.Getenv("LOG_LEVEL"), LevelVerbose))))
	})
	return defaultLogger
}

func (l *Logger) slogLogger() *slog.Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logger
}

// NewLogger creates a new logger with the specified level and timestamp visibility
func NewLogger(level string, showTimestamps bool) *Logger {
	parsed := ParseLogLevel(level)
	if parsed == LogLevelNone {
		parsed = LogLevelVerbose
	}
	format := strings.ToLower(os.Getenv("LOG_FORMAT"))
	if format != "json" {
		format = "text"
	}

	out, errOut := io.Writer(os.Stdout), io.Writer(os.Stderr)
	if logFile := os.Getenv("LOG_FILE"); logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err == nil {
			if file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				out = io.MultiWriter(os.Stdout, file)
				errOut = io.MultiWriter(os.Stderr, file)
			}
		}
	}

	newHandler := func(w io.Writer) slog.Handler {
		opts := &slog.HandlerOptions{Level: globalLevel, AddSource: false}
		if !showTimestamps {
			opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey && len(groups) == 0 {
					return slog.Attr{}
				}
				return a
			}
		}
		if format == "json" {
			return slog.NewJSONHandler(w, opts)
		}
		return slog.NewTextHandler(w, opts)
	}
	handler := &splitHandler{out: newHandler(out), err: newHandler(errOut), minErr: slogError}
	return &Logger{
		level:          level,
		showTimestamps: showTimestamps,
		format:         format,
		handler:        handler,
		logger:         slog.New(handler),
	}
}

// SetLevel sets the logger level
func (l *Logger) SetLevel(level string) {
	parsed := ParseLogLevel(level)
	if parsed == LogLevelNone {
		parsed = LogLevelVerbose
	}
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
	globalLevel.Set(toSlogLevel(parsed))
}

// GetLevel returns the current logger level
func (l *Logger) GetLevel() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetShowTimestamps sets the visibility of timestamps in log messages
func (l *Logger) SetShowTimestamps(show bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.showTimestamps = show
}

// SetFormat switches output between text and json. Unknown values keep text.
func (l *Logger) SetFormat(format string) {
	format = strings.ToLower(format)
	if format != "json" {
		format = "text"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.format = format
}

// Debug logs a debug message with optional formatting
func (l *Logger) Debug(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogDebug, sprintf(format, args...))
}

// Verbose logs a verbose message with optional formatting
func (l *Logger) Verbose(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogVerbose, sprintf(format, args...))
}

// Info logs an info message with optional formatting
func (l *Logger) Info(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogInfo, sprintf(format, args...))
}

// Warn logs a warning message with optional formatting
func (l *Logger) Warn(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogWarn, sprintf(format, args...))
}

// Error logs an error message with optional formatting
func (l *Logger) Error(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogError, sprintf(format, args...))
}

// Fatal logs an error message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogError, sprintf(format, args...))
	os.Exit(1)
}

// Trace logs a trace message with optional formatting
func (l *Logger) Trace(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogTrace, sprintf(format, args...))
}

// TraceFunction logs function entry and exit with timing
func (l *Logger) TraceFunction(funcName string) func() {
	start := time.Now()
	l.Trace("ENTER: %s", funcName)

	return func() {
		l.Trace("EXIT: %s (took %v)", funcName, time.Since(start))
	}
}

func sprintf(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

// GetTimestampsEnabled returns whether timestamps are enabled for logging
func GetTimestampsEnabled() bool {
	return GetLogger().showTimestamps
}

// Helper functions that use the default logger

// Debug logs a debug message with the default logger
func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

// Verbose logs a verbose message with the default logger
func Verbose(format string, args ...interface{}) {
	GetLogger().Verbose(format, args...)
}

// Info logs an info message with the default logger
func Info(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

// Warn logs a warning message with the default logger
func Warn(format string, args ...interface{}) {
	GetLogger().Warn(format, args...)
}

// Error logs an error message with the default logger
func Error(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

// Fatal logs an error message with the default logger and exits
func Fatal(format string, args ...interface{}) {
	GetLogger().Fatal(format, args...)
}

// Trace logs a trace message with the default logger
func Trace(format string, args ...interface{}) {
	GetLogger().Trace(format, args...)
}

// DumpState logs the current state of an object for debugging
func DumpState(prefix string, obj interface{}) {
	details := fmt.Sprintf("%+v", obj)
	if len(details) > 1000 {
		details = details[:1000] + "... [truncated]"
	}

	lines := strings.Split(details, "\n")
	for i, line := range lines {
		if i == 0 {
			GetLogger().Debug("%s: %s", prefix, line)
		} else {
			GetLogger().Debug("%s (cont'd): %s", prefix, line)
		}
	}
}

// TracePath logs the execution path with caller information
func TracePath(path string, args ...interface{}) {
	message := sprintf(path, args...)
	now := time.Now().Format("15:04:05.000")

	// Get caller information
	_, file, line, ok := runtime.Caller(1)
	callerInfo := "unknown"
	if ok {
		// Extract just the filename, not the full path
		for i := len(file) - 1; i >= 0; i-- {
			if file[i] == '/' {
				file = file[i+1:]
				break
			}
		}
		callerInfo = fmt.Sprintf("%s:%d", file, line)
	}

	GetLogger().Trace("[%s] [%s] PATH: %s", now, callerInfo, message)
}
