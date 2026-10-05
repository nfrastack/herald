// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package log

import (
	"fmt"
	"io"
	"log"
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

var globalLogLevel LogLevel = LogLevelVerbose // Default global level

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

// ScopedLogger provides provider-specific logging with optional level override
type ScopedLogger struct {
	prefix     string
	level      LogLevel
	isOverride bool // Track if this logger has a level override
}

// NewScopedLogger creates a new scoped logger with an optional log level override
func NewScopedLogger(prefix, logLevel string) *ScopedLogger {
	var level LogLevel
	var isOverride bool

	if logLevel == "" {
		// If no specific log level provided, inherit the global log level
		level = globalLogLevel
		isOverride = false
	} else {
		level = ParseLogLevel(logLevel)
		if level == LogLevelNone {
			// If invalid level provided, fall back to global level
			level = globalLogLevel
			isOverride = false
		} else {
			isOverride = true
		}
	}

	return &ScopedLogger{
		prefix:     prefix,
		level:      level,
		isOverride: isOverride,
	}
}

// updateGlobalLogLevel updates the global log level and should be called when the main logger level changes
func updateGlobalLogLevel(levelStr string) {
	globalLogLevel = ParseLogLevel(levelStr)
	if globalLogLevel == LogLevelNone {
		globalLogLevel = LogLevelVerbose // Default fallback
	}
}

// shouldLog checks if a message should be logged based on the scoped logger's level
func (sl *ScopedLogger) shouldLog(messageLevel LogLevel) bool {
	// Higher numbers = more verbose, so we should log if messageLevel <= sl.level
	// LogLevelError(0) < LogLevelWarn(1) < LogLevelInfo(2) < LogLevelVerbose(3) < LogLevelDebug(4) < LogLevelTrace(5)
	return messageLevel <= sl.level
}

// Debug logs a debug message through the scoped logger
func (sl *ScopedLogger) Debug(format string, args ...interface{}) {
	if sl.shouldLog(LogLevelDebug) {
		// Use direct output instead of going through the global logger's level checking
		message := fmt.Sprintf(format, args...)
		levelStr := "   DEBUG"
		if sl.isOverride {
			levelStr = "  *DEBUG"
		}
		// Include the prefix in the message
		if sl.prefix != "" {
			message = fmt.Sprintf("%s %s", sl.prefix, message)
		}
		if GetLogger().showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s %s %s", timestamp, levelStr, message)
		} else {
			message = fmt.Sprintf("%s %s", levelStr, message)
		}
		GetLogger().debugLogger.Output(3, message)
	}
}

// Trace logs a trace message through the scoped logger
func (sl *ScopedLogger) Trace(format string, args ...interface{}) {
	if sl.shouldLog(LogLevelTrace) {
		// Use direct output instead of going through the global logger's level checking
		message := fmt.Sprintf(format, args...)
		levelStr := "   TRACE"
		if sl.isOverride {
			levelStr = "  *TRACE"
		}
		// Include the prefix in the message
		if sl.prefix != "" {
			message = fmt.Sprintf("%s %s", sl.prefix, message)
		}
		if GetLogger().showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s %s %s", timestamp, levelStr, message)
		} else {
			message = fmt.Sprintf("%s %s", levelStr, message)
		}
		GetLogger().debugLogger.Output(3, message)
	}
}

// Verbose logs a verbose message through the scoped logger
func (sl *ScopedLogger) Verbose(format string, args ...interface{}) {
	if sl.shouldLog(LogLevelVerbose) {
		message := fmt.Sprintf(format, args...)
		levelStr := " VERBOSE"
		if sl.isOverride {
			levelStr = "*VERBOSE"
		}
		// Include the prefix in the message
		if sl.prefix != "" {
			message = fmt.Sprintf("%s %s", sl.prefix, message)
		}
		if GetLogger().showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s %s %s", timestamp, levelStr, message)
		} else {
			message = fmt.Sprintf("%s %s", levelStr, message)
		}
		GetLogger().infoLogger.Output(3, message)
	}
}

// Info logs an info message through the scoped logger
func (sl *ScopedLogger) Info(format string, args ...interface{}) {
	if sl.shouldLog(LogLevelInfo) {
		message := fmt.Sprintf(format, args...)
		levelStr := "    INFO"
		if sl.isOverride {
			levelStr = "   *INFO"
		}
		// Include the prefix in the message
		if sl.prefix != "" {
			message = fmt.Sprintf("%s %s", sl.prefix, message)
		}
		if GetLogger().showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s %s %s", timestamp, levelStr, message)
		} else {
			message = fmt.Sprintf("%s %s", levelStr, message)
		}
		GetLogger().infoLogger.Output(3, message)
	}
}

// Warn logs a warning message through the scoped logger
func (sl *ScopedLogger) Warn(format string, args ...interface{}) {
	if sl.shouldLog(LogLevelWarn) {
		message := fmt.Sprintf(format, args...)
		levelStr := "    WARN"
		if sl.isOverride {
			levelStr = "   *WARN"
		}
		// Include the prefix in the message
		if sl.prefix != "" {
			message = fmt.Sprintf("%s %s", sl.prefix, message)
		}
		if GetLogger().showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s %s %s", timestamp, levelStr, message)
		} else {
			message = fmt.Sprintf("%s %s", levelStr, message)
		}
		GetLogger().warnLogger.Output(3, message)
	}
}

// Error logs an error message through the scoped logger
func (sl *ScopedLogger) Error(format string, args ...interface{}) {
	if sl.shouldLog(LogLevelError) {
		message := fmt.Sprintf(format, args...)
		levelStr := "   ERROR"
		if sl.isOverride {
			levelStr = "  *ERROR"
		}
		// Include the prefix in the message
		if sl.prefix != "" {
			message = fmt.Sprintf("%s %s", sl.prefix, message)
		}
		if GetLogger().showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s %s %s", timestamp, levelStr, message)
		} else {
			message = fmt.Sprintf("%s %s", levelStr, message)
		}
		GetLogger().errorLogger.Output(3, message)
	}
}

// Logger provides logging functionality for the application
type Logger struct {
	debugLogger    *log.Logger
	infoLogger     *log.Logger
	warnLogger     *log.Logger
	errorLogger    *log.Logger
	level          string
	mu             sync.Mutex
	showTimestamps bool
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Initialize creates the default logger with the specified level and timestamp visibility
func Initialize(level string, showTimestamps bool) {
	once.Do(func() {
		defaultLogger = NewLogger(level, showTimestamps)
		updateGlobalLogLevel(level)
	})
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	once.Do(func() {
		// Default to info if not initialized
		defaultLogger = NewLogger(os.Getenv("LOG_LEVEL"), true)
		updateGlobalLogLevel(os.Getenv("LOG_LEVEL"))
	})
	return defaultLogger
}

// NewLogger creates a new logger with the specified level and timestamp visibility
func NewLogger(level string, showTimestamps bool) *Logger {
	logger := &Logger{
		level:          LevelInfo,
		showTimestamps: showTimestamps,
	}
	logger.SetLevel(level)

	flags := 0 // Always use no standard flags to avoid double timestamps

	debugLogger := log.New(os.Stdout, "", flags)
	infoLogger := log.New(os.Stdout, "", flags)
	warnLogger := log.New(os.Stdout, "", flags)
	errorLogger := log.New(os.Stderr, "", flags)

	// Determine if log files should be used
	logFile := os.Getenv("LOG_FILE")
	if logFile != "" {
		// Create log directory if necessary
		logDir := filepath.Dir(logFile)
		if err := os.MkdirAll(logDir, 0755); err == nil {
			// Open log file
			file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				// Use MultiWriter to log to both console and file
				debugWriter := io.MultiWriter(os.Stdout, file)
				infoWriter := io.MultiWriter(os.Stdout, file)
				warnWriter := io.MultiWriter(os.Stdout, file)
				errorWriter := io.MultiWriter(os.Stderr, file)

				debugLogger.SetOutput(debugWriter)
				infoLogger.SetOutput(infoWriter)
				warnLogger.SetOutput(warnWriter)
				errorLogger.SetOutput(errorWriter)
			}
		}
	}

	return &Logger{
		debugLogger:    debugLogger,
		infoLogger:     infoLogger,
		warnLogger:     warnLogger,
		errorLogger:    errorLogger,
		level:          logger.level,
		showTimestamps: logger.showTimestamps,
	}
}

// SetLevel sets the logger level
func (l *Logger) SetLevel(level string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch strings.ToLower(level) {
	case LevelTrace:
		l.level = LevelTrace
	case LevelDebug:
		l.level = LevelDebug
	case LevelVerbose:
		l.level = LevelVerbose
	case LevelInfo:
		l.level = LevelInfo
	case LevelWarn:
		l.level = LevelWarn
	case LevelError:
		l.level = LevelError
	default:
		l.level = LevelVerbose // default to verbose
	}
	// Update global level for scoped loggers - use the input parameter, not l.level
	updateGlobalLogLevel(level)
	//fmt.Printf("Logger level set to: %s (internal: %s)\n", level, l.level)
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

// Debug logs a debug message with optional formatting
func (l *Logger) Debug(format string, args ...interface{}) {
	// Only show debug if level is debug or trace
	if l.level == LevelDebug || l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s    DEBUG %s", timestamp, message)
		} else {
			message = fmt.Sprintf("   DEBUG %s", message)
		}
		l.debugLogger.Output(2, message)
	}
}

// Verbose logs a verbose message with optional formatting
func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.level == LevelVerbose || l.level == LevelDebug || l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s  VERBOSE %s", timestamp, message)
		} else {
			message = fmt.Sprintf(" VERBOSE %s", message)
		}
		l.infoLogger.Output(2, message)
	}
}

// Info logs an info message with optional formatting
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo || l.level == LevelVerbose || l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s     INFO %s", timestamp, message)
		} else {
			message = fmt.Sprintf("    INFO %s", message)
		}
		l.infoLogger.Output(2, message)
	}
}

// Warn logs a warning message with optional formatting
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo || l.level == LevelVerbose || l.level == LevelWarn || l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s     WARN %s", timestamp, message)
		} else {
			message = fmt.Sprintf("    WARN %s", message)
		}
		l.warnLogger.Output(2, message)
	}
}

// Error logs an error message with optional formatting
func (l *Logger) Error(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	if l.showTimestamps {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message = fmt.Sprintf("%s    ERROR %s", timestamp, message)
	} else {
		message = fmt.Sprintf("   ERROR %s", message)
	}
	l.errorLogger.Output(2, message)
}

// Fatal logs an error message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	if l.showTimestamps {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message = fmt.Sprintf("%s    FATAL %s", timestamp, message)
	} else {
		message = fmt.Sprintf("   FATAL %s", message)
	}
	l.errorLogger.Output(2, message)
	os.Exit(1)
}

// Trace logs a trace message with optional formatting
func (l *Logger) Trace(format string, args ...interface{}) {
	// Only show trace if level is trace
	if l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s    TRACE %s", timestamp, message)
		} else {
			message = fmt.Sprintf("   TRACE %s", message)
		}
		l.debugLogger.Output(2, message)
	}
}

// TraceFunction logs function entry and exit with timing
func (l *Logger) TraceFunction(funcName string) func() {
	if l.level != LevelTrace {
		return func() {}
	}

	start := time.Now()
	l.Trace("ENTER: %s", funcName)

	return func() {
		l.Trace("EXIT: %s (took %v)", funcName, time.Since(start))
	}
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
	logger := GetLogger()
	if logger.level != LevelDebug && logger.level != LevelTrace {
		return
	}

	details := fmt.Sprintf("%+v", obj)
	if len(details) > 1000 {
		details = details[:1000] + "... [truncated]"
	}

	lines := strings.Split(details, "\n")
	for i, line := range lines {
		if i == 0 {
			logger.Debug("%s: %s", prefix, line)
		} else {
			logger.Debug("%s (cont'd): %s", prefix, line)
		}
	}
}

// TracePath logs the execution path with caller information
func TracePath(path string, args ...interface{}) {
	logger := GetLogger()
	if logger.level != LevelTrace {
		return
	}

	message := fmt.Sprintf(path, args...)
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

	// Make the path tracing more visible with >>> markers
	fmt.Printf("[TRACE] [%s] [%s] >>> PATH: %s <<<\n", now, callerInfo, message)
}
