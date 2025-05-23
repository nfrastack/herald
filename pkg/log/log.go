// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

// Package log provides unified logging functionality for the application
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
// TODO: Probably need a verbose in the middle of INFO and DEBUG
const (
	LevelTrace = "trace"
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

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
	})
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	once.Do(func() {
		// Default to info if not initialized
		defaultLogger = NewLogger(os.Getenv("LOG_LEVEL"), true)
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
	case LevelInfo:
		l.level = LevelInfo
	case LevelWarn:
		l.level = LevelWarn
	case LevelError:
		l.level = LevelError
	default:
		l.level = LevelInfo
	}
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
	if l.level == LevelDebug || l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s DEBUG %s", timestamp, message)
		} else {
			message = fmt.Sprintf("DEBUG %s", message)
		}
		l.debugLogger.Output(2, message)
	}
}

// Info logs an info message with optional formatting
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo || l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s INFO %s", timestamp, message)
		} else {
			message = fmt.Sprintf("INFO %s", message)
		}
		l.infoLogger.Output(2, message)
	}
}

// Warn logs a warning message with optional formatting
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo || l.level == LevelWarn || l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s WARN %s", timestamp, message)
		} else {
			message = fmt.Sprintf("WARN %s", message)
		}
		l.warnLogger.Output(2, message)
	}
}

// Error logs an error message with optional formatting
func (l *Logger) Error(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	if l.showTimestamps {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message = fmt.Sprintf("%s ERROR %s", timestamp, message)
	} else {
		message = fmt.Sprintf("ERROR %s", message)
	}
	l.errorLogger.Output(2, message)
}

// Fatal logs an error message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	if l.showTimestamps {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message = fmt.Sprintf("%s FATAL %s", timestamp, message)
	} else {
		message = fmt.Sprintf("FATAL %s", message)
	}
	l.errorLogger.Output(2, message)
	os.Exit(1)
}

// Trace logs a trace message with optional formatting
func (l *Logger) Trace(format string, args ...interface{}) {
	if l.level == LevelTrace {
		message := fmt.Sprintf(format, args...)
		if l.showTimestamps {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			message = fmt.Sprintf("%s TRACE %s", timestamp, message)
		} else {
			message = fmt.Sprintf("TRACE %s", message)
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

// Helper functions that use the default logger

// Debug logs a debug message with the default logger
func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
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
	if logger.level != LevelDebug && logger.level != LevelTrace {
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
