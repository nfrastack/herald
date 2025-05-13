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
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Logger provides logging functionality for the application
type Logger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	level       string
	mu          sync.Mutex
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Initialize creates the default logger with the specified level
func Initialize(level string) {
	once.Do(func() {
		defaultLogger = NewLogger(level)
	})
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	once.Do(func() {
		// Default to info if not initialized
		defaultLogger = NewLogger(os.Getenv("LOG_LEVEL"))
	})
	return defaultLogger
}

// NewLogger creates a new logger with the specified level
func NewLogger(level string) *Logger {
	if level == "" {
		level = LevelInfo // Default log level
	}
	level = strings.ToLower(level)

	// Use custom timestamp format
	flags := 0 // No standard flags

	// Create loggers with custom prefixes
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
		debugLogger: debugLogger,
		infoLogger:  infoLogger,
		warnLogger:  warnLogger,
		errorLogger: errorLogger,
		level:       level,
	}
}

// SetLevel sets the logger level
func (l *Logger) SetLevel(level string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = strings.ToLower(level)
}

// GetLevel returns the current logger level
func (l *Logger) GetLevel() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// Debug logs a debug message with optional formatting
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level == LevelDebug {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message := fmt.Sprintf(format, args...)
		l.debugLogger.Output(2, fmt.Sprintf("%s DEBUG %s", timestamp, message))
	}
}

// Info logs an info message with optional formatting
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message := fmt.Sprintf(format, args...)
		l.infoLogger.Output(2, fmt.Sprintf("%s INFO %s", timestamp, message))
	}
}

// Warn logs a warning message with optional formatting
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo || l.level == LevelWarn {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message := fmt.Sprintf(format, args...)
		l.warnLogger.Output(2, fmt.Sprintf("%s WARN %s", timestamp, message))
	}
}

// Error logs an error message with optional formatting
func (l *Logger) Error(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	l.errorLogger.Output(2, fmt.Sprintf("%s ERROR %s", timestamp, message))
}

// Fatal logs an error message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	l.errorLogger.Output(2, fmt.Sprintf("%s FATAL %s", timestamp, message))
	os.Exit(1)
}

// Trace logs function entry and exit with timing
func (l *Logger) Trace(funcName string) func() {
	if l.level != LevelDebug {
		return func() {}
	}

	start := time.Now()
	l.Debug("ENTER: %s", funcName)

	return func() {
		l.Debug("EXIT: %s (took %v)", funcName, time.Since(start))
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

// DumpState logs the current state of an object for debugging
func DumpState(prefix string, obj interface{}) {
	logger := GetLogger()
	if logger.level != LevelDebug {
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
	if logger.level != LevelDebug {
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
	fmt.Printf("[DEBUG] [%s] [%s] >>> PATH: %s <<<\n", now, callerInfo, message)
}
