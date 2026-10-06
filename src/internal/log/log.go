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

type ScopedLogger struct {
	prefix string
	level  *slog.LevelVar
	logger *slog.Logger
}

var globalLevel = new(slog.LevelVar)

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

func (sl *ScopedLogger) Debug(format string, args ...interface{}) {
	sl.log(slogDebug, format, args...)
}

func (sl *ScopedLogger) Trace(format string, args ...interface{}) {
	sl.log(slogTrace, format, args...)
}

func (sl *ScopedLogger) Verbose(format string, args ...interface{}) {
	sl.log(slogVerbose, format, args...)
}

func (sl *ScopedLogger) Info(format string, args ...interface{}) {
	sl.log(slogInfo, format, args...)
}

func (sl *ScopedLogger) Warn(format string, args ...interface{}) {
	sl.log(slogWarn, format, args...)
}

func (sl *ScopedLogger) Error(format string, args ...interface{}) {
	sl.log(slogError, format, args...)
}

func (sl *ScopedLogger) shouldLog(messageLevel LogLevel) bool {
	if sl == nil {
		return false
	}
	return sl.logger.Enabled(context.Background(), toSlogLevel(messageLevel))
}

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

func (l *Logger) GetLevel() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

func (l *Logger) SetShowTimestamps(show bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.showTimestamps = show
}

func (l *Logger) SetFormat(format string) {
	format = strings.ToLower(format)
	if format != "json" {
		format = "text"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.format = format
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogDebug, sprintf(format, args...))
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogVerbose, sprintf(format, args...))
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogInfo, sprintf(format, args...))
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogWarn, sprintf(format, args...))
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogError, sprintf(format, args...))
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogError, sprintf(format, args...))
	os.Exit(1)
}

func (l *Logger) Trace(format string, args ...interface{}) {
	l.slogLogger().Log(context.Background(), slogTrace, sprintf(format, args...))
}

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

func GetTimestampsEnabled() bool {
	return GetLogger().showTimestamps
}

func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

func Verbose(format string, args ...interface{}) {
	GetLogger().Verbose(format, args...)
}

func Info(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

func Warn(format string, args ...interface{}) {
	GetLogger().Warn(format, args...)
}

func Error(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	GetLogger().Fatal(format, args...)
}

func Trace(format string, args ...interface{}) {
	GetLogger().Trace(format, args...)
}

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

func TracePath(path string, args ...interface{}) {
	message := sprintf(path, args...)
	now := time.Now().Format("15:04:05.000")

	_, file, line, ok := runtime.Caller(1)
	callerInfo := "unknown"
	if ok {
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
