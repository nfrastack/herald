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
	"sync/atomic"
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
	mu     sync.Mutex
	attrs  []slog.Attr
	gen    uint64
}

var loggerGen atomic.Uint64

func logGen() uint64 {
	return loggerGen.Load()
}

func keyvalsToAttrs(keyvals []interface{}) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(keyvals)/2+1)
	for i := 0; i < len(keyvals); i += 2 {
		key, ok := keyvals[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", keyvals[i])
		}
		var val interface{}
		if i+1 < len(keyvals) {
			val = keyvals[i+1]
		}
		attrs = append(attrs, slog.Any(key, val))
	}
	return attrs
}

var globalLevel = new(slog.LevelVar)

func NewScopedLogger(prefix, logLevel string) *ScopedLogger {
	if logLevel == "" {
		return newScoped(prefix, globalLevel)
	}
	parsed := ParseLogLevel(logLevel)
	if parsed == LogLevelNone {
		return newScoped(prefix, globalLevel)
	}
	own := new(slog.LevelVar)
	own.Set(toSlogLevel(parsed))
	return newScoped(prefix, own)
}

func newScoped(prefix string, level *slog.LevelVar) *ScopedLogger {
	logger := GetLogger().slogLogger()
	var attrs []slog.Attr
	if prefix != "" {
		logger = logger.With("scope", prefix)
		attrs = []slog.Attr{slog.String("scope", prefix)}
	}
	return &ScopedLogger{prefix: prefix, level: level, logger: logger, attrs: attrs, gen: logGen()}
}

func (sl *ScopedLogger) With(keyvals ...interface{}) *ScopedLogger {
	if sl == nil {
		return NewScopedLogger("", "")
	}
	return &ScopedLogger{
		prefix: sl.prefix,
		level:  sl.level,
		logger: sl.logger.With(keyvals...),
		attrs:  append(append([]slog.Attr{}, sl.attrs...), keyvalsToAttrs(keyvals)...),
		gen:    atomic.LoadUint64(&sl.gen),
	}
}

func (sl *ScopedLogger) resolve() {
	if atomic.LoadUint64(&sl.gen) == logGen() {
		return
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.gen == logGen() {
		return
	}
	l := GetLogger()
	l.mu.Lock()
	handler := l.handler
	l.mu.Unlock()
	if len(sl.attrs) > 0 {
		if h, ok := handler.WithAttrs(sl.attrs).(*splitHandler); ok {
			handler = h
		}
	}
	sl.logger = slog.New(handler)
	sl.gen = logGen()
}

func (sl *ScopedLogger) log(level slog.Level, format string, args ...interface{}) {
	if sl == nil {
		return
	}
	sl.resolve()
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

type textSettings struct {
	mu             sync.Mutex
	showTimestamps bool
}

func (s *textSettings) show() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.showTimestamps
}

func (s *textSettings) set(show bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.showTimestamps = show
}

func levelName(l slog.Level) string {
	switch l {
	case slogTrace:
		return "TRACE"
	case slogVerbose:
		return "VERBOSE"
	default:
		return l.String()
	}
}

func timestampsDefault() bool {
	return os.Getenv("INVOCATION_ID") == "" && os.Getenv("JOURNAL_STREAM") == ""
}

func quoteValue(s string) string {
	if s == "" {
		return `""`
	}
	for _, r := range s {
		if r <= ' ' || r == '"' || r == '\\' {
			return fmt.Sprintf("%q", s)
		}
	}
	return s
}

type plainHandler struct {
	w      io.Writer
	level  slog.Leveler
	mu     *sync.Mutex
	st     *textSettings
	group  string
	scope  string
	mark   string
	action string
	attrs  []slog.Attr
}

func (h *plainHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *plainHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := &plainHandler{w: h.w, level: h.level, mu: h.mu, st: h.st, group: h.group, scope: h.scope, mark: h.mark, action: h.action}
	nh.attrs = append([]slog.Attr{}, h.attrs...)
	for _, a := range attrs {
		if h.group != "" || a.Value.Kind() == slog.KindGroup {
			nh.attrs = append(nh.attrs, a)
			continue
		}
		switch a.Key {
		case "scope":
			if a.Value.Kind() == slog.KindString {
				nh.scope = a.Value.String()
			}
		case "scope.mark":
			if a.Value.Kind() == slog.KindString {
				nh.mark = a.Value.String()
			}
		case "action":
			if a.Value.Kind() == slog.KindString {
				nh.action = a.Value.String()
			}
		default:
			nh.attrs = append(nh.attrs, a)
		}
	}
	return nh
}

func (h *plainHandler) WithGroup(name string) slog.Handler {
	nh := *h
	nh.attrs = append([]slog.Attr{}, h.attrs...)
	if h.group == "" {
		nh.group = name
	} else {
		nh.group = h.group + "." + name
	}
	return &nh
}

func (h *plainHandler) appendAttr(b *strings.Builder, key string, v slog.Value) {
	v = v.Resolve()
	if key == "" {
		return
	}
	if v.Kind() == slog.KindGroup {
		for _, ga := range v.Group() {
			h.appendAttr(b, key+"."+ga.Key, ga.Value)
		}
		return
	}
	if h.group != "" {
		key = h.group + "." + key
	}
	b.WriteByte(' ')
	b.WriteString(key)
	b.WriteByte('=')
	if s, ok := v.Any().(string); ok {
		b.WriteString(quoteValue(s))
		return
	}
	fmt.Fprintf(b, "%v", v.Any())
}

func (h *plainHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	if h.st.show() {
		b.WriteString(r.Time.Format("2006-01-02 15:04:05"))
		b.WriteByte(' ')
	}
	name := levelName(r.Level)
	pad := 8 - len(name)
	if pad < 0 {
		pad = 0
	}
	if h.mark != "" && pad > 0 {
		b.WriteString(strings.Repeat(" ", pad-1))
		b.WriteString(h.mark)
	} else {
		b.WriteString(strings.Repeat(" ", pad))
	}
	b.WriteString(name)
	scope := h.scope
	action := h.action
	var rest []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		if a.Value.Kind() == slog.KindString {
			if a.Key == "scope" && scope == "" {
				scope = a.Value.String()
				return true
			}
			if a.Key == "action" && action == "" {
				action = a.Value.String()
				return true
			}
		}
		rest = append(rest, a)
		return true
	})
	if scope != "" {
		b.WriteByte(' ')
		b.WriteString(scope)
	}
	if action != "" {
		b.WriteByte(' ')
		b.WriteString(action)
	}
	b.WriteByte(' ')
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		h.appendAttr(&b, a.Key, a.Value)
	}
	for _, a := range rest {
		h.appendAttr(&b, a.Key, a.Value)
	}
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
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
	st             *textSettings
	file           *os.File
}

var (
	defaultLogger *Logger
	once          sync.Once
)

func ValidFormat(f string) bool {
	switch strings.ToLower(f) {
	case "", "json", "text", "structured", "slog", "journald":
		return true
	}
	return false
}

func ResolveFormat(explicit string) string {
	switch strings.ToLower(explicit) {
	case "json":
		return "json"
	case "text", "journald":
		return "text"
	case "structured", "slog":
		return "structured"
	}
	if v := strings.ToLower(os.Getenv("LOG_FORMAT")); v != "" {
		return ResolveFormat(v)
	}
	if timestampsDefault() {
		return "structured"
	}
	return "text"
}

func Initialize(level string, showTimestamps bool, format string) {
	once.Do(func() {
		defaultLogger = NewLogger(level, showTimestamps, ResolveFormat(format))
		globalLevel.Set(toSlogLevel(ParseLogLevel(orDefault(level, LevelVerbose))))
	})
}

func Reinitialize(level string, showTimestamps bool, format string) {
	parsed := ParseLogLevel(level)
	if parsed == LogLevelNone {
		parsed = LogLevelVerbose
	}
	globalLevel.Set(toSlogLevel(parsed))
	next := NewLogger(level, showTimestamps, ResolveFormat(format))
	l := GetLogger()
	l.mu.Lock()
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
	l.level = level
	l.showTimestamps = showTimestamps
	l.format = next.format
	l.handler = next.handler
	l.logger = next.logger
	l.st = next.st
	l.file = next.file
	l.mu.Unlock()
	loggerGen.Add(1)
}

func orDefault(level, fallback string) string {
	if level == "" {
		return fallback
	}
	return level
}

func GetLogger() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger(os.Getenv("LOG_LEVEL"), timestampsDefault(), "")
		globalLevel.Set(toSlogLevel(ParseLogLevel(orDefault(os.Getenv("LOG_LEVEL"), LevelVerbose))))
	})
	return defaultLogger
}

func (l *Logger) slogLogger() *slog.Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logger
}

func NewLogger(level string, showTimestamps bool, format string) *Logger {
	parsed := ParseLogLevel(level)
	if parsed == LogLevelNone {
		parsed = LogLevelVerbose
	}

	out, errOut := io.Writer(os.Stdout), io.Writer(os.Stderr)
	var file *os.File
	if logFile := os.Getenv("LOG_FILE"); logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err == nil {
			if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				file = f
				out = io.MultiWriter(os.Stdout, file)
				errOut = io.MultiWriter(os.Stderr, file)
			}
		}
	}

	st := &textSettings{showTimestamps: showTimestamps}
	newHandler := func(w io.Writer) slog.Handler {
		opts := &slog.HandlerOptions{Level: globalLevel, AddSource: false}
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 {
				if a.Key == slog.TimeKey && !st.show() {
					return slog.Attr{}
				}
				if a.Key == slog.LevelKey {
					if lvl, ok := a.Value.Any().(slog.Level); ok && (lvl == slogTrace || lvl == slogVerbose) {
						return slog.String(a.Key, levelName(lvl))
					}
				}
			}
			return a
		}
		if format == "json" {
			return slog.NewJSONHandler(w, opts)
		}
		if format == "text" {
			return &plainHandler{w: w, level: globalLevel, mu: &sync.Mutex{}, st: st}
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
		st:             st,
		file:           file,
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
	l.showTimestamps = show
	l.mu.Unlock()
	if l.st != nil {
		l.st.set(show)
	}
}

func (l *Logger) SetFormat(format string) {
	format = strings.ToLower(format)
	if format != "json" && format != "text" && format != "structured" {
		format = "structured"
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
