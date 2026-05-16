package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger is a structured logger with level filtering.
type Logger struct {
	mu      sync.Mutex
	level   Level
	output  io.Writer
	service string
	fields  map[string]interface{}
}

// New creates a new structured logger.
func New(service string, level Level, output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}
	return &Logger{
		level:   level,
		output:  output,
		service: service,
		fields:  make(map[string]interface{}),
	}
}

// With returns a new logger with additional fields.
func (l *Logger) With(fields map[string]interface{}) *Logger {
	newFields := make(map[string]interface{})
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}
	return &Logger{
		level:   l.level,
		output:  l.output,
		service: l.service,
		fields:  newFields,
	}
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string) {
	l.log(DEBUG, msg)
}

// Info logs an info message.
func (l *Logger) Info(msg string) {
	l.log(INFO, msg)
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string) {
	l.log(WARN, msg)
}

// Error logs an error message.
func (l *Logger) Error(msg string) {
	l.log(ERROR, msg)
}

// Fatal logs a fatal message and exits.
func (l *Logger) Fatal(msg string) {
	l.log(FATAL, msg)
	os.Exit(1)
}

func (l *Logger) log(level Level, msg string) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := logEntry{
		Level:     level.String(),
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		Service:   l.service,
		Message:   msg,
		Fields:    make(map[string]interface{}),
	}

	// Add caller info
	_, file, line, ok := runtime.Caller(2)
	if ok {
		entry.Fields["caller"] = fmt.Sprintf("%s:%d", file, line)
	}

	// Add custom fields
	for k, v := range l.fields {
		entry.Fields[k] = v
	}

	// Encode as JSON
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("logger error: %v", err)
		return
	}

	fmt.Fprintln(l.output, string(data))
}

type logEntry struct {
	Level   string                 `json:"level"`
	Time    string                 `json:"time"`
	Service string                 `json:"service"`
	Message string                 `json:"message"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

// Default logger instance.
var defaultLogger = New("bty", INFO, os.Stdout)

// Default returns the default logger.
func Default() *Logger {
	return defaultLogger
}

// SetLevel sets the default logger level.
func SetLevel(level Level) {
	defaultLogger.level = level
}

// SetOutput sets the default logger output.
func SetOutput(output io.Writer) {
	defaultLogger.output = output
}

// Debug logs via default logger.
func Debug(msg string) {
	defaultLogger.Debug(msg)
}

// Info logs via default logger.
func Info(msg string) {
	defaultLogger.Info(msg)
}

// Warn logs via default logger.
func Warn(msg string) {
	defaultLogger.Warn(msg)
}

// Error logs via default logger.
func Error(msg string) {
	defaultLogger.Error(msg)
}

// Fatal logs via default logger.
func Fatal(msg string) {
	defaultLogger.Fatal(msg)
}

// With returns a child logger from default.
func With(fields map[string]interface{}) *Logger {
	return defaultLogger.With(fields)
}
