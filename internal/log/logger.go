package log

import (
	"os"

	"go.uber.org/zap"
)

// DDSourceLogger is a copy of the interface at https://github.com/DataDog/dd-source/blob/main/libs/go/log/logger.go
type DDSourceLogger interface {
	With(fields ...Field) DDSourceLogger

	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Panic(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)

	Debugf(msg string, params ...any)
	Infof(msg string, params ...any)
	Warnf(msg string, params ...any)
	Errorf(msg string, params ...any)
	Panicf(msg string, params ...any)
	Fatalf(msg string, params ...any)
}

// NoopLogger implements [log.NoopLogger] from dd-source
//
// [log.NoopLogger]: https://github.com/DataDog/dd-source/blob/main/libs/go/log/noop.go
func NoopLogger() DDSourceLogger {
	logger := zap.NewNop()
	return &zapLoggerShim{
		l: logger,
		s: logger.Sugar(),
	}
}

// NewDefaultLogger Creates a new zap Logger.
//
// # Warning
//
// This may leak memory, as it is never flushed. Avoid calling this when possible.
func NewDefaultLogger() DDSourceLogger {
	// Create a default logger (Note that this will differ from the dd-source implementation)
	var cfg zap.Config

	env := os.Getenv("DD_ENV")
	if env == "" {
		os.Getenv("dd_env")
	}

	if env == "prod" || env == "staging" {
		cfg = zap.NewProductionConfig()
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.DisableStacktrace = true
	}

	logger, _ := cfg.Build()
	return &zapLoggerShim{
		l: logger,
		s: logger.Sugar(),
	}
}

const (
	spanIDKey  = "dd.span_id"
	traceIDKey = "dd.trace_id"
)
