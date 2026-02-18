package log

import (
	"go.uber.org/zap"
)

// zapLoggerShim is a wrapper around a zap logger that implements DDSourceLogger.
type zapLoggerShim struct {
	l *zap.Logger
	s *zap.SugaredLogger
}

var _ DDSourceLogger = &zapLoggerShim{}

func (z *zapLoggerShim) With(fields ...Field) DDSourceLogger {
	childLogger := z.l.With(fields...)

	return &zapLoggerShim{
		l: childLogger,
		s: childLogger.Sugar(),
	}
}

func (z *zapLoggerShim) Debug(msg string, fields ...Field) {
	z.l.Debug(msg, fields...)
}
func (z *zapLoggerShim) Info(msg string, fields ...Field) {
	z.l.Info(msg, fields...)
}

func (z *zapLoggerShim) Warn(msg string, fields ...Field) {
	z.l.Warn(msg, fields...)
}

func (z *zapLoggerShim) Error(msg string, fields ...Field) {
	z.l.Error(msg, fields...)
}
func (z *zapLoggerShim) Fatal(msg string, fields ...Field) {
	z.l.Fatal(msg, fields...)
}
func (z *zapLoggerShim) Panic(msg string, fields ...Field) {
	z.l.Panic(msg, fields...)
}

func (z *zapLoggerShim) Debugf(msg string, params ...any) {
	z.s.Debugf(msg, params...)
}

func (z *zapLoggerShim) Infof(msg string, params ...any) {
	z.s.Infof(msg, params...)
}

func (z *zapLoggerShim) Warnf(msg string, params ...any) {
	z.s.Warnf(msg, params...)
}

func (z *zapLoggerShim) Errorf(msg string, params ...any) {
	z.s.Errorf(msg, params...)
}

func (z *zapLoggerShim) Fatalf(msg string, params ...any) {
	z.s.Fatalf(msg, params...)
}

func (z *zapLoggerShim) Panicf(msg string, params ...any) {
	z.s.Panicf(msg, params...)
}
