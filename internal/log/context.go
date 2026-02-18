package log

import (
	"context"
)

// A struct used for a unique type ID to store data on a context. NOTE: This is not the same as the
// equivalent private struct in dd-source, meaning we can never extract a DDSourceLogger from a ctx passed in.
type loggerKeyTypeShim struct{}

var loggerKeyShim = loggerKeyTypeShim{}

// Shim is just ContextWithLogger with a different name, used to document which specific code can be deleted
// when this library is moved to dd-source.
//
// This should be called immediately upon receiving a logger passed in from code that lives in dd-source.
func Shim(ctx context.Context, l DDSourceLogger) context.Context {
	return ContextWithLogger(ctx, l)
}

// FromContext implements [log.FromContext] from dd-source.
//
// # Warning
//
// This will _not_ work to extract a log.Logger from a context provided by code that lives in dd-source.
//
// This will _only_ extract a DDSourceLogger generated within this (datadog-saist) library!
//
// If you need a log.Logger from dd-source and you haven't already converted one to a DDSourceLogger,
// you MUST modify your function to pass one in directly and then use Shim.
//
// If no logger was present, a default one will be newly allocated.
//
// [log.FromContext]: https://github.com/DataDog/dd-source/blob/main/libs/go/log/context.go
func FromContext(ctx context.Context) DDSourceLogger {
	if l, ok := ctx.Value(loggerKeyShim).(DDSourceLogger); ok {
		return l
	}
	return NewDefaultLogger()
}

// ContextWithLogger implements [log.ContextWithLogger] from dd-source
//
// [log.ContextWithLogger]: https://github.com/DataDog/dd-source/blob/main/libs/go/log/context.go
func ContextWithLogger(ctx context.Context, l DDSourceLogger) context.Context {
	return context.WithValue(ctx, loggerKeyShim, l)
}
