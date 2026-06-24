// Package telemetry samples the engine's process memory and emits it
package telemetry

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/shirou/gopsutil/v4/process"
)

const (
	metricRSS    = "saist.engine.memory.rss_bytes"
	metricGoHeap = "saist.engine.memory.go_heap_bytes"

	defaultInterval = 2 * time.Second // overridable via SAIST_MEM_SAMPLE
	bytesPerMiB     = 1 << 20
)

var (
	currentPhase atomic.Pointer[string]
	phaseSignal  = make(chan struct{}, 1) // wakes the sampler to emit on a phase change
)

// SetPhase sets the phase label samples are tagged with, and wakes the sampler so each
// phase emits at least once even on a sub-interval scan.
func SetPhase(p string) {
	currentPhase.Store(&p)
	select {
	case phaseSignal <- struct{}{}:
	default:
	}
}

func phase() string {
	if p := currentPhase.Load(); p != nil {
		return *p
	}
	return "startup"
}

type sample struct {
	rssBytes    uint64
	goHeapBytes uint64
}

func readSample(p *process.Process) (sample, bool) {
	mi, err := p.MemoryInfo()
	if err != nil || mi == nil {
		return sample{}, false
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return sample{rssBytes: mi.RSS, goHeapBytes: ms.HeapInuse}, true
}

// Start samples memory every interval, emitting to sink until stop() or ctx ends.
// No-op when sampling is disabled (SAIST_MEM_SAMPLE=off).
func Start(parent context.Context, sink MemSink) (stop func()) {
	interval, enabled := sampleInterval()
	if !enabled {
		return func() {}
	}
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return func() {}
	}

	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		emit := func() {
			if s, ok := readSample(proc); ok {
				sink.Emit(s, phase())
			}
		}
		emit() // baseline, so a sub-interval scan still reports at least once
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				emit() // final sample at end of scan
				return
			case <-phaseSignal:
				emit() // capture memory at each phase boundary
			case <-t.C:
				emit()
			}
		}
	}()
	return func() { cancel(); <-done; sink.Close() }
}

// sampleInterval reads SAIST_MEM_SAMPLE: "off"/"false"/"0" disables, a duration overrides.
func sampleInterval() (time.Duration, bool) {
	switch v := os.Getenv("SAIST_MEM_SAMPLE"); v {
	case "":
		return defaultInterval, true
	case "off", "false", "0":
		return 0, false
	default:
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d, true
		}
		return defaultInterval, true
	}
}

// MemSink receives memory samples; NewSink picks the implementation.
type MemSink interface {
	Emit(s sample, phase string)
	Close()
}

// NewSink emits to statsd when an endpoint is configured, else to
// stderr (standalone, where the parent process doesn't buffer our output).
func NewSink() MemSink {
	if addr := statsdAddr(); addr != "" {
		if c, err := statsd.New(addr, statsd.WithTags([]string{"engine:datadog-saist"})); err == nil {
			return &statsdSink{c: c}
		}
	}
	return &stderrSink{w: os.Stderr}
}

// statsdAddr returns the statsd endpoint from the env, or "" (stderr). STATSD_*
// are set by the host environment and our subprocess inherits them.
func statsdAddr() string {
	if v := os.Getenv("STATSD_STREAM_URL"); v != "" { // unix socket
		return v
	}
	if v := os.Getenv("STATSD_URL"); v != "" { // host:port
		return v
	}
	return ""
}

// statsdSink emits a distribution sample, tagged only by phase
type statsdSink struct{ c *statsd.Client }

func (s *statsdSink) Emit(sm sample, phase string) {
	tags := []string{"phase:" + phase}
	_ = s.c.Distribution(metricRSS, float64(sm.rssBytes), tags, 1)
	_ = s.c.Distribution(metricGoHeap, float64(sm.goHeapBytes), tags, 1)
}

func (s *statsdSink) Close() { _ = s.c.Close() }

// stderrSink logs every sample.
type stderrSink struct{ w io.Writer }

func (s *stderrSink) Emit(sm sample, phase string) {
	_, _ = fmt.Fprintf(s.w, "[saist-mem] phase=%s rss=%dMiB go_heap=%dMiB\n",
		phase, sm.rssBytes/bytesPerMiB, sm.goHeapBytes/bytesPerMiB)
}

func (s *stderrSink) Close() {}
