package broker

import (
	"bytes"
	"sync"
	"unicode"
	"unicode/utf8"
)

type outputStream uint8

const (
	streamStdout outputStream = iota
	streamStderr
)

// outputCollector applies per-stream and aggregate limits under one lock.
// Writers always report the complete input length to os/exec. The first
// overflow cancels the process; no partially retained output is released.
type outputCollector struct {
	mu             sync.Mutex
	stdout         bytes.Buffer
	stderr         bytes.Buffer
	stdoutLimit    int
	stderrLimit    int
	aggregateLimit int
	overflowed     bool
	onOverflow     func()
	overflowOnce   sync.Once
}

type streamWriter struct {
	collector *outputCollector
	stream    outputStream
}

func newOutputCollector(stdoutLimit, stderrLimit, aggregateLimit int, onOverflow func()) *outputCollector {
	return &outputCollector{
		stdoutLimit: stdoutLimit, stderrLimit: stderrLimit, aggregateLimit: aggregateLimit,
		onOverflow: onOverflow,
	}
}

func (collector *outputCollector) stdoutWriter() *streamWriter {
	return &streamWriter{collector: collector, stream: streamStdout}
}

func (collector *outputCollector) stderrWriter() *streamWriter {
	return &streamWriter{collector: collector, stream: streamStderr}
}

func (writer *streamWriter) Write(value []byte) (int, error) {
	if writer == nil || writer.collector == nil {
		return len(value), nil
	}
	collector := writer.collector
	collector.mu.Lock()
	streamBuffer, streamLimit := &collector.stdout, collector.stdoutLimit
	if writer.stream == streamStderr {
		streamBuffer, streamLimit = &collector.stderr, collector.stderrLimit
	}
	remainingStream := max(streamLimit-streamBuffer.Len(), 0)
	remainingAggregate := max(collector.aggregateLimit-collector.stdout.Len()-collector.stderr.Len(), 0)
	accepted := min(len(value), remainingStream, remainingAggregate)
	if accepted > 0 {
		_, _ = streamBuffer.Write(value[:accepted])
	}
	newOverflow := accepted != len(value) && !collector.overflowed
	if accepted != len(value) {
		collector.overflowed = true
	}
	collector.mu.Unlock()

	if newOverflow {
		collector.overflowOnce.Do(func() {
			if collector.onOverflow != nil {
				collector.onOverflow()
			}
		})
	}
	return len(value), nil
}

func (collector *outputCollector) take() (stdout, stderr []byte, overflowed bool) {
	if collector == nil {
		return nil, nil, false
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	overflowed = collector.overflowed
	if !overflowed {
		stdout = bytes.Clone(collector.stdout.Bytes())
		stderr = bytes.Clone(collector.stderr.Bytes())
	}
	clear(collector.stdout.Bytes())
	clear(collector.stderr.Bytes())
	collector.stdout.Reset()
	collector.stderr.Reset()
	return stdout, stderr, overflowed
}

// sanitizeOutput converts arbitrary child bytes to bounded display bytes
// without increasing their length. Newline and horizontal tab are retained;
// terminal controls, invalid UTF-8, and Unicode formatting controls become
// question marks so persisted output cannot inject terminal or bidi state.
func sanitizeOutput(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	result := make([]byte, 0, len(value))
	for len(value) != 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			result = append(result, '?')
			value = value[1:]
			continue
		}
		value = value[size:]
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.In(r, unicode.Cf)) {
			result = append(result, '?')
			continue
		}
		result = utf8.AppendRune(result, r)
	}
	return result
}
