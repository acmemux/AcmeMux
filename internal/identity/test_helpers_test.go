package identity

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/state"
)

var testPasswordParameters = passwordParameters{
	memory:      minimumAcceptedMemory,
	iterations:  minimumAcceptedIterations,
	parallelism: minimumAcceptedParallelism,
	saltLength:  minimumAcceptedSaltLength,
	keyLength:   32,
}

var testSessionPolicy = sessionPolicy{
	idleLifetime:     10 * time.Minute,
	absoluteLifetime: time.Hour,
	rotationAfter:    5 * time.Minute,
	previousGrace:    30 * time.Second,
	maximumSessions:  8,
}

type fakeClock struct {
	mutex sync.Mutex
	now   time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2032, time.March, 4, 5, 6, 7, 0, time.UTC)}
}

func (clock *fakeClock) Now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	return clock.now
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.now = clock.now.Add(duration)
}

func (clock *fakeClock) Set(now time.Time) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.now = now
}

type incrementingReader struct {
	mutex sync.Mutex
	next  byte
}

func (reader *incrementingReader) Read(destination []byte) (int, error) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()
	for index := range destination {
		reader.next++
		destination[index] = reader.next
	}
	return len(destination), nil
}

func newTestService(
	t *testing.T,
	database Database,
	clock *fakeClock,
	random io.Reader,
	additionalOptions ...Option,
) *Service {
	t.Helper()
	options := []Option{
		WithClock(clock.Now),
		WithRandom(random),
		withPasswordParameters(testPasswordParameters),
		withSessionPolicy(testSessionPolicy),
	}
	options = append(options, additionalOptions...)
	service, err := New(database, options...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return service
}

func openTestDatabase(t *testing.T) (*state.DB, string) {
	t.Helper()
	directory := t.TempDir()
	database, err := state.Open(directory)
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	return database, directory
}
