package identity

import (
	"crypto/rand"
	"errors"
	"io"
	"time"
)

const (
	defaultKDFConcurrency = 2
	defaultIdleLifetime   = 30 * time.Minute
	defaultAbsoluteLife   = 12 * time.Hour
	defaultRotationAfter  = 15 * time.Minute
	defaultPreviousGrace  = 30 * time.Second
	defaultMaximumSession = 8
)

type passwordParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var defaultPasswordParameters = passwordParameters{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

type sessionPolicy struct {
	idleLifetime     time.Duration
	absoluteLifetime time.Duration
	rotationAfter    time.Duration
	previousGrace    time.Duration
	maximumSessions  int
}

var defaultSessionPolicy = sessionPolicy{
	idleLifetime:     defaultIdleLifetime,
	absoluteLifetime: defaultAbsoluteLife,
	rotationAfter:    defaultRotationAfter,
	previousGrace:    defaultPreviousGrace,
	maximumSessions:  defaultMaximumSession,
}

type configuration struct {
	now                func() time.Time
	random             io.Reader
	passwordParameters passwordParameters
	sessionPolicy      sessionPolicy
	kdfConcurrency     int
}

// Option changes a testable service dependency. Production callers normally
// use New without options so secure randomness, UTC wall time, and fixed
// security policy remain centralized.
type Option func(*configuration) error

// WithClock injects the UTC wall clock used for expiry and persistence. It is
// intended for deterministic tests.
func WithClock(now func() time.Time) Option {
	return func(configuration *configuration) error {
		if now == nil {
			return errors.New("identity clock is required")
		}
		configuration.now = now
		return nil
	}
}

// WithRandom injects the source used for session tokens, CSRF tokens, and
// password salts. Production callers should retain crypto/rand.Reader.
func WithRandom(random io.Reader) Option {
	return func(configuration *configuration) error {
		if random == nil {
			return errors.New("identity randomness source is required")
		}
		configuration.random = random
		return nil
	}
}

func withPasswordParameters(parameters passwordParameters) Option {
	return func(configuration *configuration) error {
		configuration.passwordParameters = parameters
		return nil
	}
}

func withSessionPolicy(policy sessionPolicy) Option {
	return func(configuration *configuration) error {
		configuration.sessionPolicy = policy
		return nil
	}
}

func withKDFConcurrency(limit int) Option {
	return func(configuration *configuration) error {
		configuration.kdfConcurrency = limit
		return nil
	}
}

func defaultConfiguration() configuration {
	return configuration{
		now:                time.Now,
		random:             rand.Reader,
		passwordParameters: defaultPasswordParameters,
		sessionPolicy:      defaultSessionPolicy,
		kdfConcurrency:     defaultKDFConcurrency,
	}
}

func (configuration configuration) validate() error {
	if err := validatePasswordParameters(configuration.passwordParameters); err != nil {
		return err
	}
	if configuration.kdfConcurrency < 1 || configuration.kdfConcurrency > 16 {
		return errors.New("identity KDF concurrency must be between 1 and 16")
	}
	policy := configuration.sessionPolicy
	if policy.idleLifetime < time.Second || policy.absoluteLifetime < time.Second || policy.rotationAfter < time.Second || policy.previousGrace < time.Second {
		return errors.New("identity session durations must be at least one second")
	}
	if policy.idleLifetime > policy.absoluteLifetime {
		return errors.New("identity idle lifetime cannot exceed absolute lifetime")
	}
	if policy.rotationAfter >= policy.absoluteLifetime {
		return errors.New("identity rotation must precede absolute expiry")
	}
	if policy.maximumSessions < 1 || policy.maximumSessions > 64 {
		return errors.New("identity maximum sessions must be between 1 and 64")
	}
	return nil
}
