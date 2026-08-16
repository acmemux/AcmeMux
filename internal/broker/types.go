package broker

import (
	"context"
	"os/exec"
	"time"
)

const (
	defaultTimeout                = 30 * time.Minute
	maximumTimeout                = time.Hour
	defaultTerminationGrace       = 5 * time.Second
	maximumTerminationGrace       = 30 * time.Second
	defaultStandardOutputLimit    = 192 << 10
	defaultErrorOutputLimit       = 64 << 10
	defaultAggregateOutputLimit   = 256 << 10
	maximumStreamOutputLimit      = 1 << 20
	maximumAggregateOutputLimit   = 2 << 20
	defaultMaximumEnvironment     = 128
	maximumEnvironment            = 512
	defaultMaximumEnvironmentByte = 64 << 10
	maximumEnvironmentByte        = 1 << 20
	defaultMaximumEnvironmentSum  = 1 << 20
	maximumEnvironmentSum         = 4 << 20
	defaultMaximumSecrets         = 128
	maximumSecrets                = 1024
	defaultMaximumSecretByte      = 64 << 10
	maximumSecretByte             = 1 << 20
	defaultMaximumSecretSum       = 1 << 20
	maximumSecretSum              = 4 << 20
)

// PreparedExecutable is the one-shot retained runtime handle consumed by a
// broker run. runtime.PreparedExecutable satisfies this interface.
type PreparedExecutable interface {
	StartContext(context.Context, func(*exec.Cmd) error, ...string) (*exec.Cmd, error)
	Close() error
}

// Policy contains fixed process and allocation limits. Zero values are
// invalid so the execution boundary never acquires implicit defaults.
type Policy struct {
	Timeout          time.Duration
	TerminationGrace time.Duration

	StdoutLimit    int
	StderrLimit    int
	AggregateLimit int

	MaximumEnvironment      int
	MaximumEnvironmentBytes int
	MaximumEnvironmentTotal int
	MaximumSecrets          int
	MaximumSecretBytes      int
	MaximumSecretTotal      int
}

// DefaultPolicy returns the bounded Task08 native-operation policy.
func DefaultPolicy() Policy {
	return Policy{
		Timeout:          defaultTimeout,
		TerminationGrace: defaultTerminationGrace,
		StdoutLimit:      defaultStandardOutputLimit,
		StderrLimit:      defaultErrorOutputLimit,
		AggregateLimit:   defaultAggregateOutputLimit,

		MaximumEnvironment:      defaultMaximumEnvironment,
		MaximumEnvironmentBytes: defaultMaximumEnvironmentByte,
		MaximumEnvironmentTotal: defaultMaximumEnvironmentSum,
		MaximumSecrets:          defaultMaximumSecrets,
		MaximumSecretBytes:      defaultMaximumSecretByte,
		MaximumSecretTotal:      defaultMaximumSecretSum,
	}
}

// Variable is one exact environment entry selected by trusted integration
// code. Value is copied for the process and never rendered. Sensitive values
// are also added to the operation's value-based redaction set.
type Variable struct {
	Name      string
	Value     []byte
	Sensitive bool
}

// Request describes the only supported upstream action: process the complete
// adopted native configuration in file mode.
type Request struct {
	Prepared          PreparedExecutable
	WorkingDirectory  string
	ConfigurationPath string
	Environment       []Variable
	ObservedSecrets   [][]byte
}

// Outcome is the broker-level process result. Certificate-level partial and
// not-attempted states require post-run inventory evidence and are owned by
// the durable operation layer.
type Outcome string

const (
	OutcomeSucceeded   Outcome = "succeeded"
	OutcomeFailed      Outcome = "failed"
	OutcomeTimedOut    Outcome = "timed_out"
	OutcomeInterrupted Outcome = "interrupted"
	OutcomeOutputLimit Outcome = "output_limit"
	OutcomeAmbiguous   Outcome = "ambiguous"
)

// Termination records whether the broker had to stop a live process tree.
type Termination string

const (
	TerminationNone     Termination = "none"
	TerminationGraceful Termination = "graceful"
	TerminationForced   Termination = "forced"
)

// Result contains only bounded, redacted, display-safe evidence. A started
// file-mode operation may have changed native or external state regardless of
// its exit status, so MayHaveChanged is true for every started result.
type Result struct {
	Outcome Outcome

	Started    bool
	StartedAt  time.Time
	FinishedAt time.Time

	ExitCode      int
	ExitCodeKnown bool
	TermSignal    string
	Termination   Termination

	Stdout          string
	Stderr          string
	OutputDiscarded bool
	MayHaveChanged  bool
}
