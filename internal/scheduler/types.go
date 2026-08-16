// Package scheduler owns the one durable automatic workspace-evaluation
// schedule. It selects when to evaluate; upstream lego remains responsible for
// deciding whether any certificate is due for renewal.
package scheduler

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	maximumZoneBytes = 128
	minutesPerDay    = 24 * 60
)

var (
	ErrInvalid = errors.New("automatic schedule is invalid")
	ErrNotDue  = errors.New("automatic schedule is not due")
	zoneName   = regexp.MustCompile(`^(?:UTC|[A-Za-z][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*)+)$`)
)

// State is the administrator-visible current schedule state.
type State string

const (
	StateDisabled  State = "disabled"
	StateScheduled State = "scheduled"
	StateDue       State = "due"
	StateDeferred  State = "deferred"
	StateBlocked   State = "blocked"
)

// Schedule is the singleton secret-free persisted schedule projection.
type Schedule struct {
	Configured        bool
	Enabled           bool
	TimeZone          string
	LocalMinute       int
	NextEvaluation    time.Time
	LastTriggeredAt   time.Time
	LastTriggerDate   string
	ReasonCode        string
	UpdatedAt         time.Time
	State             State
	Claiming          bool
	ClaimedOccurrence time.Time
}

// Update is the complete typed administrator-controlled schedule policy.
type Update struct {
	Enabled     bool
	TimeZone    string
	LocalMinute int
}

// Claim identifies one coalesced due occurrence while its operation is being
// durably accepted.
type Claim struct {
	Occurrence time.Time
}

func validateUpdate(update Update) (*time.Location, error) {
	if len(update.TimeZone) == 0 || len(update.TimeZone) > maximumZoneBytes || !zoneName.MatchString(update.TimeZone) {
		return nil, fmt.Errorf("%w: IANA time zone is invalid", ErrInvalid)
	}
	location, err := time.LoadLocation(update.TimeZone)
	if err != nil || location.String() != update.TimeZone {
		return nil, fmt.Errorf("%w: IANA time zone is unavailable", ErrInvalid)
	}
	if update.LocalMinute < 0 || update.LocalMinute >= minutesPerDay {
		return nil, fmt.Errorf("%w: local evaluation time is invalid", ErrInvalid)
	}
	return location, nil
}

func canonicalInstant(value time.Time, required bool) error {
	if value.IsZero() {
		if required {
			return errors.New("UTC instant is required")
		}
		return nil
	}
	if value.Location() != time.UTC || value != value.Round(0) || value.Year() < 1 || value.Year() > 9999 {
		return errors.New("instant is not canonical UTC")
	}
	return nil
}

func localTimeText(minute int) string {
	return fmt.Sprintf("%02d:%02d", minute/60, minute%60)
}

// LocalTime formats the configured local wall-clock time as HH:MM.
func (schedule Schedule) LocalTime() string {
	if !schedule.Configured {
		return ""
	}
	return localTimeText(schedule.LocalMinute)
}
