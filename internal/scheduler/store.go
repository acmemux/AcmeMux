package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const scheduleID = 1

// Database is the narrow transaction surface required by the schedule store.
type Database interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

type Store struct{ database Database }

func NewStore(database Database) (*Store, error) {
	if database == nil {
		return nil, errors.New("schedule database is required")
	}
	return &Store{database: database}, nil
}

func (store *Store) Get(ctx context.Context, now time.Time) (Schedule, error) {
	if err := store.ready(ctx, now); err != nil {
		return Schedule{}, err
	}
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Schedule{}, fmt.Errorf("begin schedule read: %w", err)
	}
	defer tx.Rollback()
	schedule, err := loadSchedule(ctx, tx, now)
	if err != nil {
		return Schedule{}, err
	}
	if err := tx.Commit(); err != nil {
		return Schedule{}, fmt.Errorf("finish schedule read: %w", err)
	}
	return schedule, nil
}

func (store *Store) Save(ctx context.Context, update Update, now time.Time) (Schedule, error) {
	if err := store.ready(ctx, now); err != nil {
		return Schedule{}, err
	}
	location, err := validateUpdate(update)
	if err != nil {
		return Schedule{}, err
	}
	next := ""
	reason := "schedule_disabled"
	if update.Enabled {
		calculated, err := nextOccurrence(now, location, update.LocalMinute)
		if err != nil {
			return Schedule{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		next = formatInstant(calculated)
		reason = "schedule_saved"
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Schedule{}, fmt.Errorf("begin schedule save: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
INSERT INTO automatic_schedule (
    singleton_id, enabled, time_zone, local_minute, next_evaluation_utc,
    trigger_state, claimed_occurrence_utc, reason_code, updated_at_utc
) VALUES (?, ?, ?, ?, ?, 'idle', '', ?, ?)
ON CONFLICT(singleton_id) DO UPDATE SET
    enabled = excluded.enabled,
    time_zone = excluded.time_zone,
    local_minute = excluded.local_minute,
    next_evaluation_utc = excluded.next_evaluation_utc,
    trigger_state = 'idle',
    claimed_occurrence_utc = '',
    reason_code = excluded.reason_code,
    updated_at_utc = excluded.updated_at_utc`,
		scheduleID, boolInteger(update.Enabled), update.TimeZone, update.LocalMinute, next, reason, formatInstant(now))
	if err != nil {
		return Schedule{}, fmt.Errorf("persist schedule: %w", err)
	}
	schedule, err := loadSchedule(ctx, tx, now)
	if err != nil {
		return Schedule{}, err
	}
	if err := tx.Commit(); err != nil {
		return Schedule{}, fmt.Errorf("commit schedule save: %w", err)
	}
	return schedule, nil
}

func (store *Store) ClaimDue(ctx context.Context, now time.Time) (Claim, error) {
	if err := store.ready(ctx, now); err != nil {
		return Claim{}, err
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Claim{}, fmt.Errorf("begin schedule claim: %w", err)
	}
	defer tx.Rollback()
	schedule, err := loadSchedule(ctx, tx, now)
	if err != nil {
		return Claim{}, err
	}
	if !schedule.Configured || !schedule.Enabled || schedule.Claiming || schedule.NextEvaluation.After(now) {
		return Claim{}, ErrNotDue
	}
	location, err := time.LoadLocation(schedule.TimeZone)
	if err != nil {
		return Claim{}, fmt.Errorf("persisted schedule time zone: %w", ErrInvalid)
	}
	occurrenceDate := occurrenceLocalDate(schedule.NextEvaluation, location)
	if schedule.LastTriggerDate != "" && occurrenceDate <= schedule.LastTriggerDate {
		next, err := nextOccurrence(now, location, schedule.LocalMinute)
		if err != nil {
			return Claim{}, err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE automatic_schedule
SET next_evaluation_utc = ?, reason_code = 'clock_rollback_coalesced', updated_at_utc = ?
WHERE singleton_id = ?`, formatInstant(next), formatInstant(now), scheduleID); err != nil {
			return Claim{}, fmt.Errorf("coalesce repeated local date: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return Claim{}, fmt.Errorf("commit repeated local date: %w", err)
		}
		return Claim{}, ErrNotDue
	}
	next, err := nextOccurrence(now, location, schedule.LocalMinute)
	if err != nil {
		return Claim{}, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE automatic_schedule
SET next_evaluation_utc = ?, trigger_state = 'claiming', claimed_occurrence_utc = ?,
    reason_code = 'trigger_claimed', updated_at_utc = ?
WHERE singleton_id = ? AND enabled = 1 AND trigger_state = 'idle' AND next_evaluation_utc = ?`,
		formatInstant(next), formatInstant(schedule.NextEvaluation), formatInstant(now), scheduleID, formatInstant(schedule.NextEvaluation))
	if err != nil {
		return Claim{}, fmt.Errorf("claim due schedule: %w", err)
	}
	if err := requireOne(result); err != nil {
		return Claim{}, err
	}
	if err := tx.Commit(); err != nil {
		return Claim{}, fmt.Errorf("commit schedule claim: %w", err)
	}
	return Claim{Occurrence: schedule.NextEvaluation}, nil
}

func (store *Store) CompleteClaim(ctx context.Context, claim Claim, now time.Time) error {
	if err := store.ready(ctx, now); err != nil {
		return err
	}
	if err := canonicalInstant(claim.Occurrence, true); err != nil {
		return ErrInvalid
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schedule completion: %w", err)
	}
	defer tx.Rollback()
	var zone string
	if err := tx.QueryRowContext(ctx, `SELECT time_zone FROM automatic_schedule WHERE singleton_id = ?`, scheduleID).Scan(&zone); err != nil {
		return fmt.Errorf("load claimed schedule zone: %w", err)
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return fmt.Errorf("persisted schedule time zone: %w", ErrInvalid)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE automatic_schedule
SET last_triggered_at_utc = ?, last_trigger_local_date = ?, trigger_state = 'idle',
    claimed_occurrence_utc = '', reason_code = 'triggered', updated_at_utc = ?
WHERE singleton_id = ? AND trigger_state = 'claiming' AND claimed_occurrence_utc = ?`,
		formatInstant(now), occurrenceLocalDate(claim.Occurrence, location), formatInstant(now), scheduleID, formatInstant(claim.Occurrence))
	if err != nil {
		return fmt.Errorf("complete schedule claim: %w", err)
	}
	if err := requireOne(result); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schedule completion: %w", err)
	}
	return nil
}

func (store *Store) ReleaseClaim(ctx context.Context, claim Claim, reason string, deferred bool, now time.Time) error {
	if err := store.ready(ctx, now); err != nil {
		return err
	}
	if err := canonicalInstant(claim.Occurrence, true); err != nil || !validReason(reason) {
		return ErrInvalid
	}
	nextExpression := "next_evaluation_utc"
	arguments := []any{reason, formatInstant(now), scheduleID, formatInstant(claim.Occurrence)}
	if deferred {
		nextExpression = "?"
		arguments = append([]any{formatInstant(claim.Occurrence)}, arguments...)
	}
	query := `UPDATE automatic_schedule SET next_evaluation_utc = ` + nextExpression + `,
trigger_state = 'idle', claimed_occurrence_utc = '', reason_code = ?, updated_at_utc = ?
WHERE singleton_id = ? AND trigger_state = 'claiming' AND claimed_occurrence_utc = ?`
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schedule release: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("release schedule claim: %w", err)
	}
	if err := requireOne(result); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schedule release: %w", err)
	}
	return nil
}

// Recover clears a crash-window claim and, after any interrupted operation,
// advances to the next ordinary occurrence instead of retrying immediately.
func (store *Store) Recover(ctx context.Context, now time.Time, interruptedOperation bool) error {
	if err := store.ready(ctx, now); err != nil {
		return err
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schedule recovery: %w", err)
	}
	defer tx.Rollback()
	schedule, err := loadSchedule(ctx, tx, now)
	if err != nil {
		return err
	}
	if !schedule.Configured || !schedule.Enabled || (!schedule.Claiming && !interruptedOperation) {
		return tx.Commit()
	}
	location, err := time.LoadLocation(schedule.TimeZone)
	if err != nil {
		return fmt.Errorf("persisted schedule time zone: %w", ErrInvalid)
	}
	next, err := nextOccurrence(now, location, schedule.LocalMinute)
	if err != nil {
		return err
	}
	reason := "trigger_recovered"
	if interruptedOperation {
		reason = "operation_interrupted"
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE automatic_schedule
SET next_evaluation_utc = ?, trigger_state = 'idle', claimed_occurrence_utc = '',
    reason_code = ?, updated_at_utc = ?
WHERE singleton_id = ?`, formatInstant(next), reason, formatInstant(now), scheduleID); err != nil {
		return fmt.Errorf("recover automatic schedule: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schedule recovery: %w", err)
	}
	return nil
}

func loadSchedule(ctx context.Context, tx *sql.Tx, now time.Time) (Schedule, error) {
	var enabled int64
	var next, last, updated, claimed string
	var triggerState string
	var schedule Schedule
	err := tx.QueryRowContext(ctx, `
SELECT enabled, time_zone, local_minute, next_evaluation_utc, last_triggered_at_utc,
       last_trigger_local_date, trigger_state, claimed_occurrence_utc, reason_code, updated_at_utc
	FROM automatic_schedule WHERE singleton_id = ?`, scheduleID).Scan(
		&enabled, &schedule.TimeZone, &schedule.LocalMinute, &next, &last,
		&schedule.LastTriggerDate, &triggerState, &claimed, &schedule.ReasonCode, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{State: StateDisabled, ReasonCode: "not_configured"}, nil
	}
	if err != nil {
		return Schedule{}, fmt.Errorf("load automatic schedule: %w", err)
	}
	schedule.Configured = true
	schedule.Enabled = enabled == 1
	schedule.Claiming = triggerState == "claiming"
	var parseErr error
	if schedule.NextEvaluation, parseErr = parseInstant(next, schedule.Enabled); parseErr != nil {
		return Schedule{}, fmt.Errorf("persisted next evaluation: %w", parseErr)
	}
	if schedule.LastTriggeredAt, parseErr = parseInstant(last, false); parseErr != nil {
		return Schedule{}, fmt.Errorf("persisted last trigger: %w", parseErr)
	}
	if schedule.ClaimedOccurrence, parseErr = parseInstant(claimed, false); parseErr != nil {
		return Schedule{}, fmt.Errorf("persisted claimed occurrence: %w", parseErr)
	}
	if schedule.UpdatedAt, parseErr = parseInstant(updated, true); parseErr != nil {
		return Schedule{}, fmt.Errorf("persisted schedule update: %w", parseErr)
	}
	if _, err := validateUpdate(Update{Enabled: schedule.Enabled, TimeZone: schedule.TimeZone, LocalMinute: schedule.LocalMinute}); err != nil {
		return Schedule{}, fmt.Errorf("persisted schedule: %w", err)
	}
	schedule.State = deriveState(schedule, now)
	return schedule, nil
}

func deriveState(schedule Schedule, now time.Time) State {
	if !schedule.Configured || !schedule.Enabled {
		return StateDisabled
	}
	if schedule.Claiming || !schedule.NextEvaluation.After(now) {
		if schedule.ReasonCode == "operation_active" || schedule.ReasonCode == "workspace_busy" {
			return StateDeferred
		}
		return StateDue
	}
	switch schedule.ReasonCode {
	case "configuration_invalid", "workspace_invalid", "recovery_required", "operation_unavailable":
		return StateBlocked
	default:
		return StateScheduled
	}
}

func (store *Store) ready(ctx context.Context, now time.Time) error {
	if store == nil || store.database == nil || ctx == nil {
		return errors.New("schedule store is not initialized")
	}
	return canonicalInstant(now, true)
}

func formatInstant(value time.Time) string { return value.Format(time.RFC3339Nano) }

func parseInstant(value string, required bool) (time.Time, error) {
	if value == "" && !required {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("instant is not canonical UTC RFC 3339 text")
	}
	return parsed, canonicalInstant(parsed, true)
}

func boolInteger(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func requireOne(result sql.Result) error {
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect schedule transition: %w", err)
	}
	if changed != 1 {
		return errors.New("automatic schedule changed concurrently")
	}
	return nil
}

func validReason(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
