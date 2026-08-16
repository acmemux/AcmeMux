package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const latestOperationID = 1

// Database is the transaction surface required by the durable operation
// store. state.DB implements it without exposing its SQLite connection.
type Database interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// Store owns the singleton latest operation. Enqueue deletes only a completed,
// fully reconciled predecessor, so application state never grows into history.
type Store struct {
	database Database
}

func NewStore(database Database) (*Store, error) {
	if database == nil {
		return nil, errors.New("operation database is required")
	}
	return &Store{database: database}, nil
}

// Enqueue atomically persists a manually accepted request. It remains the
// narrow compatibility entry point used by store-level tests and callers that
// cannot select a trusted product trigger.
func (store *Store) Enqueue(ctx context.Context, id string, request Request, now time.Time) (Operation, error) {
	return store.EnqueueKind(ctx, id, KindManual, request, now)
}

// EnqueueKind atomically persists an accepted trusted request before any
// worker wake or native preparation. A queued/running/pending-reconciliation
// record blocks a second accepted request.
func (store *Store) EnqueueKind(ctx context.Context, id string, kind Kind, request Request, now time.Time) (Operation, error) {
	if err := store.ready(ctx); err != nil {
		return Operation{}, err
	}
	if err := validateID(id); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if kind != KindManual && kind != KindScheduled {
		return Operation{}, fmt.Errorf("%w: operation kind is invalid", ErrInvalid)
	}
	if err := validateRequest(request); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validateTime(now, true); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, fmt.Errorf("begin operation enqueue: %w", err)
	}
	defer tx.Rollback()
	var state, inventoryState string
	err = tx.QueryRowContext(ctx, `
SELECT state, inventory_state
FROM operation_latest
WHERE singleton_id = ?`, latestOperationID).Scan(&state, &inventoryState)
	switch {
	case err == nil && (State(state).active() || InventoryState(inventoryState) == InventoryPending):
		return Operation{}, ErrActive
	case err == nil:
		if _, err := tx.ExecContext(ctx, "DELETE FROM operation_latest WHERE singleton_id = ?", latestOperationID); err != nil {
			return Operation{}, fmt.Errorf("replace completed operation: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return Operation{}, fmt.Errorf("inspect current operation: %w", err)
	}

	timestamp := formatTime(now)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO operation_latest (
    singleton_id, operation_id, reviewed_evidence_sha256, kind, state, phase, requested_at_utc,
    started_at_utc, finished_at_utc, updated_at_utc, reason_code,
    may_have_changed, inventory_state, inventory_code, redacted_output,
    output_truncated, inventory_certificate_count, request_kind
) VALUES (?, ?, ?, ?, ?, ?, ?, '', '', ?, '', 0, ?, '', '', 0, NULL, ?)`,
		latestOperationID, id, request.ReviewedEvidenceSHA256, KindManual, StateQueued, PhaseQueued, timestamp,
		timestamp, InventoryPending, kind,
	); err != nil {
		return Operation{}, fmt.Errorf("persist queued operation: %w", err)
	}
	for ordinal, item := range request.Items {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO operation_requested_item (
    operation_id, item_ordinal, item_name
) VALUES (?, ?, ?)`, id, ordinal, item); err != nil {
			return Operation{}, fmt.Errorf("persist reviewed operation item: %w", err)
		}
	}
	operation, err := loadOperation(ctx, tx)
	if err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit operation enqueue: %w", err)
	}
	return operation, nil
}

// Latest returns the one active operation or latest fully bounded result.
func (store *Store) Latest(ctx context.Context) (Operation, error) {
	if err := store.ready(ctx); err != nil {
		return Operation{}, err
	}
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Operation{}, fmt.Errorf("begin latest operation read: %w", err)
	}
	defer tx.Rollback()
	operation, err := loadOperation(ctx, tx)
	if err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, fmt.Errorf("finish latest operation read: %w", err)
	}
	return operation, nil
}

// Claim changes queued to running/revalidating in the same transaction that
// returns it. At most one worker can claim the singleton.
func (store *Store) Claim(ctx context.Context, now time.Time) (Operation, error) {
	if err := store.ready(ctx); err != nil {
		return Operation{}, err
	}
	if err := validateTime(now, true); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, fmt.Errorf("begin operation claim: %w", err)
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `
SELECT operation_id
FROM operation_latest
WHERE singleton_id = ? AND state = ?`, latestOperationID, StateQueued).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, ErrNoQueued
	}
	if err != nil {
		return Operation{}, fmt.Errorf("inspect queued operation: %w", err)
	}
	timestamp := formatTime(now)
	result, err := tx.ExecContext(ctx, `
UPDATE operation_latest
SET state = ?, phase = ?, started_at_utc = ?, updated_at_utc = ?
WHERE singleton_id = ? AND operation_id = ? AND state = ? AND phase = ?`,
		StateRunning, PhaseRevalidating, timestamp, timestamp,
		latestOperationID, id, StateQueued, PhaseQueued,
	)
	if err != nil {
		return Operation{}, fmt.Errorf("claim queued operation: %w", err)
	}
	if err := requireOneChanged(result); err != nil {
		return Operation{}, err
	}
	operation, err := loadOperation(ctx, tx)
	if err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit operation claim: %w", err)
	}
	return operation, nil
}

// UpdatePhase persists a monotonic active phase before native work enters it.
func (store *Store) UpdatePhase(ctx context.Context, id string, phase Phase, now time.Time) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validateTime(now, true); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin operation phase update: %w", err)
	}
	defer tx.Rollback()
	var currentState, currentPhase string
	err = tx.QueryRowContext(ctx, `
SELECT state, phase
FROM operation_latest
WHERE singleton_id = ? AND operation_id = ?`, latestOperationID, id).Scan(&currentState, &currentPhase)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStateChanged
	}
	if err != nil {
		return fmt.Errorf("inspect operation phase: %w", err)
	}
	if State(currentState) != StateRunning || !validPhaseTransition(Phase(currentPhase), phase) {
		return ErrStateChanged
	}
	result, err := tx.ExecContext(ctx, `
UPDATE operation_latest
SET phase = ?, updated_at_utc = ?
WHERE singleton_id = ? AND operation_id = ? AND state = ? AND phase = ?`,
		phase, formatTime(now), latestOperationID, id, StateRunning, currentPhase,
	)
	if err != nil {
		return fmt.Errorf("persist operation phase: %w", err)
	}
	if err := requireOneChanged(result); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operation phase: %w", err)
	}
	return nil
}

// Finish persists one complete executor result. Raw errors and unredacted
// output have no parameter in this API.
func (store *Store) Finish(ctx context.Context, id string, result Result, now time.Time) (Operation, error) {
	if err := validateExecutorResult(result); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return store.finish(ctx, id, result, now, false)
}

// FinishUncertain is reserved for a recovered worker panic or another jobs
// invariant failure. It persists no executor bytes and leaves inventory
// pending for mandatory inventory-only reconciliation.
func (store *Store) FinishUncertain(ctx context.Context, id string, state State, code string, now time.Time) (Operation, error) {
	if state != StateInterrupted && state != StateAmbiguous {
		return Operation{}, ErrInvalid
	}
	result := Result{
		State: state, Code: code, MayHaveChanged: true,
		Inventory: InventoryResult{State: InventoryPending},
	}
	return store.finish(ctx, id, result, now, true)
}

func (store *Store) finish(ctx context.Context, id string, result Result, now time.Time, allowPending bool) (Operation, error) {
	if err := store.ready(ctx); err != nil {
		return Operation{}, err
	}
	if err := validateID(id); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validateTime(now, true); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if allowPending {
		if !result.State.terminal() || validateCode(result.Code, true) != nil ||
			validateInventory(result.Inventory, true) != nil || validateOutput(result.Output) != nil ||
			validateItems(result.Items) != nil {
			return Operation{}, ErrInvalid
		}
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, fmt.Errorf("begin operation finish: %w", err)
	}
	defer tx.Rollback()
	var currentState string
	err = tx.QueryRowContext(ctx, `
SELECT state
FROM operation_latest
WHERE singleton_id = ? AND operation_id = ?`, latestOperationID, id).Scan(&currentState)
	if errors.Is(err, sql.ErrNoRows) || State(currentState) != StateRunning {
		return Operation{}, ErrStateChanged
	}
	if err != nil {
		return Operation{}, fmt.Errorf("inspect running operation: %w", err)
	}
	requested, err := loadRequestedItems(ctx, tx, id)
	if err != nil {
		return Operation{}, err
	}
	if allowPending && len(result.Items) == 0 {
		result.Items = make([]ItemResult, len(requested))
		for index, name := range requested {
			result.Items[index] = ItemResult{Name: name, State: ItemAmbiguous, Code: result.Code}
		}
	}
	if err := validateResultScope(requested, result.Items); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var certificateCount any
	if result.Inventory.CertificateCount != nil {
		certificateCount = int64(*result.Inventory.CertificateCount)
	}
	changed := int64(0)
	if result.MayHaveChanged {
		changed = 1
	}
	truncated := int64(0)
	if result.OutputTruncated {
		truncated = 1
	}
	resultUpdate, err := tx.ExecContext(ctx, `
UPDATE operation_latest
SET state = ?, phase = '', finished_at_utc = ?, updated_at_utc = ?,
    reason_code = ?, may_have_changed = ?, inventory_state = ?,
    inventory_code = ?, redacted_output = ?, output_truncated = ?,
    inventory_certificate_count = ?
WHERE singleton_id = ? AND operation_id = ? AND state = ?`,
		result.State, formatTime(now), formatTime(now), result.Code, changed,
		result.Inventory.State, result.Inventory.Code, result.Output, truncated, certificateCount,
		latestOperationID, id, StateRunning,
	)
	if err != nil {
		return Operation{}, fmt.Errorf("persist terminal operation: %w", err)
	}
	if err := requireOneChanged(resultUpdate); err != nil {
		return Operation{}, err
	}
	for ordinal, item := range result.Items {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO operation_item_result (
    operation_id, item_ordinal, item_name, state, reason_code
) VALUES (?, ?, ?, ?, ?)`, id, ordinal, item.Name, item.State, item.Code); err != nil {
			return Operation{}, fmt.Errorf("persist operation item result: %w", err)
		}
	}
	operation, err := loadOperation(ctx, tx)
	if err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit terminal operation: %w", err)
	}
	return operation, nil
}

// InterruptRunning converts a process that could have outlived the prior
// service into an explicit, non-retriable terminal state before reconciliation.
func (store *Store) InterruptRunning(ctx context.Context, now time.Time) (Operation, bool, error) {
	if err := store.ready(ctx); err != nil {
		return Operation{}, false, err
	}
	if err := validateTime(now, true); err != nil {
		return Operation{}, false, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, false, fmt.Errorf("begin interrupted operation recovery: %w", err)
	}
	defer tx.Rollback()
	var id, state string
	err = tx.QueryRowContext(ctx, `
SELECT operation_id, state
FROM operation_latest
WHERE singleton_id = ?`, latestOperationID).Scan(&id, &state)
	if errors.Is(err, sql.ErrNoRows) || err == nil && State(state) != StateRunning {
		if err := tx.Commit(); err != nil {
			return Operation{}, false, fmt.Errorf("finish interrupted operation inspection: %w", err)
		}
		return Operation{}, false, nil
	}
	if err != nil {
		return Operation{}, false, fmt.Errorf("inspect interrupted operation: %w", err)
	}
	requested, err := loadRequestedItems(ctx, tx, id)
	if err != nil {
		return Operation{}, false, err
	}
	timestamp := formatTime(now)
	result, err := tx.ExecContext(ctx, `
UPDATE operation_latest
SET state = ?, phase = '', finished_at_utc = ?, updated_at_utc = ?,
    reason_code = ?, may_have_changed = 1, inventory_state = ?,
    inventory_code = '', redacted_output = '', output_truncated = 0,
    inventory_certificate_count = NULL
WHERE singleton_id = ? AND operation_id = ? AND state = ?`,
		StateInterrupted, timestamp, timestamp, "service_restarted", InventoryPending,
		latestOperationID, id, StateRunning,
	)
	if err != nil {
		return Operation{}, false, fmt.Errorf("persist interrupted operation: %w", err)
	}
	if err := requireOneChanged(result); err != nil {
		return Operation{}, false, err
	}
	for ordinal, name := range requested {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO operation_item_result (
    operation_id, item_ordinal, item_name, state, reason_code
) VALUES (?, ?, ?, ?, ?)`, id, ordinal, name, ItemAmbiguous, "service_restarted"); err != nil {
			return Operation{}, false, fmt.Errorf("persist interrupted operation item: %w", err)
		}
	}
	operation, err := loadOperation(ctx, tx)
	if err != nil {
		return Operation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, false, fmt.Errorf("commit interrupted operation: %w", err)
	}
	return operation, true, nil
}

// PendingReconciliation returns a terminal result whose mandatory inventory
// refresh was interrupted before completion.
func (store *Store) PendingReconciliation(ctx context.Context) (Operation, error) {
	operation, err := store.Latest(ctx)
	if err != nil {
		return Operation{}, err
	}
	if operation.Inventory.State != InventoryPending ||
		(operation.State != StateInterrupted && operation.State != StateAmbiguous) {
		return Operation{}, ErrNotFound
	}
	return operation, nil
}

// CompleteReconciliation adds only the inventory summary to an already
// terminal interrupted/ambiguous result. It never changes the operation
// classification or schedules another native run.
func (store *Store) CompleteReconciliation(
	ctx context.Context,
	id string,
	inventory InventoryResult,
	now time.Time,
) (Operation, error) {
	if err := store.ready(ctx); err != nil {
		return Operation{}, err
	}
	if err := validateID(id); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validateInventory(inventory, false); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validateTime(now, true); err != nil {
		return Operation{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, fmt.Errorf("begin operation reconciliation: %w", err)
	}
	defer tx.Rollback()
	var certificateCount any
	if inventory.CertificateCount != nil {
		certificateCount = int64(*inventory.CertificateCount)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE operation_latest
SET inventory_state = ?, inventory_code = ?, inventory_certificate_count = ?,
    updated_at_utc = ?
WHERE singleton_id = ? AND operation_id = ?
  AND state IN (?, ?) AND inventory_state = ?`,
		inventory.State, inventory.Code, certificateCount, formatTime(now),
		latestOperationID, id, StateInterrupted, StateAmbiguous, InventoryPending,
	)
	if err != nil {
		return Operation{}, fmt.Errorf("persist operation reconciliation: %w", err)
	}
	if err := requireOneChanged(result); err != nil {
		return Operation{}, err
	}
	operation, err := loadOperation(ctx, tx)
	if err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit operation reconciliation: %w", err)
	}
	return operation, nil
}

func (store *Store) ready(ctx context.Context) error {
	if store == nil || store.database == nil {
		return errors.New("operation store is not initialized")
	}
	if ctx == nil {
		return errors.New("operation context is required")
	}
	return nil
}

func loadOperation(ctx context.Context, tx *sql.Tx) (Operation, error) {
	var persisted persistedOperation
	err := tx.QueryRowContext(ctx, loadOperationSQL, latestOperationID).Scan(
		&persisted.id, &persisted.reviewedEvidenceSHA256, &persisted.kind, &persisted.state, &persisted.phase,
		&persisted.requestedAt, &persisted.startedAt, &persisted.finishedAt,
		&persisted.updatedAt, &persisted.code, &persisted.mayHaveChanged,
		&persisted.inventoryState, &persisted.inventoryCode, &persisted.output,
		&persisted.outputTruncated, &persisted.certificateCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, fmt.Errorf("load latest operation: %w", err)
	}
	persisted.requestItems, err = loadRequestedItems(ctx, tx, persisted.id)
	if err != nil {
		return Operation{}, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT item_name, state, reason_code
FROM operation_item_result
WHERE operation_id = ?
ORDER BY item_ordinal`, persisted.id)
	if err != nil {
		return Operation{}, fmt.Errorf("load operation item results: %w", err)
	}
	for rows.Next() {
		var item ItemResult
		if err := rows.Scan(&item.Name, &item.State, &item.Code); err != nil {
			rows.Close()
			return Operation{}, fmt.Errorf("read operation item result: %w", err)
		}
		persisted.items = append(persisted.items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Operation{}, fmt.Errorf("read operation item results: %w", err)
	}
	rows.Close()
	operation, err := persisted.operation()
	if err != nil {
		return Operation{}, fmt.Errorf("%w: persisted operation: %v", ErrInvalid, err)
	}
	return operation, nil
}

func loadRequestedItems(ctx context.Context, tx *sql.Tx, id string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT item_name
FROM operation_requested_item
WHERE operation_id = ?
ORDER BY item_ordinal`, id)
	if err != nil {
		return nil, fmt.Errorf("load reviewed operation items: %w", err)
	}
	defer rows.Close()
	var items []string
	for rows.Next() {
		var item string
		if err := rows.Scan(&item); err != nil {
			return nil, fmt.Errorf("read reviewed operation item: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read reviewed operation items: %w", err)
	}
	return items, nil
}

func validateResultScope(requested []string, results []ItemResult) error {
	if len(requested) != len(results) {
		return errors.New("operation result does not cover reviewed items")
	}
	for index := range requested {
		if results[index].Name != requested[index] {
			return errors.New("operation result item differs from reviewed scope")
		}
	}
	return nil
}

type persistedOperation struct {
	id                     string
	reviewedEvidenceSHA256 string
	kind                   string
	state                  string
	phase                  string
	requestedAt            string
	startedAt              string
	finishedAt             string
	updatedAt              string
	code                   string
	mayHaveChanged         int64
	inventoryState         string
	inventoryCode          string
	output                 string
	outputTruncated        int64
	certificateCount       sql.NullInt64
	items                  []ItemResult
	requestItems           []string
}

func (persisted persistedOperation) operation() (Operation, error) {
	requestedAt, err := parseTime(persisted.requestedAt, true)
	if err != nil {
		return Operation{}, fmt.Errorf("request time: %w", err)
	}
	startedAt, err := parseTime(persisted.startedAt, false)
	if err != nil {
		return Operation{}, fmt.Errorf("start time: %w", err)
	}
	finishedAt, err := parseTime(persisted.finishedAt, false)
	if err != nil {
		return Operation{}, fmt.Errorf("finish time: %w", err)
	}
	updatedAt, err := parseTime(persisted.updatedAt, true)
	if err != nil {
		return Operation{}, fmt.Errorf("update time: %w", err)
	}
	mayHaveChanged, err := storedBoolean(persisted.mayHaveChanged)
	if err != nil {
		return Operation{}, fmt.Errorf("may-have-changed: %w", err)
	}
	outputTruncated, err := storedBoolean(persisted.outputTruncated)
	if err != nil {
		return Operation{}, fmt.Errorf("output-truncated: %w", err)
	}
	inventory := InventoryResult{State: InventoryState(persisted.inventoryState), Code: persisted.inventoryCode}
	if persisted.certificateCount.Valid {
		if persisted.certificateCount.Int64 < 0 || persisted.certificateCount.Int64 > maximumCertificateCount {
			return Operation{}, errors.New("inventory certificate count is invalid")
		}
		count := int(persisted.certificateCount.Int64)
		inventory.CertificateCount = &count
	}
	operation := Operation{
		ID: persisted.id, Kind: Kind(persisted.kind), State: State(persisted.state),
		Phase: Phase(persisted.phase), RequestedAt: requestedAt, StartedAt: startedAt,
		FinishedAt: finishedAt, UpdatedAt: updatedAt, Code: persisted.code,
		MayHaveChanged: mayHaveChanged, Inventory: inventory, Output: persisted.output,
		OutputTruncated: outputTruncated, Items: append([]ItemResult(nil), persisted.items...),
		Request: Request{
			ReviewedEvidenceSHA256: persisted.reviewedEvidenceSHA256,
			Items:                  append([]string(nil), persisted.requestItems...),
		},
	}
	if err := validateOperation(operation); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func validateOperation(operation Operation) error {
	if err := validateID(operation.ID); err != nil {
		return err
	}
	if operation.Kind != KindManual && operation.Kind != KindScheduled {
		return errors.New("operation kind is invalid")
	}
	if err := validateRequest(operation.Request); err != nil {
		return err
	}
	if err := validateTime(operation.RequestedAt, true); err != nil {
		return err
	}
	if err := validateTime(operation.UpdatedAt, true); err != nil {
		return err
	}
	if operation.UpdatedAt.Before(operation.RequestedAt) {
		return errors.New("operation update precedes request")
	}
	switch operation.State {
	case StateQueued:
		if operation.Phase != PhaseQueued || !operation.StartedAt.IsZero() || !operation.FinishedAt.IsZero() ||
			operation.Code != "" || operation.MayHaveChanged || operation.Output != "" || operation.OutputTruncated ||
			len(operation.Items) != 0 || operation.Inventory.State != InventoryPending ||
			validateInventory(operation.Inventory, true) != nil {
			return errors.New("queued operation is inconsistent")
		}
	case StateRunning:
		if operation.Phase != PhaseRevalidating && operation.Phase != PhaseExecuting && operation.Phase != PhaseRefreshingInventory {
			return errors.New("running operation phase is invalid")
		}
		if validateTime(operation.StartedAt, true) != nil || !operation.FinishedAt.IsZero() ||
			operation.Code != "" || operation.Output != "" || operation.OutputTruncated || len(operation.Items) != 0 ||
			operation.Inventory.State != InventoryPending || validateInventory(operation.Inventory, true) != nil {
			return errors.New("running operation is inconsistent")
		}
	case StateSucceeded, StateFailed, StatePartial, StateNotAttempted, StateTimedOut,
		StateInterrupted, StateIncompatible, StateAmbiguous:
		if operation.Phase != "" || validateTime(operation.StartedAt, true) != nil ||
			validateTime(operation.FinishedAt, true) != nil || validateCode(operation.Code, true) != nil ||
			validateOutput(operation.Output) != nil || validateItems(operation.Items) != nil {
			return errors.New("terminal operation is inconsistent")
		}
		allowPending := operation.State == StateInterrupted || operation.State == StateAmbiguous
		if err := validateInventory(operation.Inventory, allowPending); err != nil {
			return err
		}
		if operation.Inventory.State == InventoryPending && !allowPending {
			return errors.New("terminal operation has invalid pending inventory")
		}
		if err := validateResultScope(operation.Request.Items, operation.Items); err != nil {
			return err
		}
	default:
		return errors.New("operation state is invalid")
	}
	if !operation.StartedAt.IsZero() && operation.StartedAt.Before(operation.RequestedAt) {
		return errors.New("operation start precedes request")
	}
	if !operation.FinishedAt.IsZero() && operation.FinishedAt.Before(operation.StartedAt) {
		return errors.New("operation finish precedes start")
	}
	if !operation.FinishedAt.IsZero() && operation.UpdatedAt.Before(operation.FinishedAt) {
		return errors.New("operation update precedes finish")
	}
	return nil
}

func requireOneChanged(result sql.Result) error {
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect operation transition: %w", err)
	}
	if changed != 1 {
		return ErrStateChanged
	}
	return nil
}

func storedBoolean(value int64) (bool, error) {
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("stored Boolean is invalid")
	}
}

func formatTime(value time.Time) string {
	return value.Format(time.RFC3339Nano)
}

func parseTime(value string, required bool) (time.Time, error) {
	if value == "" && !required {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC RFC 3339 text")
	}
	if err := validateTime(parsed, true); err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

const loadOperationSQL = `
SELECT
    operation_id,
    reviewed_evidence_sha256,
    request_kind,
    state,
    phase,
    requested_at_utc,
    started_at_utc,
    finished_at_utc,
    updated_at_utc,
    reason_code,
    may_have_changed,
    inventory_state,
    inventory_code,
    redacted_output,
    output_truncated,
    inventory_certificate_count
FROM operation_latest
WHERE singleton_id = ?`
