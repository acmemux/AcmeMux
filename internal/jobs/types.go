package jobs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maximumOutputBytes      = 256 << 10
	maximumItemResults      = 256
	maximumItemNameBytes    = 255
	maximumCertificateCount = 10000
	maximumCodeBytes        = 64
	sha256HexBytes          = 64
)

// Request is the bounded, secret-free evidence retained with accepted work.
// ReviewedEvidenceSHA256 is a stable digest of runtime, workspace, and native
// source metadata; it is deliberately distinct from browser review tokens and
// contains no source-content digest. Items are the reviewed native certificate
// identities and let restart/failure results retain the accepted scope.
type Request struct {
	ReviewedEvidenceSHA256 string
	Items                  []string
}

// Kind identifies the bounded operation family. Task 08 introduces only the
// fixed native file-mode manual operation.
type Kind string

const KindManual Kind = "manual"

// State is the durable operation lifecycle and terminal classification.
type State string

const (
	StateQueued       State = "queued"
	StateRunning      State = "running"
	StateSucceeded    State = "succeeded"
	StateFailed       State = "failed"
	StatePartial      State = "partial"
	StateNotAttempted State = "not_attempted"
	StateTimedOut     State = "timed_out"
	StateInterrupted  State = "interrupted"
	StateIncompatible State = "incompatible"
	StateAmbiguous    State = "ambiguous"
)

// Phase is the pollable active stage. It is deliberately coarser than broker
// internals and never contains upstream text or native values.
type Phase string

const (
	PhaseQueued              Phase = "queued"
	PhaseRevalidating        Phase = "revalidating"
	PhaseExecuting           Phase = "executing"
	PhaseRefreshingInventory Phase = "refreshing_inventory"
)

// InventoryState records whether the mandatory terminal inventory refresh
// completed. Pending is internal recovery state and is never a completed
// executor result.
type InventoryState string

const (
	InventoryPending     InventoryState = "pending"
	InventoryRefreshed   InventoryState = "refreshed"
	InventoryUnavailable InventoryState = "unavailable"
)

// ItemState is the evidence-backed result for one configured certificate.
type ItemState string

const (
	ItemCompleted    ItemState = "completed"
	ItemFailed       ItemState = "failed"
	ItemNotAttempted ItemState = "not_attempted"
	ItemAmbiguous    ItemState = "ambiguous"
)

// InventoryResult is a bounded, non-artifact summary. CertificateCount is
// present only when refresh succeeded; native inventory rows are not stored.
type InventoryResult struct {
	State            InventoryState
	Code             string
	CertificateCount *int
}

// ItemResult retains only the latest operation's certificate-level outcome.
// Name is native metadata, not certificate, key, resource, or YAML content.
type ItemResult struct {
	Name  string
	State ItemState
	Code  string
}

// Result is the only executor data eligible for persistence. Output must have
// already passed field/value redaction and text sanitization before crossing
// into jobs. Errors and raw child bytes are intentionally absent.
type Result struct {
	State           State
	Code            string
	MayHaveChanged  bool
	Inventory       InventoryResult
	Output          string
	OutputTruncated bool
	Items           []ItemResult
}

// Operation is the bounded latest durable operation projection.
type Operation struct {
	ID              string
	Kind            Kind
	State           State
	Phase           Phase
	RequestedAt     time.Time
	StartedAt       time.Time
	FinishedAt      time.Time
	UpdatedAt       time.Time
	Code            string
	MayHaveChanged  bool
	Inventory       InventoryResult
	Output          string
	OutputTruncated bool
	Items           []ItemResult
	Request         Request
}

// PhaseReporter persists one monotonic active phase before the executor
// begins that phase. A returned error must stop native execution.
type PhaseReporter func(Phase) error

// Executor is the narrow native-operation seam owned by the composition root.
// Execute performs fresh runtime, workspace, supported-configuration, and
// shared-lease checks; invokes the constrained broker at most once; and
// refreshes inventory before returning. Reconcile is inventory-only and is
// used after restart or a recovered worker panic. Neither method may return
// raw child output or a potentially secret error.
type Executor interface {
	Execute(context.Context, string, Request, PhaseReporter) Result
	Reconcile(context.Context, string) InventoryResult
}

func validateRequest(request Request) error {
	if len(request.ReviewedEvidenceSHA256) != sha256HexBytes {
		return errors.New("reviewed evidence digest is invalid")
	}
	decoded, err := hex.DecodeString(request.ReviewedEvidenceSHA256)
	if err != nil || len(decoded) != sha256HexBytes/2 || strings.ToLower(request.ReviewedEvidenceSHA256) != request.ReviewedEvidenceSHA256 {
		return errors.New("reviewed evidence digest is invalid")
	}
	if len(request.Items) == 0 || len(request.Items) > maximumItemResults {
		return errors.New("reviewed operation items exceed their bound")
	}
	seen := make(map[string]struct{}, len(request.Items))
	for _, item := range request.Items {
		if err := validateItemName(item); err != nil {
			return err
		}
		if _, duplicate := seen[item]; duplicate {
			return errors.New("reviewed operation item is duplicated")
		}
		seen[item] = struct{}{}
	}
	return nil
}

func (state State) active() bool {
	return state == StateQueued || state == StateRunning
}

// Active reports whether this operation is queued or running.
func (operation Operation) Active() bool { return operation.State.active() }

// Terminal reports whether this operation is a completed latest result.
func (operation Operation) Terminal() bool { return operation.State.terminal() }

func (state State) terminal() bool {
	switch state {
	case StateSucceeded, StateFailed, StatePartial, StateNotAttempted,
		StateTimedOut, StateInterrupted, StateIncompatible, StateAmbiguous:
		return true
	default:
		return false
	}
}

func validPhaseTransition(from, to Phase) bool {
	switch from {
	case PhaseRevalidating:
		return to == PhaseExecuting || to == PhaseRefreshingInventory
	case PhaseExecuting:
		return to == PhaseRefreshingInventory
	default:
		return false
	}
}

func validateID(value string) error {
	if len(value) != 32 || strings.ToLower(value) != value {
		return errors.New("operation ID is not canonical lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return errors.New("operation ID is not canonical lowercase hexadecimal")
	}
	return nil
}

func validateCode(value string, required bool) error {
	if value == "" {
		if required {
			return errors.New("stable code is required")
		}
		return nil
	}
	if len(value) > maximumCodeBytes || value[0] < 'a' || value[0] > 'z' {
		return errors.New("stable code is invalid")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return errors.New("stable code is invalid")
		}
	}
	return nil
}

func validateTime(value time.Time, required bool) error {
	if value.IsZero() {
		if required {
			return errors.New("timestamp is required")
		}
		return nil
	}
	if value.Location() != time.UTC || value != value.Round(0) || value.Year() < 1 || value.Year() > 9999 {
		return errors.New("timestamp is not a persistable UTC instant")
	}
	return nil
}

func validateOutput(value string) error {
	if len(value) > maximumOutputBytes || !utf8.ValidString(value) {
		return errors.New("redacted output exceeds its text bound")
	}
	for _, character := range value {
		if character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) {
			return errors.New("redacted output contains an unsafe control character")
		}
	}
	return nil
}

func validateItemName(value string) error {
	if value == "" || len(value) > maximumItemNameBytes || !utf8.ValidString(value) {
		return errors.New("operation item name is invalid")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("operation item name contains a control character")
		}
	}
	return nil
}

func validateInventory(value InventoryResult, allowPending bool) error {
	switch value.State {
	case InventoryPending:
		if !allowPending || value.Code != "" || value.CertificateCount != nil {
			return errors.New("pending inventory result is inconsistent")
		}
	case InventoryRefreshed:
		if err := validateCode(value.Code, true); err != nil {
			return fmt.Errorf("inventory code: %w", err)
		}
		if value.CertificateCount == nil || *value.CertificateCount < 0 || *value.CertificateCount > maximumCertificateCount {
			return errors.New("refreshed inventory count is invalid")
		}
	case InventoryUnavailable:
		if err := validateCode(value.Code, true); err != nil {
			return fmt.Errorf("inventory code: %w", err)
		}
		if value.CertificateCount != nil {
			return errors.New("unavailable inventory cannot contain a certificate count")
		}
	default:
		return errors.New("inventory state is invalid")
	}
	return nil
}

func validateItems(items []ItemResult) error {
	if len(items) > maximumItemResults {
		return errors.New("operation item results exceed their bound")
	}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if err := validateItemName(item.Name); err != nil {
			return err
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return errors.New("operation item name is duplicated")
		}
		seen[item.Name] = struct{}{}
		switch item.State {
		case ItemCompleted, ItemFailed, ItemNotAttempted, ItemAmbiguous:
		default:
			return errors.New("operation item state is invalid")
		}
		if err := validateCode(item.Code, true); err != nil {
			return fmt.Errorf("operation item code: %w", err)
		}
	}
	return nil
}

func validateExecutorResult(result Result) error {
	if !result.State.terminal() {
		return errors.New("executor result is not terminal")
	}
	if err := validateCode(result.Code, true); err != nil {
		return fmt.Errorf("operation code: %w", err)
	}
	if err := validateInventory(result.Inventory, false); err != nil {
		return err
	}
	if err := validateOutput(result.Output); err != nil {
		return err
	}
	return validateItems(result.Items)
}

func cloneInventory(value InventoryResult) InventoryResult {
	if value.CertificateCount != nil {
		count := *value.CertificateCount
		value.CertificateCount = &count
	}
	return value
}

func cloneRequest(value Request) Request {
	value.Items = append([]string(nil), value.Items...)
	return value
}

func cloneOperation(value Operation) Operation {
	value.Inventory = cloneInventory(value.Inventory)
	value.Items = append([]ItemResult(nil), value.Items...)
	value.Request = cloneRequest(value.Request)
	return value
}
