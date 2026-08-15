package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

const administratorID = 1

const dummyPassword = "AcmeMux timing equalization password"

// Database is the application-state surface needed by identity. state.DB
// implements it without exposing its concrete SQLite connection.
type Database interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Service owns the singleton administrator password verifier and all browser
// session lifecycle transitions.
type Service struct {
	database           Database
	now                func() time.Time
	random             io.Reader
	randomMutex        sync.Mutex
	passwordParameters passwordParameters
	sessionPolicy      sessionPolicy
	kdfSlots           chan struct{}
	dummyVerifier      string
}

type administratorRecord struct {
	verifier string
	epoch    int64
}

// New constructs an identity service with fixed production policy and
// injectable clock and randomness for deterministic verification.
func New(database Database, options ...Option) (*Service, error) {
	if database == nil {
		return nil, errors.New("identity database is required")
	}
	configuration := defaultConfiguration()
	for _, option := range options {
		if option == nil {
			return nil, errors.New("identity option cannot be nil")
		}
		if err := option(&configuration); err != nil {
			return nil, err
		}
	}
	if err := configuration.validate(); err != nil {
		return nil, err
	}

	service := &Service{
		database:           database,
		now:                configuration.now,
		random:             configuration.random,
		passwordParameters: configuration.passwordParameters,
		sessionPolicy:      configuration.sessionPolicy,
		kdfSlots:           make(chan struct{}, configuration.kdfConcurrency),
	}
	dummySalt := make([]byte, service.passwordParameters.saltLength)
	for index := range dummySalt {
		dummySalt[index] = byte(index*17 + 29)
	}
	dummyHash, err := service.derivePassword(context.Background(), []byte(dummyPassword), dummySalt, service.passwordParameters)
	if err != nil {
		return nil, fmt.Errorf("initialize password timing equalizer: %w", err)
	}
	service.dummyVerifier = formatVerifier(service.passwordParameters, dummySalt, dummyHash)
	return service, nil
}

// Initialized reports whether the local singleton administrator exists.
func (service *Service) Initialized(ctx context.Context) (bool, error) {
	var exists int
	if err := service.database.QueryRowContext(
		ctx,
		"SELECT EXISTS(SELECT 1 FROM administrator WHERE singleton_id = ?)",
		administratorID,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("inspect administrator initialization: %w", err)
	}
	return exists == 1, nil
}

// Bootstrap creates the only administrator. The caller is responsible for
// collecting the password through a local interactive channel.
func (service *Service) Bootstrap(ctx context.Context, password []byte) error {
	if err := validateNewPassword(password); err != nil {
		return err
	}
	verifier, err := service.encodePassword(ctx, password)
	if err != nil {
		return fmt.Errorf("encode administrator password: %w", err)
	}
	now := service.utcNow().Unix()

	transaction, err := service.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin administrator bootstrap: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
INSERT OR IGNORE INTO administrator (
    singleton_id, password_verifier, auth_epoch,
    created_at_unix, password_changed_at_unix
) VALUES (?, ?, 1, ?, ?)`, administratorID, verifier, now, now)
	if err != nil {
		return fmt.Errorf("create administrator: %w", err)
	}
	created, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect administrator bootstrap: %w", err)
	}
	if created != 1 {
		return ErrAlreadyInitialized
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit administrator bootstrap: %w", err)
	}
	return nil
}

// ResetPassword replaces the administrator password and revokes every session
// atomically. auth_epoch also invalidates a stale login that races the reset.
func (service *Service) ResetPassword(ctx context.Context, password []byte) error {
	if err := validateNewPassword(password); err != nil {
		return err
	}
	verifier, err := service.encodePassword(ctx, password)
	if err != nil {
		return fmt.Errorf("encode replacement administrator password: %w", err)
	}
	return service.advanceEpoch(ctx, verifier)
}

// RevokeSessions invalidates every existing and concurrently stale session
// without changing the password verifier.
func (service *Service) RevokeSessions(ctx context.Context) error {
	return service.advanceEpoch(ctx, "")
}

func (service *Service) advanceEpoch(ctx context.Context, replacementVerifier string) error {
	transaction, err := service.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin administrator security change: %w", err)
	}
	defer transaction.Rollback()

	var result sql.Result
	now := service.utcNow().Unix()
	if replacementVerifier == "" {
		result, err = transaction.ExecContext(ctx, `
UPDATE administrator
SET auth_epoch = auth_epoch + 1
WHERE singleton_id = ?`, administratorID)
	} else {
		result, err = transaction.ExecContext(ctx, `
UPDATE administrator
SET password_verifier = ?,
    password_changed_at_unix = ?,
    auth_epoch = auth_epoch + 1
WHERE singleton_id = ?`, replacementVerifier, now, administratorID)
	}
	if err != nil {
		return fmt.Errorf("update administrator security state: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect administrator security change: %w", err)
	}
	if updated != 1 {
		return ErrUninitialized
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM identity_sessions"); err != nil {
		return fmt.Errorf("revoke administrator sessions: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit administrator security change: %w", err)
	}
	return nil
}

// Authenticate verifies the password without disclosing initialization state,
// upgrades a strictly weaker verifier, and establishes a fresh session.
func (service *Service) Authenticate(ctx context.Context, password []byte) (SessionGrant, error) {
	forceInvalid := len(password) > maximumPasswordBytes || !utf8.Valid(password)
	candidate := password
	if forceInvalid {
		candidate = []byte(dummyPassword)
	}

	administrator, err := service.loadAdministrator(ctx)
	if errors.Is(err, ErrUninitialized) {
		verified, _, verifyErr := service.verifyPassword(ctx, candidate, service.dummyVerifier)
		if verifyErr != nil {
			return SessionGrant{}, verifyErr
		}
		_ = verified
		return SessionGrant{}, ErrInvalidCredentials
	}
	if err != nil {
		return SessionGrant{}, err
	}

	verified, parsed, err := service.verifyPassword(ctx, candidate, administrator.verifier)
	if err != nil {
		return SessionGrant{}, err
	}
	if !verified || forceInvalid {
		return SessionGrant{}, ErrInvalidCredentials
	}

	replacementVerifier := ""
	if shouldUpgradePassword(parsed, service.passwordParameters) {
		replacementVerifier, err = service.encodePassword(ctx, password)
		if err != nil {
			return SessionGrant{}, fmt.Errorf("upgrade administrator password verifier: %w", err)
		}
	}
	return service.createSession(ctx, administrator, replacementVerifier)
}

func (service *Service) loadAdministrator(ctx context.Context) (administratorRecord, error) {
	var administrator administratorRecord
	err := service.database.QueryRowContext(ctx, `
SELECT password_verifier, auth_epoch
FROM administrator
WHERE singleton_id = ?`, administratorID).Scan(&administrator.verifier, &administrator.epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return administratorRecord{}, ErrUninitialized
	}
	if err != nil {
		return administratorRecord{}, fmt.Errorf("load administrator verifier: %w", err)
	}
	return administrator, nil
}

func (service *Service) utcNow() time.Time {
	return service.now().UTC()
}

func (service *Service) readRandom(destination []byte) error {
	service.randomMutex.Lock()
	defer service.randomMutex.Unlock()
	_, err := io.ReadFull(service.random, destination)
	return err
}
