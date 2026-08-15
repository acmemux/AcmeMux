package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const tokenByteLength = 32

// SessionGrant contains newly generated browser-only token material. Callers
// must place Token only in the HttpOnly session cookie and CSRFToken only in
// the separate browser CSRF cookie; neither value may be logged or persisted.
type SessionGrant struct {
	Token             string
	CSRFToken         string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// ActiveSession is the server-side result of validating a raw session cookie.
// ReplacementToken is populated only when bounded rotation succeeded. It is
// the only cookie-emission signal: callers must never re-emit the presented
// token after ordinary validation.
type ActiveSession struct {
	ReplacementToken  string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	csrfTokenHash     [sha256.Size]byte
}

// ValidCSRF reports whether a browser-provided CSRF value is bound to this
// session. It compares hashes in constant time and never exposes the stored
// digest.
func (session ActiveSession) ValidCSRF(rawToken string) bool {
	_, digest, err := decodeToken(rawToken)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(digest[:], session.csrfTokenHash[:]) == 1
}

type sessionRecord struct {
	id                     int64
	authEpoch              int64
	currentTokenHash       []byte
	previousTokenHash      []byte
	previousValidUntilUnix sql.NullInt64
	csrfTokenHash          []byte
	lastSeenUnix           int64
	idleExpiresUnix        int64
	absoluteExpiresUnix    int64
	rotateAfterUnix        int64
}

func (service *Service) createSession(
	ctx context.Context,
	administrator administratorRecord,
	replacementVerifier string,
) (SessionGrant, error) {
	rawToken, tokenHash, err := service.newToken()
	if err != nil {
		return SessionGrant{}, fmt.Errorf("generate session token: %w", err)
	}
	rawCSRFToken, csrfHash, err := service.newToken()
	if err != nil {
		return SessionGrant{}, fmt.Errorf("generate CSRF token: %w", err)
	}

	now := service.utcNow()
	nowUnix := now.Unix()
	absoluteExpiry := now.Add(service.sessionPolicy.absoluteLifetime)
	idleExpiry := now.Add(service.sessionPolicy.idleLifetime)
	if idleExpiry.After(absoluteExpiry) {
		idleExpiry = absoluteExpiry
	}
	rotateAfter := now.Add(service.sessionPolicy.rotationAfter)

	transaction, err := service.database.BeginTx(ctx, nil)
	if err != nil {
		return SessionGrant{}, fmt.Errorf("begin session creation: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `
DELETE FROM identity_sessions
WHERE idle_expires_at_unix <= ?
   OR absolute_expires_at_unix <= ?
   OR auth_epoch != COALESCE((
       SELECT auth_epoch FROM administrator WHERE singleton_id = ?
   ), -1)`, nowUnix, nowUnix, administratorID); err != nil {
		return SessionGrant{}, fmt.Errorf("remove expired sessions: %w", err)
	}

	if replacementVerifier != "" {
		if _, err := transaction.ExecContext(ctx, `
UPDATE administrator
SET password_verifier = ?
WHERE singleton_id = ?
  AND auth_epoch = ?
  AND password_verifier = ?`,
			replacementVerifier,
			administratorID,
			administrator.epoch,
			administrator.verifier,
		); err != nil {
			return SessionGrant{}, fmt.Errorf("upgrade password verifier: %w", err)
		}
	}

	result, err := transaction.ExecContext(ctx, `
INSERT INTO identity_sessions (
    administrator_id, auth_epoch, current_token_hash,
    csrf_token_hash, created_at_unix, last_seen_at_unix,
    idle_expires_at_unix, absolute_expires_at_unix, rotate_after_unix
)
SELECT singleton_id, auth_epoch, ?, ?, ?, ?, ?, ?, ?
FROM administrator
WHERE singleton_id = ? AND auth_epoch = ?`,
		tokenHash[:],
		csrfHash[:],
		nowUnix,
		nowUnix,
		idleExpiry.Unix(),
		absoluteExpiry.Unix(),
		rotateAfter.Unix(),
		administratorID,
		administrator.epoch,
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf("store session: %w", err)
	}
	created, err := result.RowsAffected()
	if err != nil {
		return SessionGrant{}, fmt.Errorf("inspect session creation: %w", err)
	}
	if created != 1 {
		return SessionGrant{}, ErrInvalidCredentials
	}

	if _, err := transaction.ExecContext(ctx, `
DELETE FROM identity_sessions
WHERE administrator_id = ?
  AND id NOT IN (
      SELECT id
      FROM identity_sessions
      WHERE administrator_id = ?
      ORDER BY last_seen_at_unix DESC, id DESC
      LIMIT ?
  )`, administratorID, administratorID, service.sessionPolicy.maximumSessions); err != nil {
		return SessionGrant{}, fmt.Errorf("bound administrator sessions: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return SessionGrant{}, fmt.Errorf("commit session creation: %w", err)
	}

	return SessionGrant{
		Token:             rawToken,
		CSRFToken:         rawCSRFToken,
		IdleExpiresAt:     idleExpiry,
		AbsoluteExpiresAt: absoluteExpiry,
	}, nil
}

// ValidateSession validates expiry and reset state, advances the idle window,
// and rotates a due current token with a bounded previous-token grace period.
func (service *Service) ValidateSession(ctx context.Context, rawToken string) (ActiveSession, error) {
	_, tokenHash, err := decodeToken(rawToken)
	if err != nil {
		return ActiveSession{}, ErrInvalidSession
	}
	return service.validateSessionHash(ctx, tokenHash, true)
}

func (service *Service) validateSessionHash(
	ctx context.Context,
	tokenHash [sha256.Size]byte,
	allowRotation bool,
) (ActiveSession, error) {
	record, err := service.loadSession(ctx, tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ActiveSession{}, ErrInvalidSession
	}
	if err != nil {
		return ActiveSession{}, fmt.Errorf("load session: %w", err)
	}

	nowUnix := service.utcNow().Unix()
	effectiveNow := nowUnix
	if record.lastSeenUnix > effectiveNow {
		effectiveNow = record.lastSeenUnix
	}
	if effectiveNow >= record.idleExpiresUnix || effectiveNow >= record.absoluteExpiresUnix {
		service.deleteExpiredSession(ctx, record, tokenHash)
		return ActiveSession{}, ErrSessionExpired
	}

	matchedCurrent := subtle.ConstantTimeCompare(tokenHash[:], record.currentTokenHash) == 1
	matchedPrevious := len(record.previousTokenHash) == sha256.Size &&
		subtle.ConstantTimeCompare(tokenHash[:], record.previousTokenHash) == 1
	if !matchedCurrent && !matchedPrevious {
		return ActiveSession{}, ErrInvalidSession
	}
	if matchedPrevious && (!record.previousValidUntilUnix.Valid || effectiveNow >= record.previousValidUntilUnix.Int64) {
		_, _ = service.database.ExecContext(ctx, `
UPDATE identity_sessions
SET previous_token_hash = NULL, previous_valid_until_unix = NULL
WHERE id = ? AND previous_token_hash = ?`, record.id, tokenHash[:])
		return ActiveSession{}, ErrInvalidSession
	}

	idleExpiryUnix := effectiveNow + int64(service.sessionPolicy.idleLifetime/time.Second)
	if idleExpiryUnix > record.absoluteExpiresUnix {
		idleExpiryUnix = record.absoluteExpiresUnix
	}
	if allowRotation && matchedCurrent && effectiveNow >= record.rotateAfterUnix {
		replacementToken, replacementHash, err := service.newToken()
		if err != nil {
			return ActiveSession{}, fmt.Errorf("rotate session token: %w", err)
		}
		result, err := service.database.ExecContext(ctx, `
UPDATE identity_sessions
SET previous_token_hash = current_token_hash,
    previous_valid_until_unix = ?,
    current_token_hash = ?,
    last_seen_at_unix = ?,
    idle_expires_at_unix = ?,
    rotate_after_unix = ?
WHERE id = ?
  AND current_token_hash = ?
  AND rotate_after_unix <= ?
  AND auth_epoch = (
      SELECT auth_epoch FROM administrator WHERE singleton_id = ?
  )`,
			effectiveNow+int64(service.sessionPolicy.previousGrace/time.Second),
			replacementHash[:],
			effectiveNow,
			idleExpiryUnix,
			effectiveNow+int64(service.sessionPolicy.rotationAfter/time.Second),
			record.id,
			tokenHash[:],
			effectiveNow,
			administratorID,
		)
		if err != nil {
			return ActiveSession{}, fmt.Errorf("persist session rotation: %w", err)
		}
		rotated, err := result.RowsAffected()
		if err != nil {
			return ActiveSession{}, fmt.Errorf("inspect session rotation: %w", err)
		}
		if rotated == 1 {
			csrfHash, err := fixedDigest(record.csrfTokenHash)
			if err != nil {
				return ActiveSession{}, err
			}
			return ActiveSession{
				ReplacementToken:  replacementToken,
				IdleExpiresAt:     time.Unix(idleExpiryUnix, 0).UTC(),
				AbsoluteExpiresAt: time.Unix(record.absoluteExpiresUnix, 0).UTC(),
				csrfTokenHash:     csrfHash,
			}, nil
		}
		return service.validateSessionHash(ctx, tokenHash, false)
	}

	result, err := service.database.ExecContext(ctx, `
UPDATE identity_sessions
SET last_seen_at_unix = ?, idle_expires_at_unix = ?
WHERE id = ?
  AND auth_epoch = (
      SELECT auth_epoch FROM administrator WHERE singleton_id = ?
  )
  AND (
      current_token_hash = ?
      OR (
          previous_token_hash = ?
          AND previous_valid_until_unix > ?
      )
  )`, effectiveNow, idleExpiryUnix, record.id, administratorID, tokenHash[:], tokenHash[:], effectiveNow)
	if err != nil {
		return ActiveSession{}, fmt.Errorf("advance session activity: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return ActiveSession{}, fmt.Errorf("inspect session activity: %w", err)
	}
	if updated != 1 {
		return ActiveSession{}, ErrInvalidSession
	}
	csrfHash, err := fixedDigest(record.csrfTokenHash)
	if err != nil {
		return ActiveSession{}, err
	}
	return ActiveSession{
		IdleExpiresAt:     time.Unix(idleExpiryUnix, 0).UTC(),
		AbsoluteExpiresAt: time.Unix(record.absoluteExpiresUnix, 0).UTC(),
		csrfTokenHash:     csrfHash,
	}, nil
}

func (service *Service) deleteExpiredSession(
	ctx context.Context,
	record sessionRecord,
	presentedTokenHash [sha256.Size]byte,
) {
	// Validation and cleanup are separate database operations. Bind cleanup to
	// the epoch and presented token as well as the row id so a reset/relogin that
	// reuses an SQLite row id cannot lose its fresh session to stale validation.
	_, _ = service.database.ExecContext(ctx, `
DELETE FROM identity_sessions
WHERE id = ?
  AND auth_epoch = ?
  AND (current_token_hash = ? OR previous_token_hash = ?)`,
		record.id,
		record.authEpoch,
		presentedTokenHash[:],
		presentedTokenHash[:],
	)
}

func (service *Service) loadSession(ctx context.Context, tokenHash [sha256.Size]byte) (sessionRecord, error) {
	var record sessionRecord
	err := service.database.QueryRowContext(ctx, `
SELECT
    sessions.id,
    sessions.auth_epoch,
    sessions.current_token_hash,
    sessions.previous_token_hash,
    sessions.previous_valid_until_unix,
    sessions.csrf_token_hash,
    sessions.last_seen_at_unix,
    sessions.idle_expires_at_unix,
    sessions.absolute_expires_at_unix,
    sessions.rotate_after_unix
FROM identity_sessions AS sessions
JOIN administrator AS administrator
  ON administrator.singleton_id = sessions.administrator_id
 AND administrator.auth_epoch = sessions.auth_epoch
WHERE sessions.current_token_hash = ?
   OR sessions.previous_token_hash = ?
LIMIT 1`, tokenHash[:], tokenHash[:]).Scan(
		&record.id,
		&record.authEpoch,
		&record.currentTokenHash,
		&record.previousTokenHash,
		&record.previousValidUntilUnix,
		&record.csrfTokenHash,
		&record.lastSeenUnix,
		&record.idleExpiresUnix,
		&record.absoluteExpiresUnix,
		&record.rotateAfterUnix,
	)
	return record, err
}

// Logout idempotently removes the logical session addressed by either its
// current token or its still-observable previous token.
func (service *Service) Logout(ctx context.Context, rawToken string) error {
	_, tokenHash, err := decodeToken(rawToken)
	if err != nil {
		return nil
	}
	if _, err := service.database.ExecContext(ctx, `
DELETE FROM identity_sessions
WHERE current_token_hash = ? OR previous_token_hash = ?`, tokenHash[:], tokenHash[:]); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (service *Service) newToken() (string, [sha256.Size]byte, error) {
	contents := make([]byte, tokenByteLength)
	if err := service.readRandom(contents); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	raw := base64.RawURLEncoding.EncodeToString(contents)
	return raw, sha256.Sum256([]byte(raw)), nil
}

func decodeToken(raw string) ([]byte, [sha256.Size]byte, error) {
	if len(raw) != base64.RawURLEncoding.EncodedLen(tokenByteLength) {
		return nil, [sha256.Size]byte{}, ErrInvalidSession
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != tokenByteLength {
		return nil, [sha256.Size]byte{}, ErrInvalidSession
	}
	return decoded, sha256.Sum256([]byte(raw)), nil
}

func fixedDigest(value []byte) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if len(value) != len(digest) {
		return digest, errors.New("persisted identity token hash has invalid length")
	}
	copy(digest[:], value)
	return digest, nil
}
