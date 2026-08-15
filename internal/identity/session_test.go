package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSessionRotationGraceCSRFAndLogout(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	clock := newFakeClock()
	policy := sessionPolicy{
		idleLifetime:     20 * time.Second,
		absoluteLifetime: time.Minute,
		rotationAfter:    5 * time.Second,
		previousGrace:    3 * time.Second,
		maximumSessions:  8,
	}
	service := newTestService(t, database, clock, &incrementingReader{}, withSessionPolicy(policy))
	password := []byte("correct horse battery staple")
	if err := service.Bootstrap(ctx, password); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	grant, err := service.Authenticate(ctx, password)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	clock.Advance(4 * time.Second)
	active, err := service.ValidateSession(ctx, grant.Token)
	if err != nil {
		t.Fatalf("ValidateSession(before rotation) error = %v", err)
	}
	if active.ReplacementToken != "" {
		t.Fatal("session rotated before rotation deadline")
	}
	if !active.ValidCSRF(grant.CSRFToken) || active.ValidCSRF("forged") {
		t.Fatal("CSRF validation did not remain session-bound")
	}

	clock.Advance(2 * time.Second)
	active, err = service.ValidateSession(ctx, grant.Token)
	if err != nil {
		t.Fatalf("ValidateSession(rotation) error = %v", err)
	}
	if active.ReplacementToken == "" || active.ReplacementToken == grant.Token {
		t.Fatal("due session did not receive an independent replacement token")
	}
	replacement := active.ReplacementToken
	if !active.ValidCSRF(grant.CSRFToken) {
		t.Fatal("CSRF binding changed during session rotation")
	}
	if previous, err := service.ValidateSession(ctx, grant.Token); err != nil || previous.ReplacementToken != "" {
		t.Fatalf("previous token during grace = (%+v, %v), want accepted without re-rotation", previous, err)
	}

	clock.Advance(4 * time.Second)
	if _, err := service.ValidateSession(ctx, grant.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("ValidateSession(previous after grace) error = %v, want ErrInvalidSession", err)
	}
	if _, err := service.ValidateSession(ctx, replacement); err != nil {
		t.Fatalf("ValidateSession(replacement) error = %v", err)
	}
	if err := service.Logout(ctx, replacement); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if err := service.Logout(ctx, "malformed"); err != nil {
		t.Fatalf("Logout(malformed) error = %v", err)
	}
	if _, err := service.ValidateSession(ctx, replacement); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("ValidateSession(after logout) error = %v, want ErrInvalidSession", err)
	}
}

func TestConcurrentRotationIssuesOneReplacement(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	clock := newFakeClock()
	policy := sessionPolicy{
		idleLifetime:     time.Minute,
		absoluteLifetime: time.Hour,
		rotationAfter:    2 * time.Second,
		previousGrace:    5 * time.Second,
		maximumSessions:  8,
	}
	service := newTestService(t, database, clock, &incrementingReader{}, withSessionPolicy(policy))
	password := []byte("correct horse battery staple")
	if err := service.Bootstrap(ctx, password); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	grant, err := service.Authenticate(ctx, password)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	clock.Advance(2 * time.Second)

	start := make(chan struct{})
	results := make(chan ActiveSession, 2)
	errorsChannel := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			active, err := service.ValidateSession(ctx, grant.Token)
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- active
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatalf("ValidateSession() concurrent error = %v", err)
	}
	replacements := 0
	for active := range results {
		if active.ReplacementToken != "" {
			replacements++
		}
	}
	if replacements != 1 {
		t.Fatalf("replacement count = %d, want exactly 1", replacements)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	password := []byte("correct horse battery staple")

	t.Run("idle expiry", func(t *testing.T) {
		database, _ := openTestDatabase(t)
		defer database.Close()
		clock := newFakeClock()
		policy := sessionPolicy{
			idleLifetime:     5 * time.Second,
			absoluteLifetime: time.Minute,
			rotationAfter:    30 * time.Second,
			previousGrace:    2 * time.Second,
			maximumSessions:  8,
		}
		service := newTestService(t, database, clock, &incrementingReader{}, withSessionPolicy(policy))
		if err := service.Bootstrap(ctx, password); err != nil {
			t.Fatalf("Bootstrap() error = %v", err)
		}
		grant, err := service.Authenticate(ctx, password)
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		clock.Advance(5 * time.Second)
		if _, err := service.ValidateSession(ctx, grant.Token); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("ValidateSession() error = %v, want ErrSessionExpired", err)
		}
	})

	t.Run("absolute expiry despite activity", func(t *testing.T) {
		database, _ := openTestDatabase(t)
		defer database.Close()
		clock := newFakeClock()
		policy := sessionPolicy{
			idleLifetime:     6 * time.Second,
			absoluteLifetime: 12 * time.Second,
			rotationAfter:    4 * time.Second,
			previousGrace:    2 * time.Second,
			maximumSessions:  8,
		}
		service := newTestService(t, database, clock, &incrementingReader{}, withSessionPolicy(policy))
		if err := service.Bootstrap(ctx, password); err != nil {
			t.Fatalf("Bootstrap() error = %v", err)
		}
		grant, err := service.Authenticate(ctx, password)
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		token := grant.Token
		for range 2 {
			clock.Advance(4 * time.Second)
			active, err := service.ValidateSession(ctx, token)
			if err != nil {
				t.Fatalf("ValidateSession(activity) error = %v", err)
			}
			if active.ReplacementToken != "" {
				token = active.ReplacementToken
			}
		}
		clock.Advance(4 * time.Second)
		if _, err := service.ValidateSession(ctx, token); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("ValidateSession(absolute) error = %v, want ErrSessionExpired", err)
		}
	})
}

func TestStaleExpiredValidationCannotDeleteReusedSessionRow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	clock := newFakeClock()
	policy := sessionPolicy{
		idleLifetime:     5 * time.Second,
		absoluteLifetime: time.Minute,
		rotationAfter:    30 * time.Second,
		previousGrace:    2 * time.Second,
		maximumSessions:  8,
	}
	service := newTestService(t, database, clock, &incrementingReader{}, withSessionPolicy(policy))
	oldPassword := []byte("original correct horse password")
	newPassword := []byte("replacement correct horse password")
	if err := service.Bootstrap(ctx, oldPassword); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	oldGrant, err := service.Authenticate(ctx, oldPassword)
	if err != nil {
		t.Fatalf("Authenticate(old) error = %v", err)
	}
	_, oldTokenHash, err := decodeToken(oldGrant.Token)
	if err != nil {
		t.Fatalf("decodeToken(old) error = %v", err)
	}
	staleRecord, err := service.loadSession(ctx, oldTokenHash)
	if err != nil {
		t.Fatalf("loadSession(old) error = %v", err)
	}
	clock.Advance(policy.idleLifetime)
	if clock.Now().Unix() < staleRecord.idleExpiresUnix {
		t.Fatal("old session fixture is not expired")
	}

	if err := service.ResetPassword(ctx, newPassword); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	newGrant, err := service.Authenticate(ctx, newPassword)
	if err != nil {
		t.Fatalf("Authenticate(new) error = %v", err)
	}
	_, newTokenHash, err := decodeToken(newGrant.Token)
	if err != nil {
		t.Fatalf("decodeToken(new) error = %v", err)
	}
	freshRecord, err := service.loadSession(ctx, newTokenHash)
	if err != nil {
		t.Fatalf("loadSession(new) error = %v", err)
	}
	if freshRecord.id != staleRecord.id {
		t.Fatalf("fresh row id = %d, want reused stale id %d", freshRecord.id, staleRecord.id)
	}
	if freshRecord.authEpoch == staleRecord.authEpoch {
		t.Fatalf("fresh auth epoch = %d, want different from stale epoch", freshRecord.authEpoch)
	}

	// Resume the cleanup phase of the validation that loaded staleRecord before
	// reset. Its row id now identifies the fresh post-reset session.
	service.deleteExpiredSession(ctx, staleRecord, oldTokenHash)
	if _, err := service.ValidateSession(ctx, newGrant.Token); err != nil {
		t.Fatalf("ValidateSession(fresh after stale cleanup) error = %v", err)
	}
}

func TestSessionClockRollbackDoesNotMoveActivityBackward(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	clock := newFakeClock()
	service := newTestService(t, database, clock, &incrementingReader{})
	password := []byte("correct horse battery staple")
	if err := service.Bootstrap(ctx, password); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	grant, err := service.Authenticate(ctx, password)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	clock.Advance(time.Minute)
	forward, err := service.ValidateSession(ctx, grant.Token)
	if err != nil {
		t.Fatalf("ValidateSession(forward) error = %v", err)
	}
	clock.Set(clock.Now().Add(-2 * time.Minute))
	backward, err := service.ValidateSession(ctx, grant.Token)
	if err != nil {
		t.Fatalf("ValidateSession(backward clock) error = %v", err)
	}
	if backward.IdleExpiresAt.Before(forward.IdleExpiresAt) {
		t.Fatalf("rollback moved idle expiry backward: before=%s after=%s", forward.IdleExpiresAt, backward.IdleExpiresAt)
	}
}

func TestSessionCountIsBounded(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	clock := newFakeClock()
	policy := testSessionPolicy
	policy.maximumSessions = 2
	service := newTestService(t, database, clock, &incrementingReader{}, withSessionPolicy(policy))
	password := []byte("correct horse battery staple")
	if err := service.Bootstrap(ctx, password); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	grants := make([]SessionGrant, 0, 3)
	for range 3 {
		grant, err := service.Authenticate(ctx, password)
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		grants = append(grants, grant)
		clock.Advance(time.Second)
	}
	if _, err := service.ValidateSession(ctx, grants[0].Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("oldest ValidateSession() error = %v, want ErrInvalidSession", err)
	}
	for _, grant := range grants[1:] {
		if _, err := service.ValidateSession(ctx, grant.Token); err != nil {
			t.Fatalf("retained ValidateSession() error = %v", err)
		}
	}
	var stored int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM identity_sessions").Scan(&stored); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if stored != 2 {
		t.Fatalf("stored sessions = %d, want 2", stored)
	}
}

func TestMalformedAndForgedSessionsAreUniformlyRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	service := newTestService(t, database, newFakeClock(), &incrementingReader{})
	password := []byte("correct horse battery staple")
	if err := service.Bootstrap(ctx, password); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	grant, err := service.Authenticate(ctx, password)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	for _, token := range []string{"", "malformed", grant.Token[:len(grant.Token)-1], grant.CSRFToken} {
		if _, err := service.ValidateSession(ctx, token); !errors.Is(err, ErrInvalidSession) {
			t.Errorf("ValidateSession(%q) error = %v, want ErrInvalidSession", token, err)
		}
	}
}
