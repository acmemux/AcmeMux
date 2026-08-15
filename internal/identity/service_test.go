package identity

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sgurden-certleap/AcmeMux/internal/state"
)

func TestBootstrapAuthenticateAndPersistOnlyVerifierAndTokenHashes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, directory := openTestDatabase(t)
	clock := newFakeClock()
	service := newTestService(t, database, clock, &incrementingReader{})
	password := []byte("canary password never persisted")

	initialized, err := service.Initialized(ctx)
	if err != nil {
		t.Fatalf("Initialized() error = %v", err)
	}
	if initialized {
		t.Fatal("Initialized() = true before bootstrap")
	}
	if _, err := service.Authenticate(ctx, password); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate(uninitialized) error = %v, want ErrInvalidCredentials", err)
	}
	if err := service.Bootstrap(ctx, []byte("too short")); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("Bootstrap(short) error = %v, want ErrPasswordRejected", err)
	}
	if err := service.Bootstrap(ctx, password); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if err := service.Bootstrap(ctx, password); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("Bootstrap(second) error = %v, want ErrAlreadyInitialized", err)
	}
	if _, err := service.Authenticate(ctx, []byte("wrong password value")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate(wrong) error = %v, want ErrInvalidCredentials", err)
	} else if bytes.Contains([]byte(err.Error()), []byte("wrong password value")) {
		t.Fatal("authentication error contains submitted password")
	}

	grant, err := service.Authenticate(ctx, password)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if grant.Token == "" || grant.CSRFToken == "" || grant.Token == grant.CSRFToken {
		t.Fatalf("Authenticate() returned invalid independent tokens: %+v", grant)
	}
	active, err := service.ValidateSession(ctx, grant.Token)
	if err != nil {
		t.Fatalf("ValidateSession() error = %v", err)
	}
	if !active.ValidCSRF(grant.CSRFToken) || active.ValidCSRF(grant.Token) {
		t.Fatal("CSRF binding accepted the wrong token or rejected the correct token")
	}

	var verifier string
	var tokenHash, csrfHash []byte
	if err := database.QueryRowContext(ctx, "SELECT password_verifier FROM administrator").Scan(&verifier); err != nil {
		t.Fatalf("query verifier: %v", err)
	}
	if err := database.QueryRowContext(ctx, `
SELECT current_token_hash, csrf_token_hash FROM identity_sessions`).Scan(&tokenHash, &csrfHash); err != nil {
		t.Fatalf("query token hashes: %v", err)
	}
	for label, cell := range map[string][]byte{
		"password verifier": []byte(verifier),
		"session hash":      tokenHash,
		"CSRF hash":         csrfHash,
	} {
		for _, canary := range [][]byte{password, []byte(grant.Token), []byte(grant.CSRFToken)} {
			if bytes.Contains(cell, canary) {
				t.Fatalf("%s contains raw canary %q", label, canary)
			}
		}
	}

	if _, err := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("checkpoint database: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", entry.Name(), err)
		}
		for _, canary := range [][]byte{password, []byte(grant.Token), []byte(grant.CSRFToken)} {
			if bytes.Contains(contents, canary) {
				t.Fatalf("state file %s contains raw canary %q", entry.Name(), canary)
			}
		}
	}
}

func TestConcurrentBootstrapCreatesExactlyOneAdministrator(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	firstDatabase, err := state.Open(directory)
	if err != nil {
		t.Fatalf("state.Open(first) error = %v", err)
	}
	defer firstDatabase.Close()
	secondDatabase, err := state.Open(directory)
	if err != nil {
		t.Fatalf("state.Open(second) error = %v", err)
	}
	defer secondDatabase.Close()
	clock := newFakeClock()
	firstService := newTestService(t, firstDatabase, clock, &incrementingReader{})
	secondService := newTestService(t, secondDatabase, clock, &incrementingReader{})
	password := []byte("correct horse battery staple")

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, service := range []*Service{firstService, secondService} {
		go func(service *Service) {
			<-start
			results <- service.Bootstrap(context.Background(), password)
		}(service)
	}
	close(start)
	var succeeded, alreadyInitialized int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrAlreadyInitialized):
			alreadyInitialized++
		default:
			t.Fatalf("Bootstrap() unexpected error = %v", err)
		}
	}
	if succeeded != 1 || alreadyInitialized != 1 {
		t.Fatalf("bootstrap outcomes success=%d already=%d, want 1 each", succeeded, alreadyInitialized)
	}
}

func TestResetRevokeAndRestartPersistence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, directory := openTestDatabase(t)
	clock := newFakeClock()
	random := &incrementingReader{}
	service := newTestService(t, database, clock, random)
	oldPassword := []byte("original correct horse password")
	newPassword := []byte("replacement correct horse password")
	if err := service.Bootstrap(ctx, oldPassword); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	grant, err := service.Authenticate(ctx, oldPassword)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	database, err = state.Open(directory)
	if err != nil {
		t.Fatalf("state.Open(restart) error = %v", err)
	}
	defer database.Close()
	service = newTestService(t, database, clock, random)
	if _, err := service.ValidateSession(ctx, grant.Token); err != nil {
		t.Fatalf("ValidateSession(after restart) error = %v", err)
	}
	if err := service.ResetPassword(ctx, newPassword); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	if _, err := service.ValidateSession(ctx, grant.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("ValidateSession(after reset) error = %v, want ErrInvalidSession", err)
	}
	if _, err := service.Authenticate(ctx, oldPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate(old password) error = %v, want ErrInvalidCredentials", err)
	}
	newGrant, err := service.Authenticate(ctx, newPassword)
	if err != nil {
		t.Fatalf("Authenticate(new password) error = %v", err)
	}
	if err := service.RevokeSessions(ctx); err != nil {
		t.Fatalf("RevokeSessions() error = %v", err)
	}
	if _, err := service.ValidateSession(ctx, newGrant.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("ValidateSession(after revoke) error = %v, want ErrInvalidSession", err)
	}
	if _, err := service.Authenticate(ctx, newPassword); err != nil {
		t.Fatalf("Authenticate(after revoke) error = %v", err)
	}
}

func TestConcurrentPasswordResetCannotLeaveStaleSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	clock := newFakeClock()
	random := &incrementingReader{}
	bootstrapService := newTestService(t, database, clock, random)
	oldPassword := []byte("original correct horse password")
	newPassword := []byte("replacement correct horse password")
	if err := bootstrapService.Bootstrap(ctx, oldPassword); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	upgradeParameters := testPasswordParameters
	upgradeParameters.memory *= 2
	upgradeParameters.iterations++
	upgradeParameters.parallelism++
	service := newTestService(t, database, clock, random, withPasswordParameters(upgradeParameters))

	start := make(chan struct{})
	grants := make(chan SessionGrant, 8)
	errorsChannel := make(chan error, 9)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			grant, err := service.Authenticate(ctx, oldPassword)
			if err == nil {
				grants <- grant
				return
			}
			if !errors.Is(err, ErrInvalidCredentials) {
				errorsChannel <- err
			}
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		if err := service.ResetPassword(ctx, newPassword); err != nil {
			errorsChannel <- err
		}
	}()
	close(start)
	group.Wait()
	close(grants)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatalf("concurrent operation error = %v", err)
	}
	for grant := range grants {
		if _, err := service.ValidateSession(ctx, grant.Token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("stale grant survived reset: ValidateSession() error = %v", err)
		}
	}
	if _, err := service.Authenticate(ctx, newPassword); err != nil {
		t.Fatalf("Authenticate(new password) error = %v", err)
	}
	if _, err := service.Authenticate(ctx, oldPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate(old password) error = %v, want ErrInvalidCredentials", err)
	}
}

func TestAdministrativeChangesRequireBootstrap(t *testing.T) {
	t.Parallel()

	database, _ := openTestDatabase(t)
	defer database.Close()
	service := newTestService(t, database, newFakeClock(), &incrementingReader{})
	password := []byte("correct horse battery staple")
	if err := service.ResetPassword(context.Background(), password); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("ResetPassword() error = %v, want ErrUninitialized", err)
	}
	if err := service.RevokeSessions(context.Background()); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("RevokeSessions() error = %v, want ErrUninitialized", err)
	}
}
