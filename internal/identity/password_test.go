package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordVerifierIsStrictAndCapped(t *testing.T) {
	t.Parallel()

	valid := formatVerifier(
		testPasswordParameters,
		[]byte("0123456789abcdef"),
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if _, err := parseVerifier(valid); err != nil {
		t.Fatalf("parseVerifier(valid) error = %v", err)
	}

	tests := []string{
		strings.Replace(valid, "$argon2id$", "$argon2i$", 1),
		strings.Replace(valid, "$v=19$", "$v=16$", 1),
		strings.Replace(valid, "m=8192", "m=08192", 1),
		strings.Replace(valid, "m=8192", "m=262145", 1),
		strings.Replace(valid, "t=1", "t=11", 1),
		strings.Replace(valid, "p=1", "p=17", 1),
		strings.Replace(valid, "$MDEyMzQ1Njc4OWFiY2RlZg$", "$bad*$", 1),
		formatVerifier(
			testPasswordParameters,
			[]byte("too-short"),
			[]byte("0123456789abcdef0123456789abcdef"),
		),
		strings.Repeat("x", maximumVerifierBytes+1),
		valid + "$trailing",
	}
	for _, encoded := range tests {
		if _, err := parseVerifier(encoded); !errors.Is(err, ErrVerifierUnsupported) {
			t.Errorf("parseVerifier(%q) error = %v, want ErrVerifierUnsupported", encoded, err)
		}
	}
}

func TestPasswordVerifierUpgradeDoesNotDowngrade(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	password := []byte("correct horse battery staple")

	t.Run("strictly weaker upgrades", func(t *testing.T) {
		database, _ := openTestDatabase(t)
		defer database.Close()
		clock := newFakeClock()
		random := &incrementingReader{}

		weaker := testPasswordParameters
		bootstrapService := newTestService(t, database, clock, random, withPasswordParameters(weaker))
		if err := bootstrapService.Bootstrap(ctx, password); err != nil {
			t.Fatalf("Bootstrap() error = %v", err)
		}

		current := passwordParameters{
			memory:      weaker.memory * 2,
			iterations:  weaker.iterations + 1,
			parallelism: weaker.parallelism + 1,
			saltLength:  weaker.saltLength,
			keyLength:   weaker.keyLength,
		}
		upgradeService := newTestService(t, database, clock, random, withPasswordParameters(current))
		if _, err := upgradeService.Authenticate(ctx, password); err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		var encoded string
		if err := database.QueryRowContext(ctx, "SELECT password_verifier FROM administrator").Scan(&encoded); err != nil {
			t.Fatalf("query verifier: %v", err)
		}
		parsed, err := parseVerifier(encoded)
		if err != nil {
			t.Fatalf("parse upgraded verifier: %v", err)
		}
		if parsed.parameters != current {
			t.Fatalf("upgraded parameters = %+v, want %+v", parsed.parameters, current)
		}
	})

	t.Run("incomparable stronger factor is retained", func(t *testing.T) {
		database, _ := openTestDatabase(t)
		defer database.Close()
		clock := newFakeClock()
		random := &incrementingReader{}

		strongerMemory := testPasswordParameters
		strongerMemory.memory *= 2
		bootstrapService := newTestService(t, database, clock, random, withPasswordParameters(strongerMemory))
		if err := bootstrapService.Bootstrap(ctx, password); err != nil {
			t.Fatalf("Bootstrap() error = %v", err)
		}
		var before string
		if err := database.QueryRowContext(ctx, "SELECT password_verifier FROM administrator").Scan(&before); err != nil {
			t.Fatalf("query verifier before login: %v", err)
		}

		lowerService := newTestService(t, database, clock, random)
		if _, err := lowerService.Authenticate(ctx, password); err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		var after string
		if err := database.QueryRowContext(ctx, "SELECT password_verifier FROM administrator").Scan(&after); err != nil {
			t.Fatalf("query verifier after login: %v", err)
		}
		if after != before {
			t.Fatal("stronger stored verifier was downgraded")
		}
	})

	t.Run("longer salt with weaker work factor is retained", func(t *testing.T) {
		database, _ := openTestDatabase(t)
		defer database.Close()
		clock := newFakeClock()
		random := &incrementingReader{}

		stored := testPasswordParameters
		stored.saltLength *= 2
		bootstrapService := newTestService(t, database, clock, random, withPasswordParameters(stored))
		if err := bootstrapService.Bootstrap(ctx, password); err != nil {
			t.Fatalf("Bootstrap() error = %v", err)
		}
		var before string
		if err := database.QueryRowContext(ctx, "SELECT password_verifier FROM administrator").Scan(&before); err != nil {
			t.Fatalf("query verifier before login: %v", err)
		}

		current := testPasswordParameters
		current.memory *= 2
		upgradeService := newTestService(t, database, clock, random, withPasswordParameters(current))
		if _, err := upgradeService.Authenticate(ctx, password); err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		var after string
		if err := database.QueryRowContext(ctx, "SELECT password_verifier FROM administrator").Scan(&after); err != nil {
			t.Fatalf("query verifier after login: %v", err)
		}
		if after != before {
			t.Fatal("stored verifier with longer salt was downgraded while upgrading memory")
		}
	})
}

func TestPasswordKDFConcurrencyIsBoundedAndCancelable(t *testing.T) {
	t.Parallel()

	database, _ := openTestDatabase(t)
	defer database.Close()
	service := newTestService(t, database, newFakeClock(), &incrementingReader{}, withKDFConcurrency(1))
	if cap(service.kdfSlots) != 1 {
		t.Fatalf("KDF capacity = %d, want 1", cap(service.kdfSlots))
	}
	service.kdfSlots <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.derivePassword(ctx, []byte("password"), make([]byte, 16), testPasswordParameters)
	<-service.kdfSlots
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("derivePassword() error = %v, want canceled wait", err)
	}
}

func TestUnsupportedPersistedVerifierFailsClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, _ := openTestDatabase(t)
	defer database.Close()
	service := newTestService(t, database, newFakeClock(), &incrementingReader{})
	password := []byte("correct horse battery staple")
	if err := service.Bootstrap(ctx, password); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE administrator SET password_verifier = ?", "$argon2id$v=999$bad"); err != nil {
		t.Fatalf("corrupt verifier fixture: %v", err)
	}
	if _, err := service.Authenticate(ctx, password); !errors.Is(err, ErrVerifierUnsupported) {
		t.Fatalf("Authenticate() error = %v, want ErrVerifierUnsupported", err)
	}
}

func TestProductionArgon2Policy(t *testing.T) {
	t.Parallel()

	if defaultPasswordParameters.memory != 64*1024 ||
		defaultPasswordParameters.iterations != 3 ||
		defaultPasswordParameters.parallelism != 2 ||
		argon2.Version != 19 {
		t.Fatalf("production Argon2id policy changed: %+v version=%d", defaultPasswordParameters, argon2.Version)
	}
}
