package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/state"
)

func TestAdministratorCommandsBootstrapResetAndRevoke(t *testing.T) {
	directory := t.TempDir()
	firstPassword := "first administrator password"
	secondPassword := "second administrator password"
	var output bytes.Buffer
	environment := administratorEnvironment{
		getenv: func(string) string { return "" },
		output: &output,
		promptPassword: passwordSequence(
			firstPassword,
			firstPassword,
			secondPassword,
			secondPassword,
		),
	}

	if err := runAdministrator([]string{"bootstrap", "--state-dir", directory}, environment); err != nil {
		t.Fatalf("bootstrap error = %v", err)
	}
	verifierBefore, epochBefore := administratorState(t, directory)
	insertTestSession(t, directory, epochBefore)

	if err := runAdministrator([]string{"reset-password", "--state-dir", directory}, environment); err != nil {
		t.Fatalf("reset-password error = %v", err)
	}
	verifierAfter, epochAfter := administratorState(t, directory)
	if verifierAfter == verifierBefore {
		t.Fatal("reset-password did not replace the verifier")
	}
	if epochAfter != epochBefore+1 {
		t.Fatalf("epoch after reset = %d, want %d", epochAfter, epochBefore+1)
	}
	expectSessionCount(t, directory, 0)
	insertTestSession(t, directory, epochAfter)

	if err := runAdministrator([]string{"revoke-sessions", "--state-dir", directory}, environment); err != nil {
		t.Fatalf("revoke-sessions error = %v", err)
	}
	_, epochRevoked := administratorState(t, directory)
	if epochRevoked != epochAfter+1 {
		t.Fatalf("epoch after revocation = %d, want %d", epochRevoked, epochAfter+1)
	}
	expectSessionCount(t, directory, 0)

	for _, message := range []string{
		"Administrator initialized.",
		"Administrator password replaced and all sessions revoked.",
		"All administrator sessions revoked.",
	} {
		if !strings.Contains(output.String(), message) {
			t.Errorf("command output missing %q", message)
		}
	}
}

func TestAdministratorCommandRejectsPasswordArgumentWithoutPrompt(t *testing.T) {
	const canary = "accidentally-pasted-password"
	prompts := 0
	environment := administratorEnvironment{
		getenv: func(string) string { return "" },
		output: &bytes.Buffer{},
		promptPassword: func(string) ([]byte, error) {
			prompts++
			return []byte("must not be read"), nil
		},
	}

	err := runAdministrator(
		[]string{"bootstrap", "--state-dir", t.TempDir(), "--" + canary},
		environment,
	)
	if err == nil {
		t.Fatal("bootstrap accepted a password argument")
	}
	if prompts != 0 {
		t.Fatalf("password prompt count = %d, want 0", prompts)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("rejected password-like option was reflected in error: %q", err)
	}
}

func TestAdministratorCommandDoesNotReflectRejectedPositionalArgument(t *testing.T) {
	const canary = "accidentally-pasted-administrator-password"
	environment := administratorEnvironment{
		getenv:         func(string) string { return "" },
		output:         &bytes.Buffer{},
		promptPassword: func(string) ([]byte, error) { return nil, context.Canceled },
	}

	err := runAdministrator(
		[]string{"bootstrap", "--state-dir", t.TempDir(), canary},
		environment,
	)
	if err == nil {
		t.Fatal("bootstrap accepted a positional argument")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("rejected positional argument was reflected in error: %q", err)
	}

	for name, action := range map[string]func() error{
		"top-level command": func() error { return run([]string{canary}) },
		"administrator command": func() error {
			return runAdministrator([]string{canary}, environment)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := action()
			if err == nil {
				t.Fatal("unknown command was accepted")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("unknown command was reflected in error: %q", err)
			}
		})
	}
}

func TestConfirmedPasswordClearsMismatch(t *testing.T) {
	first := []byte("first administrator password")
	second := []byte("other administrator password")
	index := 0
	_, err := confirmedPassword(func(string) ([]byte, error) {
		index++
		if index == 1 {
			return first, nil
		}
		return second, nil
	})
	if err == nil {
		t.Fatal("confirmedPassword error = nil, want mismatch")
	}
	if !allZero(first) || !allZero(second) {
		t.Fatal("mismatched password buffers were not cleared")
	}
}

func TestDefaultPasswordPromptRejectsRedirectedInput(t *testing.T) {
	input, err := os.CreateTemp(t.TempDir(), "password-input")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer input.Close()
	_, err = readTerminalPassword(
		input,
		&bytes.Buffer{},
		"Password: ",
		func(int) bool { return false },
		func(int) ([]byte, error) { return []byte("must not be read"), nil },
	)
	if err == nil || !strings.Contains(err.Error(), "controlling terminal") {
		t.Fatalf("prompt error = %v, want controlling terminal requirement", err)
	}
}

func passwordSequence(values ...string) func(string) ([]byte, error) {
	index := 0
	return func(string) ([]byte, error) {
		if index >= len(values) {
			return nil, context.Canceled
		}
		value := []byte(values[index])
		index++
		return value, nil
	}
}

func administratorState(t *testing.T, directory string) (string, int64) {
	t.Helper()
	database, err := state.Open(directory)
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	defer database.Close()
	var verifier string
	var epoch int64
	if err := database.QueryRowContext(context.Background(), `
SELECT password_verifier, auth_epoch
FROM administrator
WHERE singleton_id = 1`).Scan(&verifier, &epoch); err != nil {
		t.Fatalf("query administrator state: %v", err)
	}
	return verifier, epoch
}

func insertTestSession(t *testing.T, directory string, epoch int64) {
	t.Helper()
	database, err := state.Open(directory)
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	defer database.Close()
	now := time.Now().UTC().Unix()
	if _, err := database.ExecContext(context.Background(), `
INSERT INTO identity_sessions (
    administrator_id, auth_epoch, current_token_hash, csrf_token_hash,
    created_at_unix, last_seen_at_unix, idle_expires_at_unix,
    absolute_expires_at_unix, rotate_after_unix
) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		epoch,
		bytes.Repeat([]byte{1}, 32),
		bytes.Repeat([]byte{2}, 32),
		now,
		now,
		now+60,
		now+120,
		now+30,
	); err != nil {
		t.Fatalf("insert test session: %v", err)
	}
}

func expectSessionCount(t *testing.T, directory string, want int) {
	t.Helper()
	database, err := state.Open(directory)
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM identity_sessions").Scan(&count); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != want {
		t.Fatalf("session count = %d, want %d", count, want)
	}
}

func allZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}
