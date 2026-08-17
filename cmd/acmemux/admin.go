package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/acmemux/AcmeMux/internal/identity"
	"github.com/acmemux/AcmeMux/internal/state"
)

const administratorCommandTimeout = 30 * time.Second

type administratorEnvironment struct {
	getenv         func(string) string
	output         io.Writer
	promptPassword func(string) ([]byte, error)
}

func defaultAdministratorEnvironment() administratorEnvironment {
	return administratorEnvironment{
		getenv: os.Getenv,
		output: os.Stdout,
		promptPassword: func(prompt string) ([]byte, error) {
			return readTerminalPassword(os.Stdin, os.Stderr, prompt, term.IsTerminal, term.ReadPassword)
		},
	}
}

func readTerminalPassword(
	input *os.File,
	output io.Writer,
	prompt string,
	isTerminal func(int) bool,
	readPassword func(int) ([]byte, error),
) ([]byte, error) {
	fileDescriptor := int(input.Fd())
	if !isTerminal(fileDescriptor) {
		return nil, errors.New("administrator password input requires a controlling terminal")
	}
	if _, err := fmt.Fprint(output, prompt); err != nil {
		return nil, errors.New("write administrator password prompt")
	}
	password, err := readPassword(fileDescriptor)
	_, _ = fmt.Fprintln(output)
	if err != nil {
		return nil, errors.New("read administrator password")
	}
	return password, nil
}

func runAdministrator(arguments []string, environment administratorEnvironment) error {
	if len(arguments) == 0 {
		return errors.New("an administrator command is required: bootstrap, reset-password, or revoke-sessions")
	}
	if environment.getenv == nil || environment.output == nil || environment.promptPassword == nil {
		return errors.New("administrator command environment is incomplete")
	}
	command := arguments[0]
	if command != "bootstrap" && command != "reset-password" && command != "revoke-sessions" {
		return errors.New("unknown administrator command: expected bootstrap, reset-password, or revoke-sessions")
	}
	stateDirectory, err := administratorStateDirectory(command, arguments[1:], environment.getenv)
	if err != nil {
		return err
	}

	database, err := state.Open(stateDirectory)
	if err != nil {
		return fmt.Errorf("open application state: %w", err)
	}
	defer database.Close()
	service, err := identity.New(database)
	if err != nil {
		return fmt.Errorf("initialize administrator identity: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), administratorCommandTimeout)
	defer cancel()

	switch command {
	case "bootstrap":
		password, err := confirmedPassword(environment.promptPassword)
		if err != nil {
			return err
		}
		defer clear(password)
		if err := service.Bootstrap(ctx, password); err != nil {
			return fmt.Errorf("bootstrap administrator: %w", err)
		}
		if _, err := fmt.Fprintln(environment.output, "Administrator initialized."); err != nil {
			return errors.New("write administrator command result")
		}
	case "reset-password":
		password, err := confirmedPassword(environment.promptPassword)
		if err != nil {
			return err
		}
		defer clear(password)
		if err := service.ResetPassword(ctx, password); err != nil {
			return fmt.Errorf("replace administrator password: %w", err)
		}
		if _, err := fmt.Fprintln(environment.output, "Administrator password replaced and all sessions revoked."); err != nil {
			return errors.New("write administrator command result")
		}
	case "revoke-sessions":
		if err := service.RevokeSessions(ctx); err != nil {
			return fmt.Errorf("revoke administrator sessions: %w", err)
		}
		if _, err := fmt.Fprintln(environment.output, "All administrator sessions revoked."); err != nil {
			return errors.New("write administrator command result")
		}
	}
	return nil
}

func administratorStateDirectory(command string, arguments []string, getenv func(string) string) (string, error) {
	stateDefault := getenv("ACMEMUX_STATE_DIRECTORY")
	if stateDefault == "" {
		stateDefault = "./var"
	}
	if len(stateDefault) > 4096 {
		return "", errors.New("ACMEMUX_STATE_DIRECTORY exceeds 4096 bytes")
	}
	flags := flag.NewFlagSet("acmemux admin "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDirectory := flags.String("state-dir", stateDefault, "application state directory")
	if err := flags.Parse(arguments); err != nil {
		return "", errors.New("invalid administrator command options")
	}
	if flags.NArg() != 0 {
		return "", errors.New("unexpected positional administrator command arguments")
	}
	if *stateDirectory == "" || len(*stateDirectory) > 4096 {
		return "", errors.New("state directory must be between 1 and 4096 bytes")
	}
	absolute, err := filepath.Abs(*stateDirectory)
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	return absolute, nil
}

func confirmedPassword(prompt func(string) ([]byte, error)) ([]byte, error) {
	password, err := prompt("New administrator password: ")
	if err != nil {
		return nil, err
	}
	confirmation, err := prompt("Confirm administrator password: ")
	if err != nil {
		clear(password)
		return nil, err
	}
	defer clear(confirmation)
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		clear(password)
		return nil, errors.New("administrator password confirmation does not match")
	}
	return password, nil
}
