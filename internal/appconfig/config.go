// Package appconfig loads and validates bounded service configuration.
package appconfig

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
)

const (
	defaultListenAddress  = "127.0.0.1:8080"
	defaultStateDirectory = "./var"
	maximumValueLength    = 4096
)

// Config contains the process-level settings needed by the foundation service.
type Config struct {
	ListenAddress  string
	StateDirectory string
}

// Load parses command-line arguments over bounded environment defaults.
func Load(arguments []string, getenv func(string) string) (Config, error) {
	listenDefault, err := environmentDefault(getenv, "ACMEMUX_LISTEN_ADDRESS", defaultListenAddress)
	if err != nil {
		return Config{}, err
	}
	stateDefault, err := environmentDefault(getenv, "ACMEMUX_STATE_DIRECTORY", defaultStateDirectory)
	if err != nil {
		return Config{}, err
	}

	flags := flag.NewFlagSet("acmemux serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", listenDefault, "loopback listen address")
	stateDirectory := flags.String("state-dir", stateDefault, "application state directory")
	if err := flags.Parse(arguments); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateLoopback(*listen); err != nil {
		return Config{}, err
	}
	if *stateDirectory == "" || len(*stateDirectory) > maximumValueLength {
		return Config{}, errors.New("state directory must be between 1 and 4096 bytes")
	}
	absoluteStateDirectory, err := filepath.Abs(*stateDirectory)
	if err != nil {
		return Config{}, fmt.Errorf("resolve state directory: %w", err)
	}

	return Config{ListenAddress: *listen, StateDirectory: absoluteStateDirectory}, nil
}

func environmentDefault(getenv func(string) string, name, fallback string) (string, error) {
	value := getenv(name)
	if value == "" {
		return fallback, nil
	}
	if len(value) > maximumValueLength {
		return "", fmt.Errorf("%s exceeds 4096 bytes", name)
	}
	return value, nil
}

func validateLoopback(address string) error {
	if len(address) > maximumValueLength {
		return errors.New("listen address exceeds 4096 bytes")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("listen address must include a loopback host and port: %q", address)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address must be loopback-only: %q", address)
	}
	return nil
}
