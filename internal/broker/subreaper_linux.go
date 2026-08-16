//go:build linux

package broker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

const processGuardPrefix = "ACMEMUX_BROKER_PROCESS_GUARD"

var (
	subreaperOnce sync.Once
	subreaperErr  error
)

func ensureChildSubreaper() error {
	subreaperOnce.Do(func() {
		subreaperErr = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	})
	return subreaperErr
}

func newProcessGuard() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		clear(value)
		return "", fmt.Errorf("generate process guard: %w", err)
	}
	// Randomize the name, rather than only the value, so a caller-selected
	// manifest variable can never shadow the broker's lineage marker.
	guard := processGuardPrefix + "_" + hex.EncodeToString(value) + "=1"
	clear(value)
	return guard, nil
}
