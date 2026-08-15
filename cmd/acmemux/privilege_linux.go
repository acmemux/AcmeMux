//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var errPrivilegedService = errors.New("serve requires non-root process and group identities with no inherited, permitted, effective, or ambient Linux capabilities")

var requiredCapabilityFields = []string{"CapInh", "CapPrm", "CapEff", "CapAmb"}

func requireUnprivilegedServiceProcess() error {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("inspect service privileges: %w", err)
	}
	return validateServicePrivileges(os.Geteuid(), os.Getegid(), status)
}

func validateServicePrivileges(effectiveUID, effectiveGID int, status []byte) error {
	if effectiveUID == 0 || effectiveGID == 0 {
		return errPrivilegedService
	}
	values := make(map[string]uint64, len(requiredCapabilityFields))
	uidSeen, gidSeen, groupsSeen := false, false, false
	for _, line := range strings.Split(string(status), "\n") {
		name, encoded, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if name == "Uid" {
			if uidSeen || !validProcessIDs(effectiveUID, strings.Fields(encoded)) {
				return errPrivilegedService
			}
			uidSeen = true
			continue
		}
		if name == "Gid" {
			if gidSeen || !validProcessIDs(effectiveGID, strings.Fields(encoded)) {
				return errPrivilegedService
			}
			gidSeen = true
			continue
		}
		if name == "Groups" {
			if groupsSeen || !validSupplementaryGroups(strings.Fields(encoded)) {
				return errPrivilegedService
			}
			groupsSeen = true
			continue
		}
		if !containsCapabilityField(name) {
			continue
		}
		if _, duplicate := values[name]; duplicate {
			return errPrivilegedService
		}
		encoded = strings.TrimSpace(encoded)
		if encoded == "" || len(encoded) > 16 {
			return errPrivilegedService
		}
		value, err := strconv.ParseUint(encoded, 16, 64)
		if err != nil {
			return errPrivilegedService
		}
		values[name] = value
	}
	if !uidSeen || !gidSeen || !groupsSeen {
		return errPrivilegedService
	}
	for _, field := range requiredCapabilityFields {
		value, present := values[field]
		if !present || value != 0 {
			return errPrivilegedService
		}
	}
	return nil
}

func validProcessIDs(effectiveID int, fields []string) bool {
	if len(fields) != 4 {
		return false
	}
	var first uint64
	for index, field := range fields {
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil || value == 0 {
			return false
		}
		if index == 0 {
			first = value
		} else if value != first {
			return false
		}
	}
	return first == uint64(effectiveID)
}

func validSupplementaryGroups(fields []string) bool {
	// An empty Groups field is the valid Linux representation for a process
	// with no supplementary groups.
	for _, field := range fields {
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil || value == 0 {
			return false
		}
	}
	return true
}

func containsCapabilityField(value string) bool {
	for _, field := range requiredCapabilityFields {
		if value == field {
			return true
		}
	}
	return false
}
