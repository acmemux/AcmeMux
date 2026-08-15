//go:build linux

package main

import (
	"errors"
	"testing"
)

const zeroPrivilegeStatus = "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000 27\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n"

func TestValidateServicePrivilegesRequiresNonRootWithNoCapabilities(t *testing.T) {
	t.Parallel()
	if err := validateServicePrivileges(1000, 1000, []byte(zeroPrivilegeStatus)); err != nil {
		t.Fatalf("unprivileged process rejected: %v", err)
	}
	emptyGroups := stringReplaceOnce(zeroPrivilegeStatus, "Groups:\t1000 27", "Groups:\t")
	if err := validateServicePrivileges(1000, 1000, []byte(emptyGroups)); err != nil {
		t.Fatalf("process with no supplementary groups rejected: %v", err)
	}
	tests := []struct {
		name   string
		uid    int
		gid    int
		status string
	}{
		{name: "root uid", uid: 0, gid: 1000, status: zeroPrivilegeStatus},
		{name: "real uid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Uid:\t1000\t1000\t1000\t1000", "Uid:\t0\t1000\t1000\t1000")},
		{name: "effective uid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t0\t1000\t1000")},
		{name: "saved uid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000\t0\t1000")},
		{name: "filesystem uid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000\t1000\t0")},
		{name: "effective uid mismatch", uid: 1001, gid: 1000, status: zeroPrivilegeStatus},
		{name: "missing uid", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Uid:\t1000\t1000\t1000\t1000\n", "")},
		{name: "duplicate uid", uid: 1000, gid: 1000, status: zeroPrivilegeStatus + "Uid:\t1000\t1000\t1000\t1000\n"},
		{name: "root gid", uid: 1000, gid: 0, status: zeroPrivilegeStatus},
		{name: "real gid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t0\t1000\t1000\t1000")},
		{name: "effective gid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t0\t1000\t1000")},
		{name: "saved gid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t0\t1000")},
		{name: "filesystem gid root", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t1000\t0")},
		{name: "effective gid mismatch", uid: 1000, gid: 1001, status: zeroPrivilegeStatus},
		{name: "malformed gid count", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t1000")},
		{name: "missing gid", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Gid:\t1000\t1000\t1000\t1000\n", "")},
		{name: "duplicate gid", uid: 1000, gid: 1000, status: zeroPrivilegeStatus + "Gid:\t1000\t1000\t1000\t1000\n"},
		{name: "supplementary root group", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Groups:\t1000 27", "Groups:\t1000 0 27")},
		{name: "malformed supplementary group", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Groups:\t1000 27", "Groups:\t1000 operator")},
		{name: "oversized supplementary group", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Groups:\t1000 27", "Groups:\t4294967296")},
		{name: "missing groups", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "Groups:\t1000 27\n", "")},
		{name: "duplicate groups", uid: 1000, gid: 1000, status: zeroPrivilegeStatus + "Groups:\t1000\n"},
		{name: "inheritable", uid: 1000, gid: 1000, status: replaceCapability(zeroPrivilegeStatus, "CapInh", "0000000000000400")},
		{name: "permitted", uid: 1000, gid: 1000, status: replaceCapability(zeroPrivilegeStatus, "CapPrm", "0000000000000400")},
		{name: "effective", uid: 1000, gid: 1000, status: replaceCapability(zeroPrivilegeStatus, "CapEff", "0000000000000400")},
		{name: "ambient", uid: 1000, gid: 1000, status: replaceCapability(zeroPrivilegeStatus, "CapAmb", "0000000000000400")},
		{name: "missing capability", uid: 1000, gid: 1000, status: stringReplaceOnce(zeroPrivilegeStatus, "CapAmb:\t0000000000000000\n", "")},
		{name: "malformed capability", uid: 1000, gid: 1000, status: replaceCapability(zeroPrivilegeStatus, "CapEff", "not-hex")},
		{name: "oversized capability", uid: 1000, gid: 1000, status: replaceCapability(zeroPrivilegeStatus, "CapEff", "00000000000000000")},
		{name: "duplicate capability", uid: 1000, gid: 1000, status: zeroPrivilegeStatus + "CapEff:\t0000000000000000\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateServicePrivileges(test.uid, test.gid, []byte(test.status)); !errors.Is(err, errPrivilegedService) {
				t.Fatalf("validateServicePrivileges() error = %v", err)
			}
		})
	}
}

func replaceCapability(status, name, value string) string {
	old := name + ":\t0000000000000000"
	return stringReplaceOnce(status, old, name+":\t"+value)
}

func stringReplaceOnce(value, old, replacement string) string {
	for index := 0; index+len(old) <= len(value); index++ {
		if value[index:index+len(old)] == old {
			return value[:index] + replacement + value[index+len(old):]
		}
	}
	return value
}
