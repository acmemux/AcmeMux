package runtime

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	releasePattern  = regexp.MustCompile(`^(?:v)?([0-9]+)\.([0-9]+)\.([0-9]+)$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	platformPattern = regexp.MustCompile(`^[a-z0-9]+$`)
)

// ParseVersionOutput strictly parses the one-line format emitted by upstream
// lego's version printer. It accepts official numeric releases and exact
// source revisions but no development aliases, ranges, or decorated commits.
func ParseVersionOutput(output []byte) (VersionIdentity, Platform, string, error) {
	if len(output) == 0 || len(output) > maximumVersionOutput {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "version output has an invalid length"}
	}
	for _, character := range output {
		if character == '\n' {
			continue
		}
		if character < 0x20 || character > 0x7e {
			return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "version output contains non-ASCII or control data"}
		}
	}
	if output[len(output)-1] != '\n' || strings.Count(string(output), "\n") != 1 {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "version output must be exactly one newline-terminated line"}
	}

	line := string(output[:len(output)-1])
	const prefix = "lego version "
	if !strings.HasPrefix(line, prefix) {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "version output has an unexpected prefix"}
	}
	fields := strings.Split(strings.TrimPrefix(line, prefix), " ")
	if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "version output has an unexpected field count"}
	}
	platformFields := strings.Split(fields[1], "/")
	if len(platformFields) != 2 || !platformPattern.MatchString(platformFields[0]) || !platformPattern.MatchString(platformFields[1]) {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "version output has an invalid platform"}
	}

	var identity VersionIdentity
	if match := releasePattern.FindStringSubmatch(fields[0]); match != nil {
		for _, component := range match[1:] {
			if len(component) > 1 && component[0] == '0' {
				return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "release identity is not canonical semantic version text"}
			}
		}
		identity = VersionIdentity{Kind: VersionRelease, Value: fmt.Sprintf("v%s.%s.%s", match[1], match[2], match[3])}
	} else if revisionPattern.MatchString(fields[0]) {
		identity = VersionIdentity{Kind: VersionRevision, Value: fields[0]}
	} else {
		return VersionIdentity{}, Platform{}, "", &Error{Code: CodeMalformedVersion, Detail: "version identity is neither an official release nor an exact source revision"}
	}

	return identity, Platform{OS: platformFields[0], Arch: platformFields[1]}, line, nil
}
