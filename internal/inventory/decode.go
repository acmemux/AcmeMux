package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	legoExpirationLayout = "2006-01-02 15:04:05 -0700 MST"
	maximumNameBytes     = 255
	maximumDNSNameBytes  = 253
	maximumIssuerBytes   = 4096
	maximumNamesPerCert  = 100
)

type upstreamCertificate struct {
	Name           string   `json:"name"`
	Domains        []string `json:"domains"`
	IPs            []string `json:"ips"`
	ExpirationDate string   `json:"expirationDate"`
	Expired        *bool    `json:"expired"`
	Issuer         string   `json:"issuer"`
	Path           string   `json:"path"`
}

func decodeInventory(output []byte, audit treeAudit, storagePath string, maximumCertificates int) ([]Certificate, error) {
	trimmed := bytes.TrimSpace(output)
	if bytes.Equal(trimmed, []byte("null")) {
		if len(audit.expected) != 0 {
			return nil, &Error{Code: CodeMalformedOutput, Detail: "certificate inventory does not match native resource count"}
		}
		return []Certificate{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('[') {
		return nil, &Error{Code: CodeMalformedOutput, Detail: "certificate inventory is not a JSON array or null", Cause: err}
	}
	upstream := make([]upstreamCertificate, 0, min(maximumCertificates, 64))
	for decoder.More() {
		if len(upstream) >= maximumCertificates {
			return nil, &Error{Code: CodeCertificateLimit, Detail: "certificate inventory exceeds the configured limit"}
		}
		var candidate upstreamCertificate
		if err := decoder.Decode(&candidate); err != nil {
			return nil, &Error{Code: CodeMalformedOutput, Detail: "certificate inventory entry is malformed", Cause: err}
		}
		upstream = append(upstream, candidate)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return nil, &Error{Code: CodeMalformedOutput, Detail: "certificate inventory array is not complete", Cause: err}
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, &Error{Code: CodeMalformedOutput, Detail: "certificate inventory contains trailing data", Cause: err}
	}
	if len(upstream) != len(audit.expected) {
		return nil, &Error{Code: CodeMalformedOutput, Detail: "certificate inventory does not match native resource count"}
	}
	certificatesPath := certificateRoot(storagePath)
	certificates := make([]Certificate, 0, len(upstream))
	seenPaths := make(map[string]struct{}, len(upstream))
	seenNames := make(map[string]struct{}, len(upstream))
	for _, candidate := range upstream {
		if err := validateCandidateStrings(candidate); err != nil {
			return nil, err
		}
		if candidate.Expired == nil {
			return nil, &Error{Code: CodeMalformedOutput, Detail: "certificate entry omits the expired field"}
		}
		if err := validateCanonicalPath(candidate.Path); err != nil {
			return nil, &Error{Code: CodeMalformedOutput, Path: candidate.Path, Detail: "certificate path is not canonical", Cause: err}
		}
		relativePath, err := filepath.Rel(certificatesPath, candidate.Path)
		if err != nil || relativePath == "." || filepath.IsAbs(relativePath) || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
			return nil, &Error{Code: CodePathOutsideStorage, Path: candidate.Path, Detail: "certificate path is outside the adopted certificates directory", Cause: err}
		}
		if filepath.Ext(candidate.Path) != ".crt" {
			return nil, &Error{Code: CodeMalformedOutput, Path: candidate.Path, Detail: "certificate path does not use the native .crt extension"}
		}
		expectedName := strings.TrimSuffix(filepath.Base(candidate.Path), ".crt")
		if candidate.Name != expectedName {
			return nil, &Error{Code: CodeMalformedOutput, Path: candidate.Path, Detail: "certificate name does not match its native path"}
		}
		artifact, ok := audit.expected[candidate.Path]
		if !ok {
			return nil, &Error{Code: CodeMalformedOutput, Path: candidate.Path, Detail: "certificate path has no audited native resource"}
		}
		if _, duplicate := seenPaths[candidate.Path]; duplicate {
			return nil, &Error{Code: CodeDuplicate, Path: candidate.Path, Detail: "certificate path appears more than once"}
		}
		seenPaths[candidate.Path] = struct{}{}
		if _, duplicate := seenNames[candidate.Name]; duplicate {
			return nil, &Error{Code: CodeDuplicate, Detail: "certificate name appears more than once"}
		}
		seenNames[candidate.Name] = struct{}{}

		expiresAt, err := parseLegoExpiration(candidate.ExpirationDate)
		if err != nil {
			return nil, &Error{Code: CodeMalformedOutput, Path: candidate.Path, Detail: "certificate expiration is not the exact UTC lego format", Cause: err}
		}
		certificates = append(certificates, Certificate{
			Name:       candidate.Name,
			DNSNames:   append([]string{}, candidate.Domains...),
			Issuer:     candidate.Issuer,
			ExpiresAt:  expiresAt,
			NativePath: candidate.Path,
			Artifact:   artifact.metadata(),
		})
	}
	sort.Slice(certificates, func(first, second int) bool {
		return certificates[first].NativePath < certificates[second].NativePath
	})
	return certificates, nil
}

func validateCandidateStrings(candidate upstreamCertificate) error {
	if err := validateBoundedText(candidate.Name, "certificate name", 1, maximumNameBytes); err != nil {
		return err
	}
	if err := validateBoundedText(candidate.Issuer, "certificate issuer", 1, maximumIssuerBytes); err != nil {
		return err
	}
	if err := validateBoundedText(candidate.ExpirationDate, "certificate expiration", 1, 64); err != nil {
		return err
	}
	if len(candidate.Domains) > maximumNamesPerCert {
		return &Error{Code: CodeMalformedOutput, Detail: "certificate has too many DNS names"}
	}
	seenDomains := make(map[string]struct{}, len(candidate.Domains))
	for _, domain := range candidate.Domains {
		if err := validateBoundedText(domain, "certificate DNS name", 1, maximumDNSNameBytes); err != nil {
			return err
		}
		if _, duplicate := seenDomains[domain]; duplicate {
			return &Error{Code: CodeDuplicate, Detail: "certificate DNS name appears more than once"}
		}
		seenDomains[domain] = struct{}{}
	}
	if len(candidate.IPs) > maximumNamesPerCert {
		return &Error{Code: CodeMalformedOutput, Detail: "certificate has too many IP names"}
	}
	seenIPs := make(map[string]struct{}, len(candidate.IPs))
	for _, address := range candidate.IPs {
		if len(address) == 0 || len(address) > net.IPv6len*4 || net.ParseIP(address) == nil {
			return &Error{Code: CodeMalformedOutput, Detail: "certificate contains a malformed IP name"}
		}
		if _, duplicate := seenIPs[address]; duplicate {
			return &Error{Code: CodeDuplicate, Detail: "certificate IP name appears more than once"}
		}
		seenIPs[address] = struct{}{}
	}
	return nil
}

func validateBoundedText(value, field string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || strings.IndexFunc(value, invalidPathCharacter) >= 0 {
		return &Error{Code: CodeMalformedOutput, Detail: fmt.Sprintf("%s is missing, invalid, or too long", field)}
	}
	return nil
}

func parseLegoExpiration(value string) (time.Time, error) {
	parsed, err := time.Parse(legoExpirationLayout, value)
	if err != nil {
		return time.Time{}, err
	}
	zone, offset := parsed.Zone()
	if zone != "UTC" || offset != 0 || parsed.Format(legoExpirationLayout) != value {
		return time.Time{}, fmt.Errorf("expiration is not canonical UTC")
	}
	return parsed.UTC(), nil
}
