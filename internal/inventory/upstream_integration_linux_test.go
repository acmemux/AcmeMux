//go:build linux

package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestRealUpstreamCertificateInventory(t *testing.T) {
	legoPath := os.Getenv("ACMEMUX_TEST_LEGO")
	if legoPath == "" {
		t.Skip("set ACMEMUX_TEST_LEGO to an explicit qualified lego executable")
	}
	if !filepath.IsAbs(legoPath) || filepath.Clean(legoPath) != legoPath {
		t.Fatal("ACMEMUX_TEST_LEGO must be a canonical absolute path")
	}

	fixture := newInventoryFixture(t, true)
	name := "integration.example"
	dnsNames := []string{name, "www.integration.example"}
	notAfter := time.Now().UTC().Truncate(time.Second).Add(48 * time.Hour)
	issuer := writeSelfSignedCertificate(t, fixture.certificatePath(name), dnsNames, notAfter)
	fixture.writeResource(t, name)

	prepared := &pathPrepared{path: legoPath}
	certificates, err := fixture.reader(t).Read(context.Background(), prepared, fixture.storage)
	if err != nil {
		t.Fatalf("Read() real upstream error = %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("Read() certificate count = %d, want 1", len(certificates))
	}
	certificate := certificates[0]
	if certificate.Name != name || !slices.Equal(certificate.DNSNames, dnsNames) {
		t.Fatalf("Read() identity = %#v", certificate)
	}
	if certificate.Issuer != issuer {
		t.Fatalf("Read() issuer = %q, want %q", certificate.Issuer, issuer)
	}
	if !certificate.ExpiresAt.Equal(notAfter) {
		t.Fatalf("Read() expiration = %v, want %v", certificate.ExpiresAt, notAfter)
	}
	if certificate.NativePath != fixture.certificatePath(name) {
		t.Fatalf("Read() native path = %q", certificate.NativePath)
	}
	if certificate.Artifact.UID != uint32(os.Geteuid()) || certificate.Artifact.GID != uint32(os.Getegid()) || certificate.Artifact.LinkCount != 1 {
		t.Fatalf("Read() artifact metadata = %#v", certificate.Artifact)
	}
	if !prepared.started || prepared.closeCount != 1 {
		t.Fatalf("prepared lifecycle = started %t, close %d", prepared.started, prepared.closeCount)
	}
}

func TestRealUpstreamEmptyNativeStorage(t *testing.T) {
	legoPath := os.Getenv("ACMEMUX_TEST_LEGO")
	if legoPath == "" {
		t.Skip("set ACMEMUX_TEST_LEGO to an explicit qualified lego executable")
	}
	if !filepath.IsAbs(legoPath) || filepath.Clean(legoPath) != legoPath {
		t.Fatal("ACMEMUX_TEST_LEGO must be a canonical absolute path")
	}
	fixture := newInventoryFixture(t, false)
	prepared := &pathPrepared{path: legoPath}
	certificates, err := fixture.reader(t).Read(context.Background(), prepared, fixture.storage)
	if err != nil {
		t.Fatalf("Read() empty real upstream storage error = %v", err)
	}
	if certificates == nil || len(certificates) != 0 {
		t.Fatalf("Read() = %#v, want non-nil empty slice", certificates)
	}
}

type pathPrepared struct {
	path       string
	started    bool
	closeCount int
}

func (prepared *pathPrepared) StartContext(
	ctx context.Context,
	configure func(*exec.Cmd) error,
	arguments ...string,
) (*exec.Cmd, error) {
	command := exec.CommandContext(ctx, prepared.path, arguments...)
	if err := configure(command); err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	prepared.started = true
	return command, nil
}

func (prepared *pathPrepared) Close() error {
	prepared.closeCount++
	return nil
}

func writeSelfSignedCertificate(t *testing.T, path string, dnsNames []string, notAfter time.Time) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: "AcmeMux Inventory Integration", Organization: []string{"AcmeMux Test"}}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             notAfter.Add(-72 * time.Hour),
		NotAfter:              notAfter,
		DNSNames:              slices.Clone(dnsNames),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	return subject.String()
}
