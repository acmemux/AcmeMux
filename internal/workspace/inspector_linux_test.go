//go:build linux

package workspace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectConventionalWorkspaceResolvesNativePaths(t *testing.T) {
	t.Parallel()

	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "working"), 0o700)
	storage := mkdir(t, filepath.Join(root, "storage"), 0o700)
	secrets := mkdir(t, filepath.Join(root, "secrets"), 0o700)
	dotenv := writeFile(t, filepath.Join(secrets, "provider.env"), []byte("TOKEN=do-not-retain\n"), 0o600)
	webroot := mkdir(t, filepath.Join(root, "public"), 0o700)
	configuration := writeFile(t, filepath.Join(working, ".lego.yml"), []byte(`
storage: ../storage
accounts:
  home:
    eab:
      hmacKey: do-not-retain-eab
challenges:
  cloud:
    dns:
      provider: cloudflare
      envFile: ../secrets/./provider.env
  site:
    http:
      webroot: ../unused/../public
`), 0o600)

	review := inspect(t, Request{WorkingDirectory: working})
	if !review.Adoptable {
		t.Fatalf("review is not adoptable: %#v", review.Diagnostics)
	}
	if review.ConfigurationSource != ConfigurationConventionalYML || review.Configuration.Path != configuration {
		t.Fatalf("configuration evidence = %#v", review.Configuration)
	}
	if review.Storage.Path != storage || review.Storage.Reference != "../storage" {
		t.Fatalf("storage evidence = %#v", review.Storage)
	}
	if len(review.DotenvFiles) != 1 || review.DotenvFiles[0].Path != dotenv || review.DotenvFiles[0].Reference != "../secrets/./provider.env" {
		t.Fatalf("dotenv evidence = %#v", review.DotenvFiles)
	}
	if len(review.Webroots) != 1 || review.Webroots[0].Path != webroot {
		t.Fatalf("webroot evidence = %#v", review.Webroots)
	}
	if review.ReviewedEvidenceSHA256 == "" || review.ReviewedEvidenceSHA256 != ReviewFingerprint(review) {
		t.Fatalf("review fingerprint = %q", review.ReviewedEvidenceSHA256)
	}
	for _, path := range review.AllPaths() {
		if !path.Exists || len(path.Components) < 2 || path.Components[0].Path != "/" {
			t.Fatalf("incomplete evidence for %s: %#v", path.Role, path)
		}
	}
	formatted := fmt.Sprintf("%#v", review)
	for _, secret := range []string{"do-not-retain", "TOKEN="} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("review retained confidential YAML or dotenv content %q", secret)
		}
	}
}

func TestVerifyAllowsNativeChildDirectoryChurnWithoutLosingSelectedIdentity(t *testing.T) {
	t.Parallel()
	working := secureTempDir(t)
	storage := mkdir(t, filepath.Join(working, "storage"), 0o700)
	webroot := mkdir(t, filepath.Join(working, "webroot"), 0o700)
	writeFile(t, filepath.Join(working, ".lego.yml"), []byte("storage: storage\nchallenges:\n  http:\n    http:\n      webroot: webroot\n"), 0o600)
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
	if err != nil || !review.Adoptable {
		t.Fatalf("Inspect() review = %#v, error = %v", review, err)
	}
	mkdir(t, filepath.Join(storage, "accounts"), 0o700)
	mkdir(t, filepath.Join(webroot, ".well-known"), 0o700)
	current, err := inspector.Verify(context.Background(), review)
	if err != nil {
		t.Fatalf("Verify() rejected native child-directory churn: %v", err)
	}
	if current.Storage.Inode != review.Storage.Inode || current.Webroots[0].Inode != review.Webroots[0].Inode {
		t.Fatal("selected directory identity changed during churn test")
	}
}

func TestInspectUsesConventionalNamePrecedence(t *testing.T) {
	t.Parallel()

	working := secureTempDir(t)
	mkdir(t, filepath.Join(working, "first"), 0o700)
	mkdir(t, filepath.Join(working, "second"), 0o700)
	yml := writeFile(t, filepath.Join(working, ".lego.yml"), []byte("storage: first\n"), 0o600)
	writeFile(t, filepath.Join(working, ".lego.yaml"), []byte("storage: second\n"), 0o600)

	review := inspect(t, Request{WorkingDirectory: working})
	if review.Configuration.Path != yml || review.Storage.Path != filepath.Join(working, "first") {
		t.Fatalf("precedence review = %#v", review)
	}
	if !hasDiagnostic(review, CodeConfigurationPrecedence, SeverityNotice) || !review.Adoptable {
		t.Fatalf("diagnostics = %#v", review.Diagnostics)
	}
}

func TestInspectSkipsConventionalDirectoryLikeUpstream(t *testing.T) {
	t.Parallel()

	working := secureTempDir(t)
	mkdir(t, filepath.Join(working, ".lego.yml"), 0o700)
	storage := mkdir(t, filepath.Join(working, "storage"), 0o700)
	yaml := writeFile(t, filepath.Join(working, ".lego.yaml"), []byte("storage: storage\n"), 0o600)

	review := inspect(t, Request{WorkingDirectory: working})
	if review.ConfigurationSource != ConfigurationConventionalYAML ||
		review.Configuration.Path != yaml || review.Storage.Path != storage || !review.Adoptable {
		t.Fatalf("directory fallback review = %#v", review)
	}
	if hasDiagnostic(review, CodeConfigurationPrecedence, SeverityNotice) {
		t.Fatalf("directory must not count as a conventional configuration: %#v", review.Diagnostics)
	}
}

func TestInspectDoesNotReplaceConventionalAuditFailureWithMissing(t *testing.T) {
	t.Parallel()

	working := secureTempDir(t)
	for componentCount(working) < maximumRecordedPathComponents {
		working = mkdir(t, filepath.Join(working, "d"), 0o700)
	}
	writeFile(t, filepath.Join(working, ".lego.yaml"), []byte("storage: storage\n"), 0o600)

	review := inspect(t, Request{WorkingDirectory: working})
	if review.Configuration.Path != filepath.Join(working, ".lego.yml") || review.Configuration.Type != PathTypeUnknown {
		t.Fatalf("configuration evidence = %#v", review.Configuration)
	}
	if !hasDiagnostic(review, CodePathTooDeep, SeverityBlocking) || hasDiagnostic(review, CodeConfigurationMissing, SeverityBlocking) {
		t.Fatalf("diagnostics = %#v", review.Diagnostics)
	}
}

func componentCount(path string) int {
	trimmed := strings.TrimPrefix(path, string(filepath.Separator))
	if trimmed == "" {
		return 1
	}
	return 1 + len(strings.Split(trimmed, string(filepath.Separator)))
}

func TestInspectExplicitConfigurationUsesEffectiveWorkingDirectory(t *testing.T) {
	t.Parallel()

	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "cwd"), 0o500)
	configurationDirectory := mkdir(t, filepath.Join(root, "configuration"), 0o700)
	storage := mkdir(t, filepath.Join(root, "native"), 0o700)
	configuration := writeFile(t, filepath.Join(configurationDirectory, "lego.yaml"), []byte("storage: ../native\n"), 0o600)

	review := inspect(t, Request{WorkingDirectory: working, ConfigurationPath: configuration})
	if review.ConfigurationSource != ConfigurationExplicit || review.Storage.Path != storage {
		t.Fatalf("explicit review = %#v", review)
	}
	if !review.Adoptable {
		t.Fatalf("read-only working directory should be adoptable with external managed paths: %#v", review.Diagnostics)
	}
}

func TestInspectReportsMissingAndUnsafeCandidatesWithPartialEvidence(t *testing.T) {
	t.Parallel()

	working := secureTempDir(t)
	review := inspect(t, Request{WorkingDirectory: working})
	if review.Adoptable || review.Configuration.Exists || review.Configuration.Path != filepath.Join(working, ".lego.yml") {
		t.Fatalf("missing review = %#v", review)
	}
	if !hasDiagnostic(review, CodeConfigurationMissing, SeverityBlocking) {
		t.Fatalf("diagnostics = %#v", review.Diagnostics)
	}

	target := mkdir(t, filepath.Join(working, "real"), 0o700)
	writeFile(t, filepath.Join(target, ".lego.yml"), []byte("storage: .lego\n"), 0o600)
	if err := os.Symlink(target, filepath.Join(working, "linked")); err != nil {
		t.Fatal(err)
	}
	review = inspect(t, Request{WorkingDirectory: filepath.Join(working, "linked")})
	if review.Adoptable || !hasDiagnostic(review, CodeSymlinkNotAllowed, SeverityBlocking) {
		t.Fatalf("symlink review = %#v", review)
	}
}

func TestInspectRejectsConfidentialPermissionsAndHardlinks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		set  func(t *testing.T, working string)
		code ErrorCode
	}{
		{
			name: "configuration mode 0644",
			set: func(t *testing.T, working string) {
				mkdir(t, filepath.Join(working, ".lego"), 0o700)
				writeFile(t, filepath.Join(working, ".lego.yml"), []byte("{}\n"), 0o644)
			},
			code: CodePathPermissionsUnsafe,
		},
		{
			name: "dotenv mode 0644",
			set: func(t *testing.T, working string) {
				mkdir(t, filepath.Join(working, ".lego"), 0o700)
				writeFile(t, filepath.Join(working, "credentials.env"), []byte("TOKEN=x\n"), 0o644)
				writeFile(t, filepath.Join(working, ".lego.yml"), []byte("challenges:\n  dns:\n    dns:\n      envFile: credentials.env\n"), 0o600)
			},
			code: CodePathPermissionsUnsafe,
		},
		{
			name: "hardlinked configuration",
			set: func(t *testing.T, working string) {
				mkdir(t, filepath.Join(working, ".lego"), 0o700)
				path := writeFile(t, filepath.Join(working, ".lego.yml"), []byte("{}\n"), 0o600)
				if err := os.Link(path, filepath.Join(working, "another-link")); err != nil {
					t.Fatal(err)
				}
			},
			code: CodePathHardlinkUnsafe,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			working := secureTempDir(t)
			test.set(t, working)
			review := inspect(t, Request{WorkingDirectory: working})
			if review.Adoptable || !hasDiagnostic(review, test.code, SeverityBlocking) {
				t.Fatalf("review = %#v", review)
			}
		})
	}
}

func TestInspectRejectsSymlinkedConfigurationAndReferencedFile(t *testing.T) {
	t.Parallel()

	t.Run("configuration", func(t *testing.T) {
		working := secureTempDir(t)
		mkdir(t, filepath.Join(working, ".lego"), 0o700)
		target := writeFile(t, filepath.Join(working, "target.yml"), []byte("{}\n"), 0o600)
		if err := os.Symlink(target, filepath.Join(working, ".lego.yml")); err != nil {
			t.Fatal(err)
		}
		review := inspect(t, Request{WorkingDirectory: working})
		if review.Adoptable || !hasDiagnostic(review, CodeSymlinkNotAllowed, SeverityBlocking) {
			t.Fatalf("review = %#v", review)
		}
	})

	t.Run("dotenv", func(t *testing.T) {
		working := secureTempDir(t)
		mkdir(t, filepath.Join(working, ".lego"), 0o700)
		target := writeFile(t, filepath.Join(working, "target.env"), []byte("TOKEN=x\n"), 0o600)
		if err := os.Symlink(target, filepath.Join(working, "credentials.env")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(working, ".lego.yml"), []byte("challenges:\n  dns:\n    dns:\n      envFile: credentials.env\n"), 0o600)
		review := inspect(t, Request{WorkingDirectory: working})
		if review.Adoptable || !hasDiagnostic(review, CodeSymlinkNotAllowed, SeverityBlocking) {
			t.Fatalf("review = %#v", review)
		}
	})
}

func TestInspectRequiresWritableReplacementParent(t *testing.T) {
	t.Parallel()

	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "working"), 0o700)
	mkdir(t, filepath.Join(working, ".lego"), 0o700)
	writeFile(t, filepath.Join(working, ".lego.yml"), []byte("{}\n"), 0o600)
	if err := os.Chmod(working, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(working, 0o700) })
	review := inspect(t, Request{WorkingDirectory: working})
	if review.Adoptable || !hasDiagnostic(review, CodePathReadOnly, SeverityBlocking) {
		t.Fatalf("review = %#v", review)
	}
	if !review.WorkingDirectory.Safe {
		t.Fatalf("working directory read/search should remain safe: %#v", review.WorkingDirectory)
	}
}

func TestInspectDistinguishesReadOnlyManagedDirectories(t *testing.T) {
	t.Parallel()

	working := secureTempDir(t)
	mkdir(t, filepath.Join(working, "storage"), 0o500)
	mkdir(t, filepath.Join(working, "webroot"), 0o500)
	writeFile(t, filepath.Join(working, ".lego.yml"), []byte("storage: storage\nchallenges:\n  http:\n    http:\n      webroot: webroot\n"), 0o600)
	review := inspect(t, Request{WorkingDirectory: working})
	if review.Adoptable || !hasDiagnostic(review, CodePathReadOnly, SeverityBlocking) {
		t.Fatalf("review = %#v", review)
	}
	if review.Storage.Access.Writable || review.Webroots[0].Access.Writable {
		t.Fatalf("access evidence = storage %#v webroot %#v", review.Storage.Access, review.Webroots[0].Access)
	}
}

func TestInspectReportsMissingWrongTypeAndUnsafeOwnership(t *testing.T) {
	t.Parallel()

	t.Run("missing storage", func(t *testing.T) {
		working := secureTempDir(t)
		writeFile(t, filepath.Join(working, ".lego.yml"), []byte("storage: missing\n"), 0o600)
		review := inspect(t, Request{WorkingDirectory: working})
		if review.Adoptable || review.Storage.Exists || !hasDiagnostic(review, CodePathMissing, SeverityBlocking) {
			t.Fatalf("review = %#v", review)
		}
	})

	t.Run("storage is a file", func(t *testing.T) {
		working := secureTempDir(t)
		writeFile(t, filepath.Join(working, "storage"), []byte("not a directory"), 0o600)
		writeFile(t, filepath.Join(working, ".lego.yml"), []byte("storage: storage\n"), 0o600)
		review := inspect(t, Request{WorkingDirectory: working})
		if review.Adoptable || review.Storage.Type != PathTypeRegular || !hasDiagnostic(review, CodePathTypeUnsafe, SeverityBlocking) {
			t.Fatalf("review = %#v", review)
		}
	})

	t.Run("owner differs from service", func(t *testing.T) {
		working := secureTempDir(t)
		mkdir(t, filepath.Join(working, ".lego"), 0o700)
		writeFile(t, filepath.Join(working, ".lego.yml"), []byte("{}\n"), 0o600)
		policy := DefaultPolicy()
		policy.EffectiveUID += 10000
		inspector, err := NewInspector(policy)
		if err != nil {
			t.Fatal(err)
		}
		review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
		if err != nil {
			t.Fatal(err)
		}
		if review.Adoptable || !hasDiagnostic(review, CodePathOwnerUntrusted, SeverityBlocking) {
			t.Fatalf("review = %#v", review)
		}
	})

	t.Run("writable traversal component", func(t *testing.T) {
		root := secureTempDir(t)
		working := mkdir(t, filepath.Join(root, "working"), 0o700)
		mkdir(t, filepath.Join(working, ".lego"), 0o700)
		writeFile(t, filepath.Join(working, ".lego.yml"), []byte("{}\n"), 0o600)
		if err := os.Chmod(root, 0o770); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
		review := inspect(t, Request{WorkingDirectory: working})
		if review.Adoptable || !hasDiagnostic(review, CodePathPermissionsUnsafe, SeverityBlocking) {
			t.Fatalf("review = %#v", review)
		}
	})
}

func TestInspectRejectsMalformedDuplicateAndOversizeYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		contents []byte
		limit    int64
		code     ErrorCode
	}{
		{name: "malformed", contents: []byte("challenges: [\n"), limit: 1024, code: CodeConfigurationMalformed},
		{name: "duplicate", contents: []byte("storage: one\nstorage: two\n"), limit: 1024, code: CodeConfigurationDuplicateKey},
		{name: "oversize", contents: []byte(strings.Repeat("#", 65)), limit: 64, code: CodeConfigurationTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			working := secureTempDir(t)
			writeFile(t, filepath.Join(working, ".lego.yml"), test.contents, 0o600)
			policy := DefaultPolicy()
			policy.MaxConfigurationBytes = test.limit
			inspector, err := NewInspector(policy)
			if err != nil {
				t.Fatal(err)
			}
			review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
			if err != nil {
				t.Fatal(err)
			}
			if review.Adoptable || !hasDiagnostic(review, test.code, SeverityBlocking) {
				t.Fatalf("review = %#v", review)
			}
		})
	}
}

func TestVerifyDetectsExternalChangeAndConventionalPriorityChange(t *testing.T) {
	t.Parallel()

	working := secureTempDir(t)
	mkdir(t, filepath.Join(working, "storage"), 0o700)
	configuration := writeFile(t, filepath.Join(working, ".lego.yaml"), []byte("storage: storage\n"), 0o600)
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
	if err != nil || !review.Adoptable {
		t.Fatalf("initial review = %#v, error = %v", review, err)
	}
	if _, err := inspector.Verify(context.Background(), review); err != nil {
		t.Fatalf("unchanged Verify() error = %v", err)
	}

	writeFile(t, configuration, []byte("storage: storage\n# changed\n"), 0o600)
	current, err := inspector.Verify(context.Background(), review)
	if CodeOf(err) != CodeReviewEvidenceChanged || current.Configuration.Path != configuration {
		t.Fatalf("changed Verify() review = %#v, error = %v", current, err)
	}

	review, err = inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(working, ".lego.yml"), []byte("storage: storage\n"), 0o600)
	current, err = inspector.Verify(context.Background(), review)
	if CodeOf(err) != CodeReviewEvidenceChanged || current.ConfigurationSource != ConfigurationConventionalYML {
		t.Fatalf("priority Verify() review = %#v, error = %v", current, err)
	}

	review = current
	if err := os.Remove(current.Configuration.Path); err != nil {
		t.Fatal(err)
	}
	current, err = inspector.Verify(context.Background(), review)
	if CodeOf(err) != CodeReviewEvidenceChanged || current.ConfigurationSource != ConfigurationConventionalYAML {
		t.Fatalf("disappearance Verify() review = %#v, error = %v", current, err)
	}
}

func TestReviewFingerprintIgnoresObservationTimeButCoversEvidence(t *testing.T) {
	t.Parallel()

	review := Review{
		ConfigurationSource: ConfigurationExplicit,
		WorkingDirectory:    PathEvidence{Role: RoleWorkingDirectory, Path: "/srv/lego", Safe: true},
		Configuration:       PathEvidence{Role: RoleConfiguration, Path: "/srv/lego/.lego.yml", Safe: true},
		Storage:             PathEvidence{Role: RoleStorage, Path: "/srv/lego/.lego", Safe: true},
		Adoptable:           true,
		ObservedAt:          time.Now(),
	}
	first := ReviewFingerprint(review)
	review.ObservedAt = review.ObservedAt.Add(time.Hour)
	if second := ReviewFingerprint(review); second != first {
		t.Fatalf("observation time changed fingerprint: %s != %s", second, first)
	}
	review.Storage.Inode++
	if second := ReviewFingerprint(review); second == first {
		t.Fatal("storage evidence did not change fingerprint")
	}
}

func TestVerifyIgnoresVolatileAncestorDirectoryLinkCount(t *testing.T) {
	t.Parallel()

	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "working"), 0o700)
	mkdir(t, filepath.Join(working, ".lego"), 0o700)
	writeFile(t, filepath.Join(working, ".lego.yml"), []byte("{}\n"), 0o600)
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
	if err != nil || !review.Adoptable {
		t.Fatalf("Inspect() review = %#v, error = %v", review, err)
	}

	// t.TempDir is below /tmp. Creating another /tmp directory changes /tmp's
	// directory link count without changing any selected workspace object.
	volatileAncestor := filepath.Dir(filepath.Dir(root))
	sibling, err := os.MkdirTemp(volatileAncestor, "acmemux-nlink-sibling-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(sibling) })
	if _, err := inspector.Verify(context.Background(), review); err != nil {
		t.Fatalf("Verify() rejected unrelated ancestor nlink churn: %v", err)
	}

	mutated := review
	mutated.WorkingDirectory = clonePathEvidence(mutated.WorkingDirectory)
	mutated.WorkingDirectory.Components[0].NLink++
	if ReviewFingerprint(mutated) != review.ReviewedEvidenceSHA256 {
		t.Fatal("volatile ancestor component link count changed the fingerprint")
	}
	mutated = review
	mutated.WorkingDirectory.NLink++
	if ReviewFingerprint(mutated) == review.ReviewedEvidenceSHA256 {
		t.Fatal("selected working-directory link count was not fingerprinted")
	}
	if ExecutionReviewFingerprint(mutated) != ExecutionReviewFingerprint(review) {
		t.Fatal("native directory child churn changed execution evidence")
	}
	mutated.WorkingDirectory.Inode++
	if ExecutionReviewFingerprint(mutated) == ExecutionReviewFingerprint(review) {
		t.Fatal("selected directory replacement did not change execution evidence")
	}
}

func TestInspectorRejectsInvalidPolicyAndRequest(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy()
	policy.EffectiveUID = 0
	if _, err := NewInspector(policy); CodeOf(err) != CodeInvalidPolicy {
		t.Fatalf("NewInspector() error = %v", err)
	}
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		request Request
		code    ErrorCode
	}{
		{request: Request{}, code: CodePathRequired},
		{request: Request{WorkingDirectory: "relative"}, code: CodePathNotAbsolute},
		{request: Request{WorkingDirectory: "/tmp/../tmp"}, code: CodePathNotCanonical},
		{request: Request{WorkingDirectory: "/tmp\n"}, code: CodePathNotCanonical},
		{request: Request{WorkingDirectory: "/tmp", ConfigurationPath: "relative"}, code: CodePathNotAbsolute},
	} {
		if _, err := inspector.Inspect(context.Background(), test.request); CodeOf(err) != test.code {
			t.Fatalf("Inspect(%#v) error = %v, want %s", test.request, err, test.code)
		}
	}
	var missingContext context.Context
	if _, err := inspector.Inspect(missingContext, Request{WorkingDirectory: "/tmp"}); CodeOf(err) != CodeContextRequired {
		t.Fatalf("nil-context error = %v", err)
	}
}

func TestInspectBoundsDeepComponentEvidenceBeforeTraversal(t *testing.T) {
	t.Parallel()
	allowed := "/" + strings.Repeat("a/", maximumRecordedPathComponents-2) + "a"
	if !boundedComponentEvidence(allowed) {
		t.Fatal("maximum allowed component count was rejected")
	}
	tooDeep := "/" + strings.Repeat("a/", maximumRecordedPathComponents-1) + "a"
	if boundedComponentEvidence(tooDeep) {
		t.Fatal("over-deep component path was accepted")
	}
	review := inspect(t, Request{WorkingDirectory: tooDeep})
	if review.Adoptable || !hasDiagnostic(review, CodePathTooDeep, SeverityBlocking) || len(review.WorkingDirectory.Components) != 0 {
		t.Fatalf("deep-path review = %#v", review)
	}
}

func TestReviewDiagnosticsAreBoundedWithExplicitBlockingMarker(t *testing.T) {
	t.Parallel()
	values := make([]Diagnostic, maximumReviewDiagnostics+20)
	for index := range values {
		values[index] = diagnostic(CodePathPermissionsUnsafe, RoleStorage, "/storage", fmt.Sprintf("/component/%d", index), "bounded detail")
	}
	var diagnostics []Diagnostic
	appendReviewDiagnostics(&diagnostics, values...)
	if len(diagnostics) != maximumReviewDiagnostics {
		t.Fatalf("diagnostic count = %d", len(diagnostics))
	}
	last := diagnostics[len(diagnostics)-1]
	if last.Code != CodeReviewEvidenceLimit || last.Severity != SeverityBlocking || last.Role != RoleWorkspace {
		t.Fatalf("limit diagnostic = %#v", last)
	}
	appendReviewDiagnostics(&diagnostics, diagnostic(CodePathMissing, RoleStorage, "/later", "/later", "later"))
	if len(diagnostics) != maximumReviewDiagnostics || diagnostics[len(diagnostics)-1] != last {
		t.Fatal("diagnostics changed after the bounded marker")
	}
}

func inspect(t *testing.T, request Request) Review {
	t.Helper()
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	review, err := inspector.Inspect(context.Background(), request)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	return review
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func mkdir(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path string, contents []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func hasDiagnostic(review Review, code ErrorCode, severity DiagnosticSeverity) bool {
	return slicesContainsFunc(review.Diagnostics, func(diagnostic Diagnostic) bool {
		return diagnostic.Code == code && diagnostic.Severity == severity
	})
}

func slicesContainsFunc[T any](values []T, predicate func(T) bool) bool {
	for _, value := range values {
		if predicate(value) {
			return true
		}
	}
	return false
}
