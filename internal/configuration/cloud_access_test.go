package configuration

import (
	"context"
	"errors"
	"testing"

	"github.com/acmemux/AcmeMux/internal/integrations"
	"github.com/acmemux/AcmeMux/internal/workspace"
)

type fakeCloudAccessInspector struct {
	files map[string][]byte
	fail  bool
}

func (fake fakeCloudAccessInspector) ReadExternalCredential(_ context.Context, path string, _ int64) (workspace.ExternalFile, error) {
	if fake.fail {
		return workspace.ExternalFile{}, errors.New("denied")
	}
	content, ok := fake.files[path]
	if !ok {
		return workspace.ExternalFile{}, errors.New("missing")
	}
	return workspace.ExternalFile{Evidence: workspace.PathEvidence{Role: workspace.RoleCloudCredential, Path: path, Exists: true, Safe: true}, Content: append([]byte(nil), content...)}, nil
}
func (fake fakeCloudAccessInspector) AuditExternalDirectory(_ context.Context, path string) (workspace.PathEvidence, error) {
	if fake.fail {
		return workspace.PathEvidence{}, errors.New("denied")
	}
	return workspace.PathEvidence{Role: workspace.RoleCloudDirectory, Path: path, Exists: true, Safe: true}, nil
}
func (fake fakeCloudAccessInspector) AuditExternalExecutable(_ context.Context, path string) (workspace.PathEvidence, error) {
	if fake.fail {
		return workspace.PathEvidence{}, errors.New("denied")
	}
	return workspace.PathEvidence{Role: workspace.RoleCloudHelper, Path: path, Exists: true, Safe: true}, nil
}

func TestRoute53SharedProfileIsParsedAndMaterializedWithoutHOME(t *testing.T) {
	service := &Service{cloudAccess: fakeCloudAccessInspector{files: map[string][]byte{
		"/etc/acmemux/aws": []byte("[other]\naws_access_key_id = ignore\naws_secret_access_key = ignore\n[acmemux]\naws_access_key_id = ACCESS\naws_secret_access_key = SECRET\naws_session_token = SESSION\n"),
	}}}
	projection := cloudProjection{present: map[integrations.FieldID]bool{integrations.FieldAWSProfile: true}, values: map[integrations.FieldID]string{
		integrations.FieldAWSProfile: "acmemux", integrations.FieldAWSSharedCredentialsFile: "/etc/acmemux/aws",
	}}
	access, environment, secrets, evidence, err := service.prepareRoute53Access(t.Context(), "dns", projection)
	if err != nil {
		t.Fatal(err)
	}
	if access.AuthMode != "shared_profile" || len(access.Files) != 1 || len(evidence) != 1 {
		t.Fatalf("access = %#v", access)
	}
	if len(environment) != 3 || environment[0].Name != "AWS_ACCESS_KEY_ID" || environment[1].Name != "AWS_SECRET_ACCESS_KEY" || environment[2].Name != "AWS_SESSION_TOKEN" {
		t.Fatalf("environment = %#v", environment)
	}
	if len(secrets) != 3 {
		t.Fatalf("secrets = %d", len(secrets))
	}
	for _, variable := range environment {
		if variable.Name == "HOME" || variable.Name == "AWS_PROFILE" {
			t.Fatal("ambient profile environment escaped")
		}
	}
}

func TestAWSSharedProfileRejectsHelpersAndRecursiveConfiguration(t *testing.T) {
	invalid := [][]byte{
		[]byte("[acmemux]\ncredential_process = /bin/false\naws_access_key_id = A\naws_secret_access_key = S\n"),
		[]byte("[acmemux]\nrole_arn = arn:aws:iam::1:role/recursive\nsource_profile = other\n"),
		[]byte("[acmemux]\naws_access_key_id = A\n"),
	}
	for _, content := range invalid {
		if _, err := parseAWSSharedProfile(content, "acmemux"); err == nil {
			t.Fatal("unsafe shared profile was accepted")
		}
	}
}

func TestAzureOIDCFileIsAuditedAndInjectedAsSensitiveAssertion(t *testing.T) {
	service := &Service{cloudAccess: fakeCloudAccessInspector{files: map[string][]byte{"/run/oidc": []byte("  assertion-value\n")}}}
	projection := cloudProjection{present: map[integrations.FieldID]bool{integrations.FieldAzureOIDCTokenFile: true}, values: map[integrations.FieldID]string{
		integrations.FieldAzureAuthMethod: "oidc", integrations.FieldAzureOIDCTokenFile: "/run/oidc",
	}}
	access, environment, secrets, evidence, err := service.prepareAzureAccess(t.Context(), "dns", projection)
	if err != nil {
		t.Fatal(err)
	}
	if access.AuthMode != "oidc" || len(environment) != 1 || environment[0].Name != "AZURE_OIDC_TOKEN" || !environment[0].Sensitive || string(environment[0].Value) != "assertion-value" || len(secrets) != 1 || len(evidence) != 1 {
		t.Fatalf("OIDC access = %#v %#v", access, environment)
	}
}

func TestCloudHelperAndCredentialAuditFailureBlocksPreparation(t *testing.T) {
	service := &Service{cloudAccess: fakeCloudAccessInspector{fail: true}}
	projection := cloudProjection{present: map[integrations.FieldID]bool{}, values: map[integrations.FieldID]string{
		integrations.FieldAzureAuthMethod: "cli", integrations.FieldAzureCLIPath: "/trusted/bin", integrations.FieldAzureCLIConfigDirectory: "/trusted/cache",
	}}
	if _, _, _, _, err := service.prepareAzureAccess(t.Context(), "dns", projection); !errors.Is(err, ErrChanged) {
		t.Fatalf("helper audit error = %v", err)
	}
}
