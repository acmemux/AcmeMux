package configuration

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

func executionTestTransactions(t *testing.T) *fakeTransactions {
	t.Helper()
	directory := t.TempDir()
	return &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, ".lego.yml"),
		configuration: []byte(serviceTestConfiguration), generation: 1,
	}
}

func TestPrepareExecutionBuildsSafeWholeWorkspaceIntentAndOwnsSecrets(t *testing.T) {
	configuration := strings.Replace(serviceTestConfiguration,
		"    acceptsTermsOfService: true",
		"    acceptsTermsOfService: true\n    eab:\n      kid: public-kid\n      hmacKey: "+task07EABCanary,
		1,
	)
	configuration = strings.Replace(configuration, "networkStack: ipv4only\n", "", 1)
	configuration = strings.Replace(configuration, "server: letsencrypt", "server: googletrust", 1)
	transactions := executionTestTransactions(t)
	transactions.configuration = []byte(configuration)
	service := newTestService(t, transactions, nil, 0x7c)
	view, viewErr := service.Snapshot(context.Background())
	if viewErr != nil {
		t.Fatal(viewErr)
	}
	if view.State != StateReady || !view.Execution {
		t.Fatalf("snapshot state = %s execution=%v diagnostics=%#v projection=%#v", view.State, view.Execution, view.Diagnostics, view.Inspection.Projection)
	}
	lease, err := service.coordinator.TryAcquire(context.Background(), workspace.PurposeManualRun)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.PrepareExecution(context.Background(), lease)
	if releaseErr := lease.Release(); releaseErr != nil {
		t.Fatal(releaseErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if plan.Revision == "" || len(plan.ReviewedEvidenceSHA256) != 64 || plan.Intent.RuntimeIdentity != "v5.3.1" ||
		plan.Intent.ConfigurationPath != transactions.configurationPath ||
		plan.Intent.StoragePath != transactions.workingDirectory+"/.lego" {
		t.Fatalf("execution plan = %#v", plan)
	}
	if len(plan.Intent.Certificates) != 1 {
		t.Fatalf("certificates = %#v", plan.Intent.Certificates)
	}
	certificate := plan.Intent.Certificates[0]
	if certificate.Name != "gateway" || certificate.Account != "home" ||
		certificate.CA != "googletrust" || certificate.ChallengeName != "web" ||
		certificate.ChallengeMode != "listener" || len(certificate.Domains) != 1 ||
		certificate.Domains[0] != "gateway.home.example" {
		t.Fatalf("certificate intent = %#v", certificate)
	}
	if len(plan.ObservedSecrets) != 1 || string(plan.ObservedSecrets[0]) != task07EABCanary {
		t.Fatalf("observed secrets = %#v", plan.ObservedSecrets)
	}
	retained := plan.ObservedSecrets[0]
	plan.Close()
	for _, value := range retained {
		if value != 0 {
			t.Fatal("ExecutionPlan.Close did not clear a secret buffer")
		}
	}
}

func TestExecutionEvidenceIsStableAcrossServicesAndChangesWithSourceIdentity(t *testing.T) {
	transactions := executionTestTransactions(t)
	transactions.configuration = []byte(strings.Replace(serviceTestConfiguration, "networkStack: ipv4only\n", "", 1))
	first := newTestService(t, transactions, nil, 0x31)
	second := newTestService(t, transactions, nil, 0x32)
	prepare := func(service *Service) *ExecutionPlan {
		lease, err := service.coordinator.TryAcquire(context.Background(), workspace.PurposeManualRun)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := service.PrepareExecution(context.Background(), lease)
		_ = lease.Release()
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	left, right := prepare(first), prepare(second)
	if left.Revision == right.Revision {
		t.Fatal("independent browser review keys produced the same revision token")
	}
	if left.ReviewedEvidenceSHA256 != right.ReviewedEvidenceSHA256 {
		t.Fatalf("durable evidence differs across services: %q != %q", left.ReviewedEvidenceSHA256, right.ReviewedEvidenceSHA256)
	}
	stable := left.ReviewedEvidenceSHA256
	left.Close()
	right.Close()
	transactions.mu.Lock()
	transactions.generation++
	transactions.mu.Unlock()
	changed := prepare(first)
	defer changed.Close()
	if changed.ReviewedEvidenceSHA256 == stable {
		t.Fatal("source identity change did not change durable execution evidence")
	}
}

func TestPrepareExecutionRejectsConfigurationThatCannotExecute(t *testing.T) {
	transactions := executionTestTransactions(t)
	transactions.configuration = append(transactions.configuration, []byte("hooks:\n  pre:\n    command: echo unsafe\n")...)
	service := newTestService(t, transactions, nil, 0x7d)
	lease, err := service.coordinator.TryAcquire(context.Background(), workspace.PurposeManualRun)
	if err != nil {
		t.Fatal(err)
	}
	_, operationErr := service.PrepareExecution(context.Background(), lease)
	_ = lease.Release()
	if operationErr != ErrInvalid {
		t.Fatalf("PrepareExecution() error = %v, want ErrInvalid", operationErr)
	}
}
