package httpapi

import (
	"context"
	"errors"
	"strings"

	"github.com/acmemux/AcmeMux/internal/compatibility"
	"github.com/acmemux/AcmeMux/internal/configuration"
	"github.com/acmemux/AcmeMux/internal/inventory"
	"github.com/acmemux/AcmeMux/internal/jobs"
	"github.com/acmemux/AcmeMux/internal/nativeconfig"
	"github.com/acmemux/AcmeMux/internal/operation"
	acmeruntime "github.com/acmemux/AcmeMux/internal/runtime"
	"github.com/acmemux/AcmeMux/internal/scheduler"
	"github.com/acmemux/AcmeMux/internal/workspace"
)

type inertRuntimeInspector struct{}

func (inertRuntimeInspector) Inspect(context.Context, string) (acmeruntime.Observation, error) {
	return acmeruntime.Observation{}, errors.New("unexpected runtime inspection")
}

func (inertRuntimeInspector) Verify(context.Context, acmeruntime.Observation) (acmeruntime.Observation, error) {
	return acmeruntime.Observation{}, errors.New("unexpected runtime verification")
}

type inertRuntimeSelections struct{}

func (inertRuntimeSelections) Load(context.Context) (acmeruntime.Selection, error) {
	return acmeruntime.Selection{}, acmeruntime.ErrNoSelection
}

func (inertRuntimeSelections) Save(context.Context, acmeruntime.Selection) error {
	return errors.New("unexpected runtime selection save")
}

type nativeEditJournalStub struct {
	pending bool
	err     error
	loads   int
}

func (stub *nativeEditJournalStub) Load(context.Context) (workspace.Journal, error) {
	stub.loads++
	if stub.err != nil {
		return workspace.Journal{}, stub.err
	}
	if stub.pending {
		return workspace.Journal{TransactionID: strings.Repeat("a", 32)}, nil
	}
	return workspace.Journal{}, workspace.ErrNoEditJournal
}

func clearNativeEditJournal() NativeEditJournal {
	return &nativeEditJournalStub{}
}

func testRuntimeDependencies() RuntimeDependencies {
	return RuntimeDependencies{
		Inspector:        inertRuntimeInspector{},
		Selections:       inertRuntimeSelections{},
		AcquireWorkspace: testWorkspaceLease,
		EditJournal:      clearNativeEditJournal(),
		Classify: func(acmeruntime.Observation) compatibility.Result {
			return compatibility.Result{Code: compatibility.CodeUnknownIdentity}
		},
	}
}

type inertWorkspaceInspector struct{}

func (inertWorkspaceInspector) Inspect(context.Context, workspace.Request) (workspace.Review, error) {
	return workspace.Review{}, errors.New("unexpected workspace inspection")
}

func (inertWorkspaceInspector) Verify(context.Context, workspace.Review) (workspace.Review, error) {
	return workspace.Review{}, errors.New("unexpected workspace verification")
}

type inertWorkspaceSelections struct{}

func (inertWorkspaceSelections) Load(context.Context) (workspace.Selection, error) {
	return workspace.Selection{}, workspace.ErrNoSelection
}

func (inertWorkspaceSelections) Save(context.Context, workspace.Selection) error {
	return errors.New("unexpected workspace selection save")
}

type inertWorkspaceInventory struct{}

func (inertWorkspaceInventory) Read(context.Context, inventory.PreparedExecutable, string) ([]inventory.Certificate, error) {
	return nil, errors.New("unexpected workspace inventory")
}

func testWorkspaceDependencies() WorkspaceDependencies {
	return WorkspaceDependencies{
		Inspector:        inertWorkspaceInspector{},
		Selections:       inertWorkspaceSelections{},
		Inventory:        inertWorkspaceInventory{},
		AcquireWorkspace: testWorkspaceLease,
		EditJournal:      clearNativeEditJournal(),
		PrepareRuntime: func(context.Context) (inventory.PreparedExecutable, error) {
			return nil, errors.New("unexpected runtime preparation")
		},
	}
}

func testWorkspaceLease(context.Context, workspace.Purpose) (func() error, error) {
	return func() error { return nil }, nil
}

type inertConfigurationService struct{}

func (inertConfigurationService) Snapshot(context.Context) (configuration.View, error) {
	return configuration.View{}, errors.New("unexpected configuration snapshot")
}

func (inertConfigurationService) Preview(context.Context, string, []nativeconfig.Change) (configuration.Preview, error) {
	return configuration.Preview{}, errors.New("unexpected configuration preview")
}

func (inertConfigurationService) Save(context.Context, string, []nativeconfig.Change, string, workspace.CommitGuard) (configuration.View, error) {
	return configuration.View{}, errors.New("unexpected configuration save")
}

func (inertConfigurationService) PreviewCreation(context.Context, string, configuration.CreationRequest) (configuration.Preview, error) {
	return configuration.Preview{}, errors.New("unexpected configuration creation preview")
}

func (inertConfigurationService) Create(context.Context, string, configuration.CreationRequest, string, workspace.CommitGuard) (configuration.View, error) {
	return configuration.View{}, errors.New("unexpected configuration creation")
}

func (inertConfigurationService) ResolveRecovery(context.Context, string, workspace.RecoveryResolution, workspace.CommitGuard) (configuration.View, error) {
	return configuration.View{}, errors.New("unexpected configuration recovery")
}

func testConfigurationDependencies() ConfigurationDependencies {
	return ConfigurationDependencies{Service: inertConfigurationService{}}
}

type inertOperationService struct{}

func (inertOperationService) Preview(context.Context) (operation.Preview, error) {
	return operation.Preview{}, errors.New("unexpected operation preview")
}

func (inertOperationService) Enqueue(context.Context, string, workspace.CommitGuard) (jobs.Operation, error) {
	return jobs.Operation{}, errors.New("unexpected operation enqueue")
}

func (inertOperationService) Status(context.Context) (jobs.Operation, error) {
	return jobs.Operation{}, jobs.ErrNotFound
}

func (inertOperationService) Latest(context.Context) (jobs.Operation, error) {
	return jobs.Operation{}, jobs.ErrNotFound
}

func (inertOperationService) Policy() operation.Policy { return operation.DefaultPolicy() }

type inertScheduleService struct{}

func (inertScheduleService) Get(context.Context) (scheduler.Schedule, error) {
	return scheduler.Schedule{State: scheduler.StateDisabled, ReasonCode: "not_configured"}, nil
}

func (inertScheduleService) Update(context.Context, scheduler.Update) (scheduler.Schedule, error) {
	return scheduler.Schedule{}, errors.New("unexpected automatic schedule update")
}

func testOperationDependencies() OperationDependencies {
	return OperationDependencies{Service: inertOperationService{}, Scheduler: inertScheduleService{}}
}
