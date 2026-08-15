package httpapi

import (
	"context"
	"errors"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/inventory"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
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

func testRuntimeDependencies() RuntimeDependencies {
	return RuntimeDependencies{
		Inspector:  inertRuntimeInspector{},
		Selections: inertRuntimeSelections{},
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
		Inspector:  inertWorkspaceInspector{},
		Selections: inertWorkspaceSelections{},
		Inventory:  inertWorkspaceInventory{},
		PrepareRuntime: func(context.Context) (inventory.PreparedExecutable, error) {
			return nil, errors.New("unexpected runtime preparation")
		},
	}
}
